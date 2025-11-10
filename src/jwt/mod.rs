/* Copyright 2024 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use std::{fmt::Debug, marker::PhantomData, str::FromStr, time::SystemTime};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use josekit::{
    JoseHeader,
    jwk::Jwk,
    jws::{JwsHeader, JwsSigner, JwsVerifier},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use tracing::instrument;
use x509_cert::der::{Decode, Encode};

use crate::models::{
    JwkSet,
    errors::{JwsError, JwtError, PayloadError, X509Error},
    transformer::Transformer,
};

pub mod creator;
pub mod verifier;

pub mod jwt_rfc7519 {
    use crate::models;
    models!(
        #[derive(Default, Debug)]
        pub struct TimeValidity {
            not_before ("nbf"): Option<i64>,
            expires_at ("exp"): Option<i64>,
            issued_at ("iat"): Option<i64>,
        }
    );
    models!(
        #[derive(Default, Debug)]
        pub struct Header {
            kid: String,
            typ: String,
        }
    );
}

pub trait JwtVerifier<T: Serialize + DeserializeOwned> {
    fn jws_header(&self, jwt: &Jwt<T>) -> Result<JwsHeader, JwtError> {
        let header = jwt.header()?;
        let Some(jws_header) = header.as_any().downcast_ref::<JwsHeader>() else {
            return Err(JwtError::Jws(JwsError::TypeError(
                "Invalid header type".to_string(),
            )));
        };
        Ok(jws_header.clone())
    }
    fn typ(&self, jwt: &Jwt<T>) -> Option<String> {
        let jws_header = self.jws_header(jwt).ok()?;
        jws_header.token_type().map(|s| s.to_string())
    }
    fn assert_type(&self, jwt: &Jwt<T>, expected_type: &str) -> Result<(), JwtError> {
        let ty = self.typ(jwt).ok_or(JwtError::Jws(JwsError::TypeError(
            "Invalid header type".to_string(),
        )))?;
        if ty != expected_type {
            Err(JwtError::Jws(JwsError::TypeError(format!(
                "Expected type {}, got {}",
                expected_type, ty
            ))))
        } else {
            Ok(())
        }
    }
    fn verify_header(&self, jwt: &Jwt<T>) -> Result<(), JwtError>;
    fn verify_time(&self, jwt: &Jwt<T>) -> Result<(), JwtError> {
        self.verify_time_at(jwt, Utc::now())
    }
    #[instrument(skip(self, jwt), fields(time_parts))]
    fn verify_time_at(&self, jwt: &Jwt<T>, time: chrono::DateTime<Utc>) -> Result<(), JwtError> {
        let time = time.timestamp();
        let mut time_parts = jwt_rfc7519::TimeValidity::default();
        jwt.generalized_payload_unverified()
            .insecure()
            .write_to_transformer(&mut time_parts);

        if let Some(nbf) = time_parts.not_before {
            if nbf > time {
                return Err(JwtError::Jws(JwsError::NotYetValid(
                    "JWT not yet valid".to_string(),
                )));
            }
        }
        if let Some(exp) = time_parts.expires_at {
            if exp < time {
                return Err(JwtError::Jws(JwsError::Expired("JWT expired".to_string())));
            }
        }
        Ok(())
    }
    fn verify_body(&self, jwt: &Jwt<T>) -> Result<(), JwtError>;
}

pub trait Jwtable: Serialize + DeserializeOwned + Debug {}

#[derive(Clone)]
pub struct Jwt<T: Serialize + DeserializeOwned> {
    payload: T,
    generalized_payload: serde_json::Value,
    pub original_payload: String,
    pub signatures: Vec<Signature>,
}
impl<T: Serialize + DeserializeOwned> Debug for Jwt<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Jwt")
            .field("payload", &serde_json::to_string(&self.payload))
            .field("original_payload", &self.original_payload)
            .field("signatures", &self.signatures)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub signature: String,
    pub protected: String,
    pub header: Option<String>,
}

impl<T: Serialize + DeserializeOwned> Jwt<T> {
    pub fn header(&self) -> Result<JwsHeader, JwtError> {
        josekit::jwt::decode_header(self.jwt_at(0))
            .map(|h| {
                h.as_any()
                    .downcast_ref::<JwsHeader>()
                    .cloned()
                    .ok_or_else(|| {
                        JwtError::Jws(JwsError::InvalidHeader("Invalid header type".to_string()))
                    })
            })
            .map_err(|e| JwtError::Jws(JwsError::InvalidHeader(format!("{e}"))))?
    }

    pub fn verifier_from_embedded_jwk(
        &self,
    ) -> Result<Vec<(String, Box<dyn JwsVerifier>)>, JwtError> {
        let Some(jwks) = self
            .generalized_payload
            .get("jwks")
            .and_then(|a| a.get("keys"))
            .and_then(|a| a.as_array())
        else {
            return Err(JwtError::Payload(PayloadError::MissingRequiredProperty(
                "jwks".to_string(),
            )));
        };
        let mut verifiers = vec![];
        for key in jwks {
            let Ok(jwk) = serde_json::from_value::<Jwk>(key.clone()) else {
                continue;
            };
            let key_id = jwk.key_id().unwrap_or_default().to_string();
            let Some(verifier) = verifier_for_jwk(jwk) else {
                continue;
            };
            verifiers.push((key_id, verifier));
        }
        Ok(verifiers)
    }

    pub fn payload(
        &self,
        jwk_set: &JwkSet,
        jwt_verifier: &dyn JwtVerifier<T>,
    ) -> Result<&T, JwtError> {
        self.verify_signature(jwk_set)?;
        self.verify(jwt_verifier)?;
        Ok(&self.payload)
    }
    pub fn payload_with_verifier_from_header(
        &self,
        jwt_verifier: &dyn JwtVerifier<T>,
    ) -> Result<&T, JwtError> {
        let signature_verifier = verifier_for_header(
            self.header()?
                .as_any()
                .downcast_ref::<JwsHeader>()
                .ok_or_else(|| JwtError::Jws(JwsError::InvalidHeader(format!("invalid header"))))?,
        )
        .ok_or_else(|| {
            JwtError::Jws(JwsError::InvalidHeader(format!(
                "cannot extract signature verifier"
            )))
        })?;
        self.verify_signature_with_verifier(signature_verifier.as_ref())?;
        self.verify(jwt_verifier)?;
        Ok(&self.payload)
    }
    pub fn payload_with_verifier(
        &self,
        signature_verifier: &dyn JwsVerifier,
        jwt_verifier: &dyn JwtVerifier<T>,
    ) -> Result<&T, JwtError> {
        self.verify_signature_with_verifier(signature_verifier)?;
        self.verify(jwt_verifier)?;
        Ok(&self.payload)
    }
    pub fn payload_with_verifier_from_keyset(
        &self,
        key_set: &JwkSet,
        jwt_verifier: &dyn JwtVerifier<T>,
    ) -> Result<&T, JwtError> {
        self.verify_signature(key_set)?;
        self.verify(jwt_verifier)?;
        Ok(&self.payload)
    }
    #[instrument(skip(self, jwk_set), err)]
    pub fn verify_signature(&self, jwk_set: &JwkSet) -> Result<(), JwtError> {
        let header = josekit::jwt::decode_header(self.jwt_at(0))
            .map_err(|e| JwtError::Jws(JwsError::InvalidHeader(format!("{e}"))))?;
        let Some(verifier) = jwk_set.verifier_for(header.claim("kid").unwrap().as_str().unwrap())
        else {
            return Err(JwtError::Jws(JwsError::KeyNotFound(
                "No matching key found".to_string(),
            )));
        };
        for s in &self.signatures {
            let sig_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&s.signature)
                .map_err(|e| JwsError::EncodingError(format!("{e}")))?;
            println!("alg: {}", verifier.algorithm().name());

            verifier
                .verify(
                    format!("{}.{}", s.protected, self.original_payload).as_bytes(),
                    sig_bytes.as_slice(),
                )
                .map_err(|e| JwsError::InvalidSignature(format!("{e}")))?;
        }
        Ok(())
    }
    #[instrument(skip(self, verifier), err)]
    pub fn verify_signature_with_verifier(
        &self,
        verifier: &dyn JwsVerifier,
    ) -> Result<(), JwtError> {
        let header = josekit::jwt::decode_header(self.jwt_at(0))
            .map_err(|e| JwtError::Jws(JwsError::InvalidHeader(format!("{e}"))))?;
        if verifier.algorithm().name()
            != header
                .as_any()
                .downcast_ref::<JwsHeader>()
                .unwrap()
                .algorithm()
                .unwrap()
        {
            return Err(JwsError::InvalidHeader("algorithm not matching".to_string()).into());
        }
        for s in &self.signatures {
            let sig_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&s.signature)
                .map_err(|e| JwsError::EncodingError(format!("{e}")))?;
            println!("alg: {}", verifier.algorithm().name());

            verifier
                .verify(
                    format!("{}.{}", s.protected, self.original_payload).as_bytes(),
                    sig_bytes.as_slice(),
                )
                .map_err(|e| JwsError::InvalidSignature(format!("{e}")))?;
        }
        Ok(())
    }
    pub fn verify(&self, verifier: &dyn JwtVerifier<T>) -> Result<(), JwtError> {
        verifier.verify_header(self)?;
        verifier.verify_time(self)?;
        verifier.verify_body(self)?;
        Ok(())
    }

    pub fn generalized_payload_unverified(&self) -> Unverified<&serde_json::Value> {
        Unverified::new(&self.generalized_payload)
    }
    pub fn payload_unverified(&self) -> Unverified<&T> {
        let p = &self.payload;
        Unverified::new(p)
    }
    pub fn jwt_at(&self, index: usize) -> String {
        let sig = self.signatures.get(index).unwrap();
        format!(
            "{}.{}.{}",
            sig.protected, self.original_payload, sig.signature
        )
    }
}
pub struct Unverified<'a, T> {
    payload: T,
    _data: PhantomData<&'a T>,
}
impl<'a, T> Unverified<'a, &'a T> {
    pub fn new(payload: &'a T) -> Self {
        Self {
            payload,
            _data: PhantomData,
        }
    }
    pub fn insecure(&self) -> &T {
        self.payload
    }
}

impl<T> FromStr for Jwt<T>
where
    T: Serialize + DeserializeOwned,
{
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let binding = s.split('.').collect::<Vec<_>>();
        let [header, payload, signature] = binding.as_slice() else {
            return Err(JwsError::InvalidFormat("Invalid JWT format".to_string()).into());
        };
        let original_payload = payload.to_string();

        let decoded_bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|e| {
                JwtError::Payload(PayloadError::InvalidPayload(format!(
                    "Base64 decode failed: {}",
                    e
                )))
            })?;

        let payload = std::str::from_utf8(&decoded_bytes).map_err(|e| {
            JwtError::Payload(PayloadError::InvalidPayload(format!(
                "UTF-8 decode failed: {}",
                e
            )))
        })?;

        Ok(Self {
            payload: serde_json::from_str(payload)
                .map_err(|e| JwsError::BodyParseError(format!("{e}")))?,
            generalized_payload: serde_json::from_str(payload)
                .map_err(|e| JwsError::BodyParseError(format!("{e}")))?,
            original_payload,
            signatures: vec![Signature {
                signature: signature.to_string(),
                protected: header.to_string(),
                header: None,
            }],
        })
    }
}

impl JwkSet {
    pub fn verifier_for(&self, key_id: &str) -> Option<Box<dyn JwsVerifier>> {
        let jwks = self.0.get(key_id);
        for jwk in jwks {
            for alg in [
                josekit::jws::ES256,
                josekit::jws::ES384,
                josekit::jws::ES512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [
                josekit::jws::RS256,
                josekit::jws::RS384,
                josekit::jws::RS512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [
                josekit::jws::PS256,
                josekit::jws::PS384,
                josekit::jws::PS512,
            ] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
            for alg in [josekit::jws::EdDSA] {
                if let Ok(verifier) = alg.verifier_from_jwk(jwk) {
                    return Some(Box::new(verifier));
                }
            }
        }
        None
    }
}

pub fn verifier_for_jwk(jwk: Jwk) -> Option<Box<dyn JwsVerifier>> {
    for alg in [
        josekit::jws::ES256,
        josekit::jws::ES384,
        josekit::jws::ES512,
    ] {
        if let Ok(verifier) = alg.verifier_from_jwk(&jwk) {
            return Some(Box::new(verifier));
        }
    }
    for alg in [
        josekit::jws::RS256,
        josekit::jws::RS384,
        josekit::jws::RS512,
    ] {
        if let Ok(verifier) = alg.verifier_from_jwk(&jwk) {
            return Some(Box::new(verifier));
        }
    }
    for alg in [
        josekit::jws::PS256,
        josekit::jws::PS384,
        josekit::jws::PS512,
    ] {
        if let Ok(verifier) = alg.verifier_from_jwk(&jwk) {
            return Some(Box::new(verifier));
        }
    }
    for alg in [josekit::jws::EdDSA] {
        if let Ok(verifier) = alg.verifier_from_jwk(&jwk) {
            return Some(Box::new(verifier));
        }
    }
    None
}
pub fn signer_for_jwk(jwk: Jwk) -> Option<Box<dyn JwsSigner>> {
    for alg in [
        josekit::jws::ES256,
        josekit::jws::ES384,
        josekit::jws::ES512,
    ] {
        if let Ok(signer) = alg.signer_from_jwk(&jwk) {
            return Some(Box::new(signer));
        }
    }
    for alg in [
        josekit::jws::RS256,
        josekit::jws::RS384,
        josekit::jws::RS512,
    ] {
        if let Ok(signer) = alg.signer_from_jwk(&jwk) {
            return Some(Box::new(signer));
        }
    }
    for alg in [
        josekit::jws::PS256,
        josekit::jws::PS384,
        josekit::jws::PS512,
    ] {
        if let Ok(signer) = alg.signer_from_jwk(&jwk) {
            return Some(Box::new(signer));
        }
    }
    for alg in [josekit::jws::EdDSA] {
        if let Ok(signer) = alg.signer_from_jwk(&jwk) {
            return Some(Box::new(signer));
        }
    }
    None
}

//TODO: we should check CRL extensions and such
pub fn check_x5c_chain(chain: &[Vec<u8>]) -> Result<(), JwtError> {
    if chain.is_empty() {
        return Err(X509Error::InvalidX5cChain("empty chain".to_string()).into());
    }
    let mut last_child: Option<x509_cert::Certificate> = None;
    for c in chain {
        let cert = x509_cert::Certificate::from_der(c)
            .map_err(|e| X509Error::ParseError(format!("{e}")))?;
        // check validity
        let validity = cert.tbs_certificate.validity;
        if validity.not_after.to_system_time() < SystemTime::now() {
            return Err(X509Error::ExpiredCertificate(format!(
                "certificate expired at {}",
                validity.not_after
            ))
            .into());
        }
        if validity.not_before.to_system_time() > SystemTime::now() {
            return Err(X509Error::ExpiredCertificate(format!(
                "certificate not yet valid {}",
                validity.not_after
            ))
            .into());
        }
        if let Some(last_child) = last_child {
            let verifier = verifier_for_x5c(&cert)?;
            let mut buf = vec![];
            last_child.tbs_certificate.encode_to_vec(&mut buf).unwrap();
            println!(
                "{:?}",
                verifier.verify(&buf, last_child.signature.raw_bytes())
            );
            if verifier
                .verify(&buf, last_child.signature.raw_bytes())
                .is_err()
            {
                return Err(JwsError::InvalidSignature(format!(
                    "certificate has invalid signature {}",
                    last_child.tbs_certificate.subject.to_string()
                ))
                .into());
            };
        }
        last_child = Some(cert);
    }
    Ok(())
}

pub fn verifier_for_x5c(x509: &x509_cert::Certificate) -> Result<Box<dyn JwsVerifier>, JwtError> {
    verifier_for_der(
        &x509
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|e| X509Error::ParseError(format!("{e}")))?,
    )
}
pub fn verifier_for_der(der: &[u8]) -> Result<Box<dyn JwsVerifier>, JwtError> {
    //TODO: we should check the algorithm identifier in the certificate
    for alg in [
        josekit::jws::ES256,
        josekit::jws::ES384,
        josekit::jws::ES512,
    ] {
        let Ok(verifier) = alg.verifier_from_der(der) else {
            continue;
        };
        return Ok(Box::new(verifier));
    }
    for alg in [
        josekit::jws::RS256,
        josekit::jws::RS384,
        josekit::jws::RS512,
    ] {
        let Ok(verifier) = alg.verifier_from_der(der) else {
            continue;
        };
        return Ok(Box::new(verifier));
    }
    for alg in [
        josekit::jws::PS256,
        josekit::jws::PS384,
        josekit::jws::PS512,
    ] {
        let Ok(verifier) = alg.verifier_from_der(der) else {
            continue;
        };
        return Ok(Box::new(verifier));
    }
    for alg in [josekit::jws::EdDSA] {
        let Ok(verifier) = alg.verifier_from_der(der) else {
            continue;
        };
        return Ok(Box::new(verifier));
    }
    Err(X509Error::InvalidAlgorithm(format!("Invalid Algorithm")).into())
}

#[tracing::instrument]
//TODO: verify the x509 certificate chain is valid
pub fn verifier_for_header(header: &JwsHeader) -> Option<Box<dyn JwsVerifier>> {
    let alg_name = header.algorithm().unwrap_or("ES256");
    if let Some(x5c) = header.x509_certificate_chain() {
        // Check if the x509 certificate chain is valid
        println!("-#> {:?}", check_x5c_chain(x5c.as_ref()));
        check_x5c_chain(x5c.as_ref()).ok()?;
    }
    for alg in [
        josekit::jws::ES256,
        josekit::jws::ES384,
        josekit::jws::ES512,
    ] {
        if alg.name() == alg_name {
            if let Some(x5c) = header.x509_certificate_chain() {
                let x509 = x509_cert::Certificate::from_der(&x5c.first()?).ok()?;
                let verifier = alg
                    .verifier_from_der(&x509.tbs_certificate.subject_public_key_info.to_der().ok()?)
                    .ok()?;
                return Some(Box::new(verifier));
            }
            if let Some(jwk) = header.jwk() {
                let verifier = alg.verifier_from_jwk(&jwk).ok()?;
                return Some(Box::new(verifier));
            }
        }
    }
    for alg in [
        josekit::jws::RS256,
        josekit::jws::RS384,
        josekit::jws::RS512,
    ] {
        if alg.name() == alg_name {
            if let Some(x5c) = header.x509_certificate_chain() {
                let x509 = x509_cert::Certificate::from_der(&x5c.first()?).ok()?;
                let verifier = alg
                    .verifier_from_der(&x509.tbs_certificate.subject_public_key_info.to_der().ok()?)
                    .ok()?;
                return Some(Box::new(verifier));
            }
        }
        if let Some(jwk) = header.jwk() {
            let verifier = alg.verifier_from_jwk(&jwk).ok()?;
            return Some(Box::new(verifier));
        }
    }
    for alg in [
        josekit::jws::PS256,
        josekit::jws::PS384,
        josekit::jws::PS512,
    ] {
        if alg.name() == alg_name {
            if let Some(x5c) = header.x509_certificate_chain() {
                let x509 = x509_cert::Certificate::from_der(&x5c.first()?).ok()?;
                let verifier = alg
                    .verifier_from_der(&x509.tbs_certificate.subject_public_key_info.to_der().ok()?)
                    .ok()?;
                return Some(Box::new(verifier));
            }
        }
        if let Some(jwk) = header.jwk() {
            let verifier = alg.verifier_from_jwk(&jwk).ok()?;
            return Some(Box::new(verifier));
        }
    }
    for alg in [josekit::jws::EdDSA] {
        if alg.name() == alg_name {
            if let Some(x5c) = header.x509_certificate_chain() {
                let x509 = x509_cert::Certificate::from_der(&x5c.first()?).ok()?;
                let verifier = alg
                    .verifier_from_der(&x509.tbs_certificate.subject_public_key_info.to_der().ok()?)
                    .ok()?;
                return Some(Box::new(verifier));
            }
        }
        if let Some(jwk) = header.jwk() {
            let verifier = alg.verifier_from_jwk(&jwk).ok()?;
            return Some(Box::new(verifier));
        }
    }
    None
}

/// Get a verifier from a SEC1 encoded EC key (no point compression!).
pub fn ec_verifier_from_sec1(sec1_bytes: &[u8], crv: &str) -> Option<Box<dyn JwsVerifier>> {
    if sec1_bytes.len() != 65 {
        return None;
    }
    let x = &sec1_bytes[1..33];
    let y = &sec1_bytes[33..65];
    let x = BASE64_URL_SAFE_NO_PAD.encode(x);
    let y = BASE64_URL_SAFE_NO_PAD.encode(y);
    let jwk = json!({
        "x" : x,
        "y" : y,
        "kty" : "EC",
        "crv" : crv,
        "use" : "sig"
    });
    let jwk: Jwk = serde_json::from_value(jwk).ok()?;
    return match crv {
        "P-256" => Some(Box::new(josekit::jws::ES256.verifier_from_jwk(&jwk).ok()?)),
        "P-384" => Some(Box::new(josekit::jws::ES384.verifier_from_jwk(&jwk).ok()?)),
        "P-521" => Some(Box::new(josekit::jws::ES512.verifier_from_jwk(&jwk).ok()?)),
        _ => None,
    };
}

/// Get a verifier from an encoded HMAC key.
pub fn hmac_verifier_from_bytes(bytes: &[u8], alg: &str) -> Option<Box<dyn JwsVerifier>> {
    return match alg {
        "HS256" => Some(Box::new(
            josekit::jws::HS256.verifier_from_bytes(&bytes).ok()?,
        )),
        "HS384" => Some(Box::new(
            josekit::jws::HS384.verifier_from_bytes(&bytes).ok()?,
        )),
        "HS512" => Some(Box::new(
            josekit::jws::HS512.verifier_from_bytes(&bytes).ok()?,
        )),
        _ => None,
    };
}

/// Get a verifier from an encoded RSA key.
pub fn rsa_verifier_from_der(der: &[u8], alg: &str) -> Option<Box<dyn JwsVerifier>> {
    match alg {
        "RS256" => Some(Box::new(josekit::jws::RS256.verifier_from_der(&der).ok()?)),
        "RS384" => Some(Box::new(josekit::jws::RS384.verifier_from_der(&der).ok()?)),
        "RS512" => Some(Box::new(josekit::jws::RS512.verifier_from_der(&der).ok()?)),
        "PS256" => Some(Box::new(josekit::jws::PS256.verifier_from_der(&der).ok()?)),
        "PS384" => Some(Box::new(josekit::jws::PS384.verifier_from_der(&der).ok()?)),
        "PS512" => Some(Box::new(josekit::jws::PS512.verifier_from_der(&der).ok()?)),
        _ => None,
    }
}

/// Get a verifier from an encoded EdDSA key.
pub fn eddsa_verifier_from_bytes(bytes: &[u8], crv: &str) -> Option<Box<dyn JwsVerifier>> {
    if bytes.len() != 32 {
        return None;
    }
    let x = BASE64_URL_SAFE_NO_PAD.encode(bytes);
    let jwk = json!({
        "x" : x,
        "kty" : "OKP",
        "crv" : crv,
        "use" : "sig"
    });
    let jwk: Jwk = serde_json::from_value(jwk).ok()?;
    return match crv {
        "Ed25519" | "Ed448" => Some(Box::new(josekit::jws::EdDSA.verifier_from_jwk(&jwk).ok()?)),
        _ => None,
    };
}
