use std::ops::Deref;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use josekit::{
    JoseHeader,
    jws::{JwsHeader, JwsSigner},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::models::errors::{JwsError, JwtError, PayloadError};

pub trait JwtCreator: Serialize + DeserializeOwned {
    type Header: JoseHeader;
    fn create_jwt(
        &self,
        header: &Self::Header,
        issuer: Option<&str>,
        lifetime: chrono::Duration,
        signer: &dyn Signer,
    ) -> Result<String, JwtError>;
}

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError>;
}

impl<T> Signer for Box<T>
where
    T: JwsSigner + ?Sized,
{
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError> {
        self.as_ref()
            .sign(data)
            .map_err(|e| JwtError::Jws(JwsError::InvalidSignature(format!("Signing-Error: {e}"))))
    }
}

impl<T> JwtCreator for T
where
    T: Serialize + DeserializeOwned,
{
    type Header = JwsHeader;

    fn create_jwt(
        &self,
        header: &Self::Header,
        issuer: Option<&str>,
        lifetime: chrono::Duration,
        signer: &dyn Signer,
    ) -> Result<String, JwtError> {
        let mut val = serde_json::to_value(self).map_err(|e| {
            JwtError::Payload(PayloadError::InvalidPayload(format!("Serde-Error: {e}")))
        })?;
        let now = Utc::now();
        if let Some(issuer) = issuer {
            val["iss"] = serde_json::Value::String(issuer.to_string());
        }
        if val["iat"].is_null() {
            val["iat"] = serde_json::Value::Number(now.timestamp().into());
        }
        // account for clock skew
        if val["nbf"].is_null() {
            val["nbf"] = serde_json::Value::Number((now - Duration::minutes(5)).timestamp().into());
        }
        if val["exp"].is_null() {
            val["exp"] = serde_json::Value::Number((now + lifetime).timestamp().into());
        }
        let payload = BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_string(&val).map_err(|e| {
            JwtError::Payload(PayloadError::InvalidPayload(format!("Serde-Error: {e}")))
        })?);
        let header = BASE64_URL_SAFE_NO_PAD.encode(header.to_string());
        let mut jwt = format!("{}.{}", header, payload);
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signer.sign(jwt.as_bytes())?);
        jwt.push_str(".");
        jwt.push_str(&signature);
        Ok(jwt)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        jwt::{
            Jwt,
            verifier::{ClaimValidator, DefaultVerifier},
        },
        models,
    };

    use super::*;
    use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm::Es256;
    use serde::Deserialize;

    #[test]
    fn test_create_jwt() {
        let mut header = JwsHeader::new();
        header.set_algorithm("ES256");
        header.set_token_type("example+jwt");
        let signer_key = Es256.generate_key_pair().unwrap();
        let signer = Es256
            .signer_from_der(signer_key.to_der_private_key())
            .unwrap();
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct TestStruct {
            id: String,
            name: String,
        }

        let jwt = TestStruct {
            id: "1".to_string(),
            name: "John".to_string(),
        }
        .create_jwt(
            &header,
            Some("test-issuer"),
            Duration::minutes(5),
            &Box::new(signer),
        )
        .unwrap();

        println!("{jwt}");
        let parsed_jwt = Jwt::<TestStruct>::from_str(&jwt).unwrap();
        let verifier = Es256
            .verifier_from_der(signer_key.to_der_public_key())
            .unwrap();
        let payload = parsed_jwt
            .payload_with_verifier(
                &verifier,
                &DefaultVerifier::new("example+jwt".to_string(), vec![]),
            )
            .unwrap();
        assert_eq!(
            payload,
            &TestStruct {
                id: "1".to_string(),
                name: "John".to_string(),
            }
        );

        assert!(
            parsed_jwt
                .payload_with_verifier(
                    &verifier,
                    &DefaultVerifier::new(
                        "example+jwt".to_string(),
                        vec![
                            ClaimValidator::Presence("id".to_string()),
                            ClaimValidator::Value(
                                "name".to_string(),
                                models::transformer::Value::String("John".to_string())
                            ),
                        ]
                    ),
                )
                .is_ok()
        );
        assert!(
            parsed_jwt
                .payload_with_verifier(
                    &verifier,
                    &DefaultVerifier::new(
                        "example+jwt".to_string(),
                        vec![
                            ClaimValidator::Presence("id".to_string()),
                            ClaimValidator::Value(
                                "name".to_string(),
                                models::transformer::Value::String("John2".to_string())
                            ),
                        ]
                    ),
                )
                .is_err()
        );

        assert!(
            parsed_jwt
                .payload_with_verifier(
                    &verifier,
                    &DefaultVerifier::new("example+jwt2".to_string(), vec![]),
                )
                .is_err()
        );
        let wrong_signing_key = Es256.generate_key_pair().unwrap();
        let wrong_verifier = Es256
            .verifier_from_der(wrong_signing_key.to_der_public_key())
            .unwrap();
        assert!(
            parsed_jwt
                .payload_with_verifier(
                    &wrong_verifier,
                    &DefaultVerifier::new("example+jwt".to_string(), vec![]),
                )
                .is_err()
        );
    }
}
