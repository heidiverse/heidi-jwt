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
pub mod jwt;
pub mod models;

pub use chrono;
pub use josekit::JoseError;
pub use josekit::jwe;
pub use josekit::jwk::{Jwk, JwkSet};
pub use josekit::jws::*;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use josekit::jws::{JwsHeader, alg::ecdsa::EcdsaJwsAlgorithm::Es256};
    use serde_json::json;

    use crate::jwt::{Jwt, creator::JwtCreator, verifier_for_header};

    #[test]
    fn test_float_or_int() {
        let t: serde_json::Value = json!({
            "iat": 1000.23,
            "exp": 42,
            "nbf": 1000.23,
            "test" : "hallo"
        });
        let jws_keypair = Es256.generate_key_pair().unwrap();
        let signer = Es256
            .signer_from_jwk(&jws_keypair.to_jwk_key_pair())
            .unwrap();
        let mut header = JwsHeader::new();
        header.set_algorithm(Es256.name());
        let jwt = t
            .create_jwt(
                &header,
                None,
                chrono::Duration::seconds(3600),
                &Box::new(signer),
            )
            .unwrap();
        let p = Jwt::<serde_json::Value>::from_str(&jwt).unwrap();
        let unverified = p.payload_unverified();

        assert_eq!(
            unverified.insecure().get("iat").unwrap().as_f64().unwrap(),
            1000.23
        );
        assert_eq!(
            unverified.insecure().get("exp").unwrap().as_i64().unwrap(),
            42
        );
    }
    #[test]
    fn test_payload_parse() {
        let jwt_str = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImlVbE96RF9HOV9tODkwNmpfMTk1WXIzSXBlNlhtWS1Ld2dicmhzTVI4M28iLCJ5IjoiYjU1TEQ5NFVhVVh3VUhxMGN1QnJyMERQRk5EZUFzRTQ5UzhEVjJlaVBibyJ9LCJ0eXAiOiJrYitqd3QifQ.eyJpYXQiOjE3NjkwNzg4NDQuMzA0MDY2LCJhdWQiOiJjaC5hZG1pbi5zd2l5dWNoZWNrIiwic2RfaGFzaCI6IkNGWF9paUxBNjM4TUlDUW9veXBOdVJFeHBEczJjTXVac2luOXFpbDhqSHcifQ.FYQzJ1vmFFNF9e3YoBSSh3lTxDY-7gBlZvbX8SHKmW6KB1LkoJtThIxALrdcwkvtZIzmQHnXK9Afv1hVsOZHEQ";
        let t = Jwt::<serde_json::Value>::from_str(jwt_str).unwrap();
        println!(
            "{}",
            t.payload_unverified()
                .insecure()
                .get("iat")
                .unwrap()
                .as_f64()
                .unwrap()
        );
    }
    #[test]
    fn test_parse_key() {
        let privatekey = r#"-----BEGIN EC PRIVATE KEY-----
        MGsCAQEEIJDTZuhqP1I1aXzhovYlJDNQu82654Ix4L5GnK8M+sJsoUQDQgAE8HCr
        Uv4fHF+Wbojb+sIjgujr7pPZNGP0EzduTBo1DpOu1hMZk7auKBnRSZFAiJD1sxqt
        1nD5vNU0ddhsMqLfzg==
        -----END EC PRIVATE KEY-----"#;
        let s = Es256.key_pair_from_pem(privatekey).unwrap();
        println!(
            "{}",
            s.to_jwk_private_key()
                .parameter("d")
                .unwrap()
                .as_str()
                .unwrap()
        );
        let signer = Es256.signer_from_pem(privatekey).unwrap();
        signer.sign(b"some test message").unwrap();
    }
    #[test]
    fn test_rsa_verification() {
        let jwt = r#"eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldTIiwia2lkIiA6ICJ6NGY1TXk4TEZuQ1FfMkhCTU9zR1V5QjE0WXI3cDJiMFhLbTd5QThYdndBIiwieDVjIiA6IFsiTUlJQ296Q0NBWXNDQmdHY1RZcDRIVEFOQmdrcWhraUc5dzBCQVFzRkFEQVZNUk13RVFZRFZRUUREQXB3YVdRdGFYTnpkV1Z5TUI0WERUSTJNREl4TVRFMk1qa3dObG9YRFRNMk1ESXhNVEUyTXpBME5sb3dGVEVUTUJFR0ExVUVBd3dLY0dsa0xXbHpjM1ZsY2pDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBT0lJWEc0NVFPclQ0R3F3cllvR3g5QzdQejBrVUZsVHcxWGQwRm05blBUYk9ESDZqRFBFYnRwYnlYa2ZmYmV4cVpuMzNXUDYxNzR2S0lTUFZVMlFIM0xSZCt6T1JpQXVIdEk4NDdBN0ZCNFg2YjhhK0ZQVGh0dWhGMHV3WmRoNjU1cVduNmNHcldQZ1NoQ0tEQmFkRllsSDZoT2xSNWhPdGQrR0NSVzJKb2pzbmxCZTF2ZmN3cFVpdjZ2bGtmY2dSaDY5c0MzMFltb25VdDZzT0Rlb2tMK20xdC8wcDZyaldzQkJKWHZKYUZWWjB0bG96OS91NVZ3NThBOWpRcFN1RS9iTk1TWE5jRVgxNjFwSnU3UEVHWDM4SHVlOTF5OTlEdnBRYnBPc2tnbW0vdzM3clFSdWF2ODVRRVozZC9iWWEvUEo4Tjc5MENlSFpPcjIwemlvem04Q0F3RUFBVEFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBclZtcWxzNTNYeEswS210Z29DUTlTeFRFUHVadG5jU0N1RTFtNnBNY3M4cHFpTGh5WXYyakk1bUkzWG94VGM3ZmYzYlhTL0xGVk5FWFdaU052K1lhV1RHWXAwMmloRk1OTVVUS0MvZzNCS2MwRkR6M3ZlYXQvSGVEMU15eW5kOENBLzhFZ1haTm5MOGtEUWh1Q2VnOEhKcnpJS1NHNzBxS21aYlRvcG5aOHNWV2VGM2RneG1ITjFDYTRIYUNOQ05xU3Z2eFF1bkF3UUV0T1FCSGdyamRIUzdPN0wwaEExUEQwcWRnc0hYb01ReE14V2RuOU9ZK2wxcEovRC9MQXB6MUxvOWR6dkgwM2tyelpiWXcxUGdVSm5VYzYzYXJTWUdMT1AxU2xWcVVNcVlPbVBnVXU2Q1Q1NFYyWEVETzZSYjJqa0diYUtLeWJSTGhXQnZDM1Z4WVhnPT0iXX0.eyJfc2QiOlsiQl9sN2FfUndQSGlUMHFTOTNqTUc0aGFCbGVjM013VXVrbGdnWm9jankyTSIsIkZTaEFudHhsc0NRV2FscFpldHhCSmFGSmp0akZ1UHpkb1VVdmZWdm4tcGsiLCJIUmJ3NWoxdE9GSnFSRmR2cm1VRnVQQkdSeWFBWmRhcXRXY29MWlEtRElVIiwiSjg4T2p0ZDQ4RlVrYno0emJoYjRmYUhQV3Vrd2k2ZGJ2bmNTOVNWYzI3MCIsIk13bmVrX04tSGgxNmxVT0Yxcm5XZkJiLVRzcm9LOUpZcEs4dmhaZ29oYnciLCJQb183NWh3MFVoZ2NJNV9VODRLNXEyeGxIQUl5a1hWbjU0MGtCeWJYcElZIiwiU29nbmtrenE5dFZUTV9CUDNSX2VXTG1Oazh5ZENjUGotU1hZcUFVdzhsbyIsIlYybjFVX3IzaGMyLUJIUDNCTmREY2dISjJuX2c0dmJpbXF2VDA0M2lVOXciLCJZeEZFQmdFU3QxN09pa0JxZXc2Yk14QVlMYXRmcW44RHpUekNhSU9VbjAwIiwiX05GN25leE8xSFRsOVdjVGY1YnFBOXkxc0VRMzF6Wnc0eE5nczBrbUlKayIsImNwZWFlYi1UTmZJLWpSS05UWVdjT3lValRtNERpcWg5UDNxaENNRWZSQU0iLCJpMTNkRngwWGx5a0FKNWw1YnJIYi1zY1VUb3hQNWxYWFRpREFvS19ES09RIiwiaTVkb3FwR1JVUkw4YnZGejVWTDZEbmQxY3RlcmZ5SnlJWWN2WG1ZS2JQOCIsImphZEUwUm5pN2syRHdqNlZvQ1dEZ042WTZoSTUzQWJfanBIUTVxQ0M2Q28iLCJqd0xrV2pNS3B2VHZPRVlSRTdEdTZidjJEcXdSSkN2RkJQLTd2UnBKY2ZNIiwiblF4RjFPbC0xSnZRdkxwWDg1Z1Iyd2g1WWxiUm9KMFRSTkdjT2ZLQzRoVSIsInBjeHJvZUI1U05za0NRdFkwZ2lOb0xKd3lsQmNwMUtneVQ4bVVXM1VwVFkiLCJxNEhFUGZXTTVrNWZZTFdhQzFvQmFDYkowUFRPMDVwOGhXcWlQZ3d3bWNJIiwid0liWXBCVHJBbXhhTlM0RUlOX3V1VmFmRmNTZkdidVFsMnpTZ0xmSHJROCJdLCJfc2RfYWxnIjoic2hhLTI1NiIsInZjdCI6InVybjpldWRpOnBpZDoxIiwiaXNzIjoiIiwiZXhwIjoxODA1OTY0NjQ2LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoibnFjX19NdXVId3BxaG10V1VJUXFfcE9yVlc5MFc2UUxfeTc4bGZhNVAyYyIsInkiOiJIdWhDYm9LbXZ6MzJiMGVYZmVfRi1wSUtYQ2ljbGtYcHZlYzlLM0JENTFzIn19fQ.SS19zFKfcssytGJrZtizKOMU-Lbvgz2WEiw-k3W3pl3Edl0C2IhnSZWf0SGBE3N7aS4fwxtHHddYw-WbTTBd5emZvxld0Gq78u0jiuQqpggsJU1kFUbRTOmUAOT2jHyAZcg4nDGJO9ciyWWpXNTSjTpn1I4l08vjo0hqwrUzqDh0hoqy-tK-upyJp9r9AyoqzkoTeb9pI2koBZfOBdGrqaUFYPFkv3CVtTFgI8n225KQbxBOwgnINrkpUxGsCrvrwCscXKt0XequbVjAy2oHr1wSC-nkRg3Kcz2pTdiTGFGG4SO41GMqX4o02AWzf_OaGhK4aiBfIEbSrjTx_dzJkQ"#;
        let jwt = Jwt::<serde_json::Value>::from_str(jwt).unwrap();
        use tracing_subscriber::{EnvFilter, fmt, prelude::*};
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
        let verifier = verifier_for_header(&jwt.header().unwrap()).unwrap();
        let _ = jwt
            .verify_signature_with_verifier(verifier.as_ref())
            .unwrap();
    }
}
