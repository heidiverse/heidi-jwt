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

    use crate::jwt::{Jwt, creator::JwtCreator};

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
        MHcCAQEEIKgaNo3YMVBLkbpvyrKMS7rR0Ey8G7BqM1BzL18iYY52oAoGCCqGSM49
        AwEHoUQDQgAEWvKFuI1SuxSeydyxBVEdJRqQhz1TvV87Niy0KhkTii4tXWRL9vww
        RJVQEx63tA/+uc5uNpm1MJ3cANXQAGKXsw==
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
        let sig = Es256.signer_from_pem(privatekey).unwrap();
    }
}
