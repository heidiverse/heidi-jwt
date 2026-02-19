use serde::{Serialize, de::DeserializeOwned};

use crate::{
    jwt::JwtVerifier,
    models::{
        self,
        errors::{JwsError, JwtError, PayloadError},
    },
};

pub struct DefaultVerifier {
    jwt_type: String,
    required_claims: Vec<ClaimValidator>,
}
pub enum ClaimValidator {
    Presence(String),
    Value(String, models::transformer::Value),
}

impl DefaultVerifier {
    pub fn new(jwt_type: String, required_claims: Vec<ClaimValidator>) -> Self {
        DefaultVerifier {
            jwt_type,
            required_claims,
        }
    }
}

impl<T: Serialize + DeserializeOwned> JwtVerifier<T> for DefaultVerifier {
    fn verify_header(&self, jwt: &super::Jwt<T>) -> Result<(), crate::models::errors::JwtError> {
        let header = jwt.header()?;
        let crit = header.critical();
        if crit.is_some() {
            return Err(JwtError::Jws(JwsError::InvalidHeader(format!(
                "unknown crit: {:?}",
                crit
            ))));
        }
        self.assert_type(jwt, &self.jwt_type)
    }

    fn verify_body(&self, jwt: &super::Jwt<T>) -> Result<(), crate::models::errors::JwtError> {
        let payload = jwt.payload_unverified();
        let payload = payload.insecure();
        let Ok(val) = serde_json::to_value(payload) else {
            return Err(JwtError::Payload(PayloadError::MissingRequiredProperty(
                "cannot check body".to_string(),
            )));
        };
        for c in &self.required_claims {
            match c {
                ClaimValidator::Presence(c) => {
                    if val.get(c).is_none() {
                        return Err(JwtError::Payload(PayloadError::MissingRequiredProperty(
                            format!("missing required claim: {}", c),
                        )));
                    }
                }
                ClaimValidator::Value(claim, value) => {
                    let Some(val) = val.get(claim) else {
                        return Err(JwtError::Payload(PayloadError::MissingRequiredProperty(
                            format!("missing required claim: {}", claim),
                        )));
                    };
                    let value: serde_json::Value = (value.to_owned()).into();
                    if val != &value {
                        return Err(JwtError::Payload(PayloadError::MissingRequiredProperty(
                            format!("invalid value for claim: {}", claim),
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}
