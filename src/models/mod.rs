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
pub mod errors;
pub mod transformer;

use josekit::jwk::JwkSet as JoseJwkSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct JwkSet(
    #[serde(serialize_with = "JwkSet::serialize_to_string")]
    #[serde(deserialize_with = "JwkSet::deserialize")]
    pub JoseJwkSet,
);

impl Default for JwkSet {
    fn default() -> Self {
        Self(JoseJwkSet::new())
    }
}

impl JwkSet {
    fn serialize_to_string<S>(set: &JoseJwkSet, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let set: &serde_json::Map<String, serde_json::Value> = set.as_ref();
        serializer.serialize_some(set)
    }
    fn deserialize<'de, D>(deserializer: D) -> Result<JoseJwkSet, D::Error>
    where
        D: Deserializer<'de>,
    {
        let set: serde_json::Value = serde_json::Value::deserialize(deserializer)?;
        let Ok(set) = serde_json::from_value(set) else {
            return Err(serde::de::Error::custom("Failed to deserialize JWK set"));
        };
        let Ok(set) = JoseJwkSet::from_map(set) else {
            return Err(serde::de::Error::custom("Failed to deserialize JWK set"));
        };
        Ok(set)
    }
}

#[macro_export]
macro_rules! extension {
    ([$($field:ident: $type:ty),*], $struct:ty) => {
        impl $struct {
            $(
                pub fn $field(&self) -> $type {
                    let value = self.additional_fields.get(stringify!($field)).unwrap_or(&JsonValue::Null);
                    serde_json::from_value(value.to_owned()).unwrap()
                }
            )*
        }
    };
}

#[macro_export]
macro_rules! models {
    ($(#[$($meta:tt)*])* $vis:vis struct $name:ident { $( $(#[$($meta_field:tt)*])* $field:ident $(($alias:expr))? : $type:ty),*, }) => {
        #[derive(serde::Deserialize, serde::Serialize)]
        $(#[$($meta)*])*
        $vis struct $name {
            $($(#[$($meta_field)*])* $(#[serde(alias = $alias)])? pub $field: $type),*,

            #[serde(flatten)]
            pub additional_fields: serde_json::Map<String, serde_json::Value>,
        }
        impl $name {
            $(
                pub fn $field(&self) -> $type {
                    self.$field.clone()
                }
            )*
            pub fn get_field(&self, name: &str) -> serde_json::Value {
                match name {
                    $(stringify!($field) => {
                       serde_json::to_value(&self.$field).unwrap_or(serde_json::Value ::Null)
                    } )*
                    _ => self.additional_fields.get(name).unwrap_or(&serde_json::Value ::Null).to_owned()
                }
            }
            pub fn to_transformer(&self, transformer: &mut dyn $crate::models::transformer::Transformer) {
                $(
                    let v = serde_json::to_value(&self.$field).unwrap_or(serde_json::Value ::Null);
                     $(transformer.set_field($alias, v.clone().into());)?
                    transformer.set_field(stringify!($field), v.into());
                )*
                for (key, value) in &self.additional_fields {
                    transformer.set_field(key, value.clone().into());
                }
            }
        }
        impl $crate::models::transformer::Transformer for $name {
            fn set_field(&mut self, name: &str, value: $crate::models::transformer::Value) {
                match name {
                    $(stringify!($field) => {
                        self.$field = serde_json::from_value(value.into()).unwrap();
                    } )*
                    $($(
                        $alias => {
                            self.$field = serde_json::from_value(value.into()).unwrap();
                        }
                    )?)*
                    _ =>  { self.additional_fields.insert(name.to_string(), value.into()); }
                }
            }
            fn transform(self, transformer: &mut dyn $crate::models::transformer::Transformer) -> Result<(), String> {
                self.to_transformer(transformer);
                Ok(())
            }
            fn write_to_transformer(&self, transformer: &mut dyn $crate::models::transformer::Transformer) {
                self.to_transformer(transformer);
            }
        }
    };
}
