use pod2::middleware::{
    Key, Value,
    containers::{Array, Dictionary, Set},
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

const DEPTH: usize = 5;

/// Error type for JSON-POD conversion operations
#[derive(Debug)]
pub enum ConversionError {
    SerializationError(serde_json::Error),
    DeserializationError(serde_json::Error),
    UnsupportedType(String),
    InvalidPodValue(String),
    PodError(String),
}

impl From<serde_json::Error> for ConversionError {
    fn from(err: serde_json::Error) -> Self {
        ConversionError::SerializationError(err)
    }
}

/// Core converter struct for JSON ↔ POD Value conversions
pub struct JsonPodConverter;

impl JsonPodConverter {
    /// Create a new converter
    pub fn new() -> Self {
        Self
    }

    /// Convert a JSON value to a POD Value
    pub fn json_to_pod_value(&self, json: &serde_json::Value) -> Result<Value, ConversionError> {
        match json {
            serde_json::Value::Null => Err(ConversionError::UnsupportedType(
                "Null values not supported".to_string(),
            )),
            serde_json::Value::Bool(b) => Ok(Value::from(*b)),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Value::from(i))
                } else if let Some(u) = n.as_u64() {
                    // Handle u64 that might not fit in i64
                    if u <= i64::MAX as u64 {
                        Ok(Value::from(u as i64))
                    } else {
                        // Convert large u64 to string to preserve value
                        Ok(Value::from(u.to_string()))
                    }
                } else {
                    // Float value
                    Err(ConversionError::UnsupportedType(
                        "Float values not supported".to_string(),
                    ))
                }
            }
            serde_json::Value::String(s) => Ok(Value::from(s.clone())),
            serde_json::Value::Array(arr) => {
                // Convert to POD Array
                let mut values = Vec::new();
                for item in arr {
                    values.push(self.json_to_pod_value(item)?);
                }

                let pod_array = Array::new(DEPTH, values.into_iter().collect()).map_err(|e| {
                    ConversionError::PodError(format!("Array creation failed: {:?}", e))
                })?;

                Ok(Value::from(pod_array))
            }
            serde_json::Value::Object(obj) => {
                // Convert to POD Dictionary
                let mut dict_entries = HashMap::new();
                for (key, value) in obj {
                    let pod_key = Key::from(key.clone());
                    let pod_value = self.json_to_pod_value(value)?;
                    dict_entries.insert(pod_key, pod_value);
                }

                let pod_dict = Dictionary::new(DEPTH, dict_entries).map_err(|e| {
                    ConversionError::PodError(format!("Dictionary creation failed: {:?}", e))
                })?;

                Ok(Value::from(pod_dict))
            }
        }
    }
}

impl Default for JsonPodConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for converting types to POD Values
pub trait ToPodValue {
    fn to_pod_value(&self) -> Result<Value, ConversionError>;
}
