use pod2::middleware::PublicKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),
    #[error("Failed to parse public key: {0}")]
    KeyParseError(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub server: ServerSettings,
    #[serde(default)]
    pub membership: MembershipSettings,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerSettings {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MembershipSettings {
    #[serde(default)]
    pub initial_admins: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            membership: MembershipSettings::default(),
        }
    }
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Default for MembershipSettings {
    fn default() -> Self {
        Self {
            initial_admins: Vec::new(),
        }
    }
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

impl ServerConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path)?;
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::load_from_file(path) {
            Ok(config) => config,
            Err(_) => Self::default(),
        }
    }

    pub fn parse_initial_admins(&self) -> Result<Vec<PublicKey>, ConfigError> {
        let mut admins = Vec::new();
        for admin_str in &self.membership.initial_admins {
            // Try to parse the string as a PublicKey
            // The format should be something like "PublicKey(0x1234...)" or just "0x1234..."
            let key = if admin_str.starts_with("PublicKey(") && admin_str.ends_with(')') {
                // Extract the content between PublicKey( and )
                let hex_part = &admin_str[10..admin_str.len() - 1];
                parse_public_key_from_hex(hex_part)?
            } else {
                // Assume it's just the hex string
                parse_public_key_from_hex(admin_str)?
            };
            admins.push(key);
        }
        Ok(admins)
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.server.host, self.server.port)
    }
}

fn parse_public_key_from_hex(key_str: &str) -> Result<PublicKey, ConfigError> {
    // Remove "0x" prefix if present for hex format
    let cleaned_str = if key_str.starts_with("0x") {
        &key_str[2..]
    } else {
        key_str
    };

    // Try parsing as Point string format first (e.g., "Point { x: ... }")
    if let Ok(public_key) = cleaned_str.parse::<PublicKey>() {
        return Ok(public_key);
    }

    // If that fails, try the original string without cleaning
    if let Ok(public_key) = key_str.parse::<PublicKey>() {
        return Ok(public_key);
    }

    // If both fail, return error
    Err(ConfigError::KeyParseError(format!(
        "Failed to parse public key from string: {}",
        key_str
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert!(config.membership.initial_admins.is_empty());
    }

    #[test]
    fn test_config_parsing() {
        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080

[membership]
initial_admins = [
    "0x1234567890abcdef",
    "PublicKey(0xfedcba0987654321)"
]
"#;

        let config: ServerConfig = toml::from_str(config_content).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.membership.initial_admins.len(), 2);
        assert_eq!(config.membership.initial_admins[0], "0x1234567890abcdef");
        assert_eq!(
            config.membership.initial_admins[1],
            "PublicKey(0xfedcba0987654321)"
        );
    }

    #[test]
    fn test_load_from_file() {
        let config_content = r#"
[server]
host = "localhost"
port = 4000

[membership]
initial_admins = ["0x123"]
"#;

        let temp_file = NamedTempFile::new().unwrap();
        fs::write(temp_file.path(), config_content).unwrap();

        let config = ServerConfig::load_from_file(temp_file.path()).unwrap();
        assert_eq!(config.server.host, "localhost");
        assert_eq!(config.server.port, 4000);
        assert_eq!(config.membership.initial_admins.len(), 1);
    }

    #[test]
    fn test_load_or_default_with_missing_file() {
        let config = ServerConfig::load_or_default("nonexistent_file.toml");
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 3000);
        assert!(config.membership.initial_admins.is_empty());
    }

    #[test]
    fn test_bind_address() {
        let mut config = ServerConfig::default();
        assert_eq!(config.bind_address(), "0.0.0.0:3000");

        config.server.host = "127.0.0.1".to_string();
        config.server.port = 8080;
        assert_eq!(config.bind_address(), "127.0.0.1:8080");
    }
}

