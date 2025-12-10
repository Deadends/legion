use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
    pub zk: ZkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub request_timeout_secs: u64,
    pub shutdown_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub client_auth: bool,
    pub ca_cert_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub hmac_key: String,
    pub ticket_ttl_secs: u64,
    pub max_replay_window_secs: u64,
    pub rate_limit_per_sec: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkConfig {
    pub verifier_pool_size: usize,
    pub queue_capacity: usize,
    pub proof_timeout_secs: u64,
    pub batch_size: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8443,
                max_connections: 1000,
                request_timeout_secs: 30,
                shutdown_timeout_secs: 10,
            },
            tls: TlsConfig {
                cert_path: "cert.pem".into(),
                key_path: "key.pem".into(),
                client_auth: false,
                ca_cert_path: None,
            },
            auth: AuthConfig {
                hmac_key: "change-me-in-production".to_string(),
                ticket_ttl_secs: 300,
                max_replay_window_secs: 60,
                rate_limit_per_sec: 100,
            },
            zk: ZkConfig {
                verifier_pool_size: 4,
                queue_capacity: 1000,
                proof_timeout_secs: 60,
                batch_size: 10,
            },

        }
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::env::var("CONFIG_PATH").unwrap_or_else(|_| "config.toml".to_string());
        
        if std::path::Path::new(&path).exists() {
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file: {}", path))?;
            
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse config file: {}", path))
        } else {
            tracing::warn!("Config file {} not found, using defaults", path);
            Ok(Self::default())
        }
    }
    
    pub fn validate(&self) -> Result<()> {
        if self.auth.hmac_key == "change-me-in-production" {
            tracing::warn!("Using default HMAC key - change this in production!");
        }
        
        if self.server.port < 1024 {
            #[cfg(unix)]
            if std::env::var("USER").unwrap_or_default() != "root" {
                tracing::warn!("Port {} requires root privileges", self.server.port);
            }
        }
        
        Ok(())
    }
}