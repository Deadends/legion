// Professional Security Module Architecture
pub mod key_management;
pub mod audit;
pub mod crypto;

use std::sync::Arc;
use anyhow::Result;
use tracing::info;

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub key_provider_type: KeyProviderType,
    pub audit_enabled: bool,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone)]
pub enum KeyProviderType {
    File,
    Vault { addr: String, token: String },
}

#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    Development,
    Production,
    Enterprise,
}

impl SecurityLevel {
    pub fn key_rotation_interval(&self) -> std::time::Duration {
        match self {
            Self::Development => std::time::Duration::from_secs(86400 * 7),
            Self::Production => std::time::Duration::from_secs(86400),
            Self::Enterprise => std::time::Duration::from_secs(3600 * 4),
        }
    }
}

pub async fn initialize_security(config: SecurityConfig) -> Result<Arc<SecurityManager>> {
    info!("Initializing Legion security subsystem");
    
    let audit_system = if config.audit_enabled {
        Some(audit::AuditSystem::new().await?)
    } else {
        None
    };
    
    let key_manager = key_management::KeyManager::new()?;
    let crypto_engine = crypto::CryptoEngine::new(config.security_level)?;
    
    Ok(Arc::new(SecurityManager {
        config,
        audit_system,
        key_manager,
        crypto_engine,
    }))
}

pub struct SecurityManager {
    config: SecurityConfig,
    audit_system: Option<audit::AuditSystem>,
    key_manager: key_management::KeyManager,
    crypto_engine: crypto::CryptoEngine,
}

impl SecurityManager {
    pub async fn audit_event(&self, event: audit::SecurityEvent) -> Result<()> {
        if let Some(ref audit) = self.audit_system {
            audit.log_event(event).await?;
        }
        Ok(())
    }
    
    pub fn key_manager(&self) -> &key_management::KeyManager {
        &self.key_manager
    }
}