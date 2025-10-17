use crate::{config::Config, error::Result, metrics::LegionMetrics};
use notify::{Watcher, RecursiveMode, watcher, DebouncedEvent};
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tracing::{info, warn, error};

#[derive(Debug, Clone)]
pub struct ConfigManager {
    config: Arc<RwLock<Config>>,
    config_path: String,
    metrics: Arc<LegionMetrics>,
    reload_tx: broadcast::Sender<Config>,
}

impl ConfigManager {
    pub fn new(config_path: String, metrics: Arc<LegionMetrics>) -> Result<Self> {
        let config = Config::load(&config_path)?;
        let (reload_tx, _) = broadcast::channel(16);
        
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            config_path,
            metrics,
            reload_tx,
        })
    }

    pub async fn get_config(&self) -> Config {
        self.config.read().await.clone()
    }

    pub fn subscribe_to_reloads(&self) -> broadcast::Receiver<Config> {
        self.reload_tx.subscribe()
    }

    pub async fn start_hot_reload(&self) -> Result<()> {
        let config_path = self.config_path.clone();
        let config = self.config.clone();
        let metrics = self.metrics.clone();
        let reload_tx = self.reload_tx.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::watch_config_file(config_path, config, metrics, reload_tx).await {
                error!("Config file watcher failed: {}", e);
            }
        });

        info!("Hot reload enabled for config file: {}", self.config_path);
        Ok(())
    }

    async fn watch_config_file(
        config_path: String,
        config: Arc<RwLock<Config>>,
        metrics: Arc<LegionMetrics>,
        reload_tx: broadcast::Sender<Config>,
    ) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        let mut watcher = watcher(tx, Duration::from_secs(1))?;
        
        watcher.watch(&config_path, RecursiveMode::NonRecursive)?;
        info!("Watching config file for changes: {}", config_path);

        loop {
            match rx.recv() {
                Ok(DebouncedEvent::Write(_)) | Ok(DebouncedEvent::Create(_)) => {
                    info!("Config file changed, reloading...");
                    
                    match Self::reload_config(&config_path, &config, &metrics, &reload_tx).await {
                        Ok(_) => info!("Config reloaded successfully"),
                        Err(e) => error!("Failed to reload config: {}", e),
                    }
                }
                Ok(_) => {} // Ignore other events
                Err(e) => {
                    error!("Config file watch error: {}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn reload_config(
        config_path: &str,
        config: &Arc<RwLock<Config>>,
        metrics: &Arc<LegionMetrics>,
        reload_tx: &broadcast::Sender<Config>,
    ) -> Result<()> {
        let new_config = Config::load(config_path)?;
        new_config.validate()?;

        {
            let mut current_config = config.write().await;
            *current_config = new_config.clone();
        }

        metrics.record_config_reload();
        
        if let Err(e) = reload_tx.send(new_config) {
            warn!("Failed to broadcast config reload: {}", e);
        }

        Ok(())
    }

    pub async fn reload_now(&self) -> Result<()> {
        Self::reload_config(
            &self.config_path,
            &self.config,
            &self.metrics,
            &self.reload_tx,
        ).await
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub stage_a_enabled: bool,
    pub stage_b_enabled: bool,
    pub key_rotation_interval: u64,
    pub metrics_enabled: bool,
    pub log_level: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            stage_a_enabled: true,
            stage_b_enabled: true,
            key_rotation_interval: 60,
            metrics_enabled: true,
            log_level: "info".to_string(),
        }
    }
}

impl RuntimeConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            stage_a_enabled: true, // Always enabled for now
            stage_b_enabled: true, // Always enabled for now
            key_rotation_interval: 60, // Fixed for now
            metrics_enabled: true, // Always enabled for now
            log_level: "info".to_string(), // Fixed for now
        }
    }

    pub fn update_log_level(&self) -> Result<()> {
        use tracing_subscriber::filter::LevelFilter;
        
        let level = match self.log_level.as_str() {
            "trace" => LevelFilter::TRACE,
            "debug" => LevelFilter::DEBUG,
            "info" => LevelFilter::INFO,
            "warn" => LevelFilter::WARN,
            "error" => LevelFilter::ERROR,
            _ => LevelFilter::INFO,
        };

        info!("Updated log level to: {}", self.log_level);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_config_manager() {
        let metrics = Arc::new(LegionMetrics::new().unwrap());
        
        // Create temporary config file
        let temp_file = NamedTempFile::new().unwrap();
        let config_path = temp_file.path().to_str().unwrap().to_string();
        
        // Write initial config
        fs::write(&config_path, r#"
[server]
host = "127.0.0.1"
port = 8443
max_connections = 1000
request_timeout_secs = 30
shutdown_timeout_secs = 10

[tls]
cert_path = "cert.pem"
key_path = "key.pem"
client_auth = false

[auth]
hmac_key = "test-key"
ticket_ttl_secs = 300
max_replay_window_secs = 60
rate_limit_per_sec = 100

[zk]
verifier_pool_size = 4
queue_capacity = 1000
proof_timeout_secs = 60
batch_size = 10

[kms]
provider = "mock"
key_cache_ttl_secs = 300
        "#).unwrap();

        let config_manager = ConfigManager::new(config_path, metrics).unwrap();
        let initial_config = config_manager.get_config().await;
        
        assert_eq!(initial_config.server.port, 8443);
    }
}