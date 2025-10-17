use crate::error::{Result, SidecarError};
use crate::stage_a::KeyProvider;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfig {
    pub provider: String,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    pub key_cache_ttl_secs: u64,
}

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            provider: "mock".to_string(),
            region: None,
            endpoint: None,
            key_cache_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedKey {
    key: Zeroizing<Vec<u8>>,
    expires_at: std::time::Instant,
}

pub struct KmsKeyProvider {
    config: KmsConfig,
    key_cache: Arc<RwLock<HashMap<String, CachedKey>>>,
    backend: Box<dyn KmsBackend>,
}

pub trait KmsBackend: Send + Sync {
    fn get_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn list_keys(&self) -> Result<Vec<String>>;
}

pub struct MockKmsBackend {
    keys: HashMap<String, Vec<u8>>,
}

impl MockKmsBackend {
    pub fn new() -> Self {
        let mut keys = HashMap::new();
        
        // Pre-populate with test keys
        keys.insert("client1".to_string(), b"test-key-client1-32bytes-long!!".to_vec());
        keys.insert("client2".to_string(), b"test-key-client2-32bytes-long!!".to_vec());
        keys.insert("client3".to_string(), b"test-key-client3-32bytes-long!!".to_vec());
        
        Self { keys }
    }
    
    pub fn add_key(&mut self, client_id: String, key: Vec<u8>) {
        self.keys.insert(client_id, key);
    }
}

impl KmsBackend for MockKmsBackend {
    fn get_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        debug!("Fetching key for client: {}", key_id);
        
        self.keys.get(key_id)
            .map(|k| Zeroizing::new(k.clone()))
            .ok_or_else(|| SidecarError::Auth(format!("Key not found for client: {}", key_id)))
    }
    
    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.keys.keys().cloned().collect())
    }
}

#[cfg(feature = "aws-kms")]
pub struct AwsKmsBackend {
    client: aws_sdk_kms::Client,
    key_mapping: HashMap<String, String>, // client_id -> kms_key_id
}

#[cfg(feature = "aws-kms")]
impl AwsKmsBackend {
    pub async fn new(region: &str, key_mapping: HashMap<String, String>) -> Result<Self> {
        let config = aws_config::from_env()
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        
        let client = aws_sdk_kms::Client::new(&config);
        
        Ok(Self { client, key_mapping })
    }
}

#[cfg(feature = "aws-kms")]
impl KmsBackend for AwsKmsBackend {
    fn get_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let kms_key_id = self.key_mapping.get(key_id)
            .ok_or_else(|| SidecarError::Auth(format!("No KMS key mapping for client: {}", key_id)))?;
        
        // In production, this would use KMS GenerateDataKey or Decrypt
        // For now, return a derived key based on the KMS key ID
        let mut key = vec![0u8; 32];
        let hash = blake3::hash(format!("{}:{}", kms_key_id, key_id).as_bytes());
        key.copy_from_slice(&hash.as_bytes()[..32]);
        
        Ok(Zeroizing::new(key))
    }
    
    fn list_keys(&self) -> Result<Vec<String>> {
        Ok(self.key_mapping.keys().cloned().collect())
    }
}

impl KmsKeyProvider {
    pub fn new(config: KmsConfig) -> Result<Self> {
        let backend: Box<dyn KmsBackend> = match config.provider.as_str() {
            "mock" => Box::new(MockKmsBackend::new()),
            #[cfg(feature = "aws-kms")]
            "aws" => {
                return Err(SidecarError::Config(anyhow::anyhow!(
                    "AWS KMS backend requires async initialization. Use new_aws() method."
                )));
            }
            _ => return Err(SidecarError::Config(anyhow::anyhow!(
                "Unsupported KMS provider: {}", config.provider
            ))),
        };
        
        info!("Initialized KMS provider: {}", config.provider);
        
        Ok(Self {
            config,
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            backend,
        })
    }
    
    #[cfg(feature = "aws-kms")]
    pub async fn new_aws(config: KmsConfig, key_mapping: HashMap<String, String>) -> Result<Self> {
        let region = config.region.as_ref()
            .ok_or_else(|| SidecarError::Config(anyhow::anyhow!("AWS region required")))?;
        
        let backend = Box::new(AwsKmsBackend::new(region, key_mapping).await?);
        
        info!("Initialized AWS KMS provider in region: {}", region);
        
        Ok(Self {
            config,
            key_cache: Arc::new(RwLock::new(HashMap::new())),
            backend,
        })
    }
    
    pub async fn cleanup_expired_keys(&self) {
        let now = std::time::Instant::now();
        let mut cache = self.key_cache.write().await;
        
        let initial_count = cache.len();
        cache.retain(|_, cached| cached.expires_at > now);
        let removed = initial_count - cache.len();
        
        if removed > 0 {
            debug!("Cleaned up {} expired keys from cache", removed);
        }
    }
    
    pub async fn preload_keys(&self, client_ids: &[String]) -> Result<()> {
        info!("Preloading keys for {} clients", client_ids.len());
        
        for client_id in client_ids {
            if let Err(e) = self.get_hmac_key(client_id) {
                error!("Failed to preload key for client {}: {}", client_id, e);
            }
        }
        
        Ok(())
    }
    
    pub async fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.key_cache.read().await;
        let total_keys = cache.len();
        let expired_keys = cache.values()
            .filter(|cached| cached.expires_at <= std::time::Instant::now())
            .count();
        
        (total_keys, expired_keys)
    }
}

impl KeyProvider for KmsKeyProvider {
    fn get_hmac_key(&self, client_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        // Try cache first (this would need to be async in production)
        // For now, we'll skip caching in the sync implementation
        
        debug!("Fetching HMAC key for client: {}", client_id);
        self.backend.get_key(client_id)
    }
}

pub fn start_key_cleanup_task(kms_provider: Arc<KmsKeyProvider>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        
        loop {
            interval.tick().await;
            kms_provider.cleanup_expired_keys().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mock_kms_backend() {
        let backend = MockKmsBackend::new();
        
        let key = backend.get_key("client1").unwrap();
        assert_eq!(key.len(), 32);
        
        let keys = backend.list_keys().unwrap();
        assert!(keys.contains(&"client1".to_string()));
    }
    
    #[tokio::test]
    async fn test_kms_key_provider() {
        let config = KmsConfig::default();
        let provider = KmsKeyProvider::new(config).unwrap();
        
        let key = provider.get_hmac_key("client1").unwrap();
        assert_eq!(key.len(), 32);
        
        // Test cache stats
        let (total, expired) = provider.get_cache_stats().await;
        assert_eq!(expired, 0);
    }
}