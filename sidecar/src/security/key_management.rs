// Removed unused import
use ed25519_dalek::SigningKey;
use zeroize::Zeroize;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use anyhow::{Result, anyhow};
use tracing::{info, warn};
use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
use ring::rand::{SystemRandom, SecureRandom};

pub struct SecureKey {
    key: [u8; 32],
    created_at: SystemTime,
    key_id: String,
}

impl SecureKey {
    pub fn new(key: [u8; 32], key_id: String) -> Self {
        Self {
            key,
            created_at: SystemTime::now(),
            key_id,
        }
    }
    
    pub fn is_expired(&self, max_age: Duration) -> bool {
        self.created_at.elapsed().unwrap_or(Duration::MAX) > max_age
    }
    
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
    
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Zeroize for SecureKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.key_id.zeroize();
    }
}

pub struct KeyManager {
    key_cache: Mutex<Option<(SecureKey, SystemTime)>>,
    rotation_interval: Duration,
    rng: SystemRandom,
}

impl KeyManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            key_cache: Mutex::new(None),
            rotation_interval: Duration::from_secs(3600), // 1 hour default
            rng: SystemRandom::new(),
        })
    }
    
    pub async fn get_signing_key(&self) -> Result<SigningKey> {
        let secure_key = self.get_hmac_key().await?;
        let signing_key = SigningKey::from_bytes(secure_key.as_bytes());
        Ok(signing_key)
    }
    
    pub async fn get_hmac_key(&self) -> Result<SecureKey> {
        // Check cache first
        if let Ok(mut cache) = self.key_cache.lock() {
            if let Some((ref key, _timestamp)) = *cache {
                if !key.is_expired(self.rotation_interval) {
                    return Ok(SecureKey::new(*key.as_bytes(), key.key_id().to_string()));
                } else {
                    warn!("Cached key expired, rotating");
                    *cache = None;
                }
            }
        }
        
        // Get fresh key from provider
        // Simplified key generation for testing
        let mut key_bytes = [0u8; 32];
        self.rng.fill(&mut key_bytes).map_err(|_| anyhow::anyhow!("RNG failed"))?;
        let key = SecureKey::new(key_bytes, "test-key".to_string());
        
        // Update cache
        if let Ok(mut cache) = self.key_cache.lock() {
            *cache = Some((SecureKey::new(*key.as_bytes(), key.key_id().to_string()), SystemTime::now()));
        }
        
        Ok(key)
    }
    
    pub async fn rotate_keys(&self) -> Result<()> {
        info!("Starting key rotation");
        // Simplified key rotation for testing
        info!("Key rotation completed (simplified)");
        
        // Clear cache to force reload
        if let Ok(mut cache) = self.key_cache.lock() {
            *cache = None;
        }
        
        info!("Key rotation completed");
        Ok(())
    }
    
    pub fn derive_key(&self, password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| anyhow!("Salt encoding failed: {}", e))?;
        
        let hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
        
        let mut key = [0u8; 32];
        let hash_bytes = hash.hash.ok_or_else(|| anyhow!("No hash generated"))?;
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        Ok(key)
    }
}

#[async_trait::async_trait]
pub trait KeyProvider {
    async fn get_key(&self) -> Result<SecureKey>;
    async fn rotate_keys(&self) -> Result<()>;
    async fn audit_access(&self, operation: &str);
}

pub struct FileKeyProvider {
    key_path: std::path::PathBuf,
}

impl FileKeyProvider {
    pub async fn new() -> Result<Self> {
        let key_path = std::env::var("LEGION_KEY_PATH")
            .unwrap_or_else(|_| "/run/secrets/legion.key".to_string());
        
        Ok(Self {
            key_path: std::path::PathBuf::from(key_path),
        })
    }
    
    fn generate_key_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("file-key-{}", timestamp)
    }
}

#[async_trait::async_trait]
impl KeyProvider for FileKeyProvider {
    async fn get_key(&self) -> Result<SecureKey> {
        self.audit_access("file_key_access").await;
        
        let key_data = tokio::fs::read(&self.key_path).await
            .map_err(|e| anyhow!("Failed to read key file: {}", e))?;
        
        if key_data.len() < 32 {
            return Err(anyhow!("Key file too short"));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_data[..32]);
        
        Ok(SecureKey::new(key, Self::generate_key_id()))
    }
    
    async fn rotate_keys(&self) -> Result<()> {
        self.audit_access("file_key_rotation").await;
        
        let rng = SystemRandom::new();
        let mut new_key = [0u8; 32];
        rng.fill(&mut new_key)
            .map_err(|_| anyhow!("Failed to generate random key"))?;
        
        tokio::fs::write(&self.key_path, &new_key).await
            .map_err(|e| anyhow!("Failed to write new key: {}", e))?;
        
        info!("File key rotated successfully");
        Ok(())
    }
    
    async fn audit_access(&self, operation: &str) {
        info!("Key access: {} at {:?}", operation, SystemTime::now());
    }
}

pub struct VaultKeyProvider {
    client: reqwest::Client,
    vault_addr: String,
    vault_token: String,
}

impl VaultKeyProvider {
    pub async fn new(addr: String, token: String) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
            vault_addr: addr,
            vault_token: token,
        })
    }
}

#[async_trait::async_trait]
impl KeyProvider for VaultKeyProvider {
    async fn get_key(&self) -> Result<SecureKey> {
        self.audit_access("vault_key_access").await;
        
        let url = format!("{}/v1/secret/data/legion-keys", self.vault_addr);
        let response = self.client
            .get(&url)
            .header("X-Vault-Token", &self.vault_token)
            .send()
            .await
            .map_err(|e| anyhow!("Vault request failed: {}", e))?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Vault returned error: {}", response.status()));
        }
        
        let vault_response: serde_json::Value = response.json().await
            .map_err(|e| anyhow!("Failed to parse Vault response: {}", e))?;
        
        let key_hex = vault_response["data"]["data"]["key"]
            .as_str()
            .ok_or_else(|| anyhow!("Key not found in Vault response"))?;
        
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| anyhow!("Invalid hex key: {}", e))?;
        
        if key_bytes.len() != 32 {
            return Err(anyhow!("Invalid key length"));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        
        let key_id = vault_response["data"]["data"]["key_id"]
            .as_str()
            .unwrap_or("vault-key-unknown")
            .to_string();
        
        Ok(SecureKey::new(key, key_id))
    }
    
    async fn rotate_keys(&self) -> Result<()> {
        self.audit_access("vault_key_rotation").await;
        
        let rng = SystemRandom::new();
        let mut new_key = [0u8; 32];
        rng.fill(&mut new_key)
            .map_err(|_| anyhow!("Failed to generate random key"))?;
        
        let key_id = format!("vault-key-{}", SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs());
        
        let payload = serde_json::json!({
            "data": {
                "key": hex::encode(new_key),
                "key_id": key_id
            }
        });
        
        let url = format!("{}/v1/secret/data/legion-keys", self.vault_addr);
        let response = self.client
            .post(&url)
            .header("X-Vault-Token", &self.vault_token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| anyhow!("Vault rotation request failed: {}", e))?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Vault rotation failed: {}", response.status()));
        }
        
        info!("Vault key rotated successfully");
        Ok(())
    }
    
    async fn audit_access(&self, operation: &str) {
        info!("Vault key access: {} at {:?}", operation, SystemTime::now());
    }
}