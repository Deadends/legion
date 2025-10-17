use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use crate::{get_timestamp, fill_random_bytes};

/// Enterprise key management system extracted from final_circuit.rs
pub struct EnterpriseKeyManager;

impl EnterpriseKeyManager {
    /// Get server key from secure storage
    pub fn get_server_key() -> Result<[u8; 32]> {
        Self::try_encrypted_storage_key()
            .or_else(|_| Self::derive_deterministic_key())
    }
    
    fn try_encrypted_storage_key() -> Result<[u8; 32]> {
        let master_key = Self::get_master_key()?;
        let encrypted_key = Self::load_encrypted_server_key()?;
        Self::decrypt_server_key(&encrypted_key, &master_key)
    }
    
    fn derive_deterministic_key() -> Result<[u8; 32]> {
        let mut kdf = blake3::Hasher::new();
        kdf.update(b"LEGION_SERVER_KEY_V1");
        kdf.update(&Self::get_system_fingerprint()?);
        kdf.update(&Self::get_hardware_id()?);
        kdf.update(&Self::get_deployment_salt()?);
        Ok(*kdf.finalize().as_bytes())
    }
    
    /// CA key management
    pub fn get_ca_keypair(issuer: &str) -> Result<([u8; 32], [u8; 32])> {
        let ca_seed = Self::get_ca_master_seed()?;
        Self::derive_ca_keypair_from_seed(&ca_seed, issuer)
    }
    
    fn get_ca_master_seed() -> Result<[u8; 32]> {
        if let Ok(seed_hex) = std::env::var("LEGION_CA_MASTER_SEED") {
            if seed_hex.len() == 64 {
                let mut seed = [0u8; 32];
                hex::decode_to_slice(&seed_hex, &mut seed)
                    .map_err(|_| anyhow!("Invalid CA master seed format"))?;
                return Ok(seed);
            }
        }
        
        let mut kdf = blake3::Hasher::new();
        kdf.update(b"LEGION_CA_MASTER_SEED_V1");
        kdf.update(&Self::get_system_fingerprint()?);
        kdf.update(&Self::get_hardware_id()?);
        kdf.update(&Self::get_deployment_salt()?);
        kdf.update(b"CA_ROOT_AUTHORITY");
        Ok(*kdf.finalize().as_bytes())
    }
    
    fn derive_ca_keypair_from_seed(seed: &[u8; 32], issuer: &str) -> Result<([u8; 32], [u8; 32])> {
        let mut kdf = blake3::Hasher::new();
        kdf.update(b"CA_KEYPAIR_DERIVATION_V1");
        kdf.update(seed);
        kdf.update(issuer.as_bytes());
        kdf.update(b"ED25519_KEYPAIR");
        
        let derived_seed = kdf.finalize();
        let mut ed25519_seed = [0u8; 32];
        ed25519_seed.copy_from_slice(&derived_seed.as_bytes()[..32]);
        
        let signing_key = SigningKey::from_bytes(&ed25519_seed);
        let verifying_key = signing_key.verifying_key();
        
        Ok((verifying_key.to_bytes(), signing_key.to_bytes()))
    }
    
    // Private helper methods
    
    fn get_master_key() -> Result<[u8; 32]> {
        if let Ok(key_hex) = std::env::var("LEGION_MASTER_KEY") {
            if key_hex.len() == 64 {
                let mut key = [0u8; 32];
                hex::decode_to_slice(&key_hex, &mut key)
                    .map_err(|_| anyhow!("Invalid master key format"))?;
                return Ok(key);
            }
        }
        Self::derive_system_master_key()
    }
    
    fn derive_system_master_key() -> Result<[u8; 32]> {
        let mut kdf = blake3::Hasher::new();
        kdf.update(b"LEGION_MASTER_KEY_V1");
        kdf.update(&Self::get_system_fingerprint()?);
        kdf.update(&Self::get_installation_id()?);
        Ok(*kdf.finalize().as_bytes())
    }
    
    fn load_encrypted_server_key() -> Result<Vec<u8>> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let key_path = std::env::var("LEGION_KEY_PATH")
                .unwrap_or_else(|_| "./secure_storage/server.key".to_string());
            
            if std::path::Path::new(&key_path).exists() {
                return std::fs::read(&key_path)
                    .map_err(|e| anyhow!("Failed to read server key: {}", e));
            }
        }
        Self::generate_and_store_server_key()
    }
    
    fn generate_and_store_server_key() -> Result<Vec<u8>> {
        let mut server_key = [0u8; 32];
        fill_random_bytes(&mut server_key)?;
        
        let master_key = Self::get_master_key()?;
        let encrypted = Self::encrypt_server_key(&server_key, &master_key)?;
        
        #[cfg(not(target_arch = "wasm32"))]
        {
            let key_path = std::env::var("LEGION_KEY_PATH")
                .unwrap_or_else(|_| "./secure_storage/server.key".to_string());
            
            if let Some(parent) = std::path::Path::new(&key_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&key_path, &encrypted)?;
        }
        
        Ok(encrypted)
    }
    
    fn encrypt_server_key(key: &[u8; 32], master_key: &[u8; 32]) -> Result<Vec<u8>> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
        
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master_key));
        let mut nonce_bytes = [0u8; 12];
        fill_random_bytes(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut buffer = key.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, b"LEGION_SERVER_KEY", &mut buffer)
            .map_err(|_| anyhow!("Encryption failed"))?;
        
        let mut result = Vec::with_capacity(12 + buffer.len() + 16);
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&buffer);
        result.extend_from_slice(&tag);
        Ok(result)
    }
    
    fn decrypt_server_key(encrypted: &[u8], master_key: &[u8; 32]) -> Result<[u8; 32]> {
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
        
        if encrypted.len() < 12 + 32 + 16 {
            return Err(anyhow!("Invalid encrypted key length"));
        }
        
        let cipher = ChaCha20Poly1305::new(Key::from_slice(master_key));
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let mut buffer = encrypted[12..encrypted.len()-16].to_vec();
        let tag = &encrypted[encrypted.len()-16..];
        
        cipher.decrypt_in_place_detached(nonce, b"LEGION_SERVER_KEY", &mut buffer, tag.into())
            .map_err(|_| anyhow!("Decryption failed"))?;
        
        if buffer.len() != 32 {
            return Err(anyhow!("Invalid decrypted key length"));
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&buffer);
        Ok(key)
    }
    
    fn get_system_fingerprint() -> Result<[u8; 32]> {
        if let Ok(fingerprint_hex) = std::env::var("LEGION_SYSTEM_ID") {
            if fingerprint_hex.len() == 64 {
                let mut fingerprint = [0u8; 32];
                hex::decode_to_slice(&fingerprint_hex, &mut fingerprint)
                    .map_err(|_| anyhow!("Invalid system ID format"))?;
                return Ok(fingerprint);
            }
        }
        
        let mut fingerprint = [0u8; 32];
        fill_random_bytes(&mut fingerprint)?;
        Ok(fingerprint)
    }
    
    fn get_hardware_id() -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"HARDWARE_ID_V1");
        
        #[cfg(target_os = "linux")]
        {
            if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
                hasher.update(machine_id.trim().as_bytes());
            }
        }
        
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(&(std::ptr::addr_of!(hasher) as usize).to_le_bytes());
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn get_deployment_salt() -> Result<[u8; 32]> {
        if let Ok(salt_hex) = std::env::var("LEGION_DEPLOYMENT_SALT") {
            if salt_hex.len() == 64 {
                let mut salt = [0u8; 32];
                hex::decode_to_slice(&salt_hex, &mut salt)
                    .map_err(|_| anyhow!("Invalid deployment salt format"))?;
                return Ok(salt);
            }
        }
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_DEFAULT_DEPLOYMENT_V1");
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        hasher.update(&get_timestamp().to_le_bytes());
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn get_installation_id() -> Result<[u8; 16]> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let id_path = "./secure_storage/installation.id";
            
            if std::path::Path::new(id_path).exists() {
                let id_data = std::fs::read(id_path)?;
                if id_data.len() == 16 {
                    let mut id = [0u8; 16];
                    id.copy_from_slice(&id_data);
                    return Ok(id);
                }
            }
            
            let mut id = [0u8; 16];
            fill_random_bytes(&mut id)?;
            
            if let Some(parent) = std::path::Path::new(id_path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(id_path, &id)?;
            Ok(id)
        }
        #[cfg(target_arch = "wasm32")]
        {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"WASM_INSTALLATION_ID_V1");
            hasher.update(&get_timestamp().to_le_bytes());
            
            let hash = hasher.finalize();
            let mut id = [0u8; 16];
            id.copy_from_slice(&hash.as_bytes()[..16]);
            Ok(id)
        }
    }
}