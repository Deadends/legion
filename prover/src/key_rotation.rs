// Key rotation system for credential management
use anyhow::Result;
use ff::PrimeField;
use pasta_curves::Fp;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[cfg(feature = "rocksdb-storage")]
use rocksdb::DB;
#[cfg(feature = "rocksdb-storage")]
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVersion {
    pub version: u32,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
    #[serde(serialize_with = "serialize_fp", deserialize_with = "deserialize_fp")]
    pub leaf_hash: Fp,
}

fn serialize_fp<S>(fp: &Fp, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(fp.to_repr()))
}

fn deserialize_fp<'de, D>(deserializer: D) -> Result<Fp, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom("Invalid Fp length"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let opt: Option<Fp> = Fp::from_repr(arr).into();
    opt.ok_or_else(|| serde::de::Error::custom("Invalid Fp"))
}

pub struct KeyRotationManager {
    // In-memory cache for fast lookups
    credentials: HashMap<String, Vec<CredentialVersion>>,
    #[cfg(feature = "rocksdb-storage")]
    db: Option<Arc<Mutex<DB>>>,
    #[cfg(not(feature = "rocksdb-storage"))]
    storage_path: Option<String>,
}

impl KeyRotationManager {
    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn new() -> Self {
        Self::new_with_storage(None)
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            db: None,
        }
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn new_with_rocksdb(db: Arc<Mutex<DB>>) -> Self {
        let mut manager = Self {
            credentials: HashMap::new(),
            db: Some(db),
        };

        if let Err(e) = manager.load_from_rocksdb() {
            eprintln!("Failed to load key rotation data from RocksDB: {}", e);
        }

        manager
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn new_with_storage(storage_path: Option<String>) -> Self {
        let mut manager = Self {
            credentials: HashMap::new(),
            storage_path: storage_path.clone(),
        };

        if let Some(ref path) = storage_path {
            if let Err(e) = manager.load_from_json(path) {
                eprintln!("Failed to load key rotation data from {}: {}", path, e);
            }
        }

        manager
    }

    /// Register new credential version
    pub fn add_credential(
        &mut self,
        username_hash: &Fp,
        password_hash: &Fp,
        version: u32,
        expiry_days: u64,
    ) -> Result<Fp> {
        let now = crate::get_timestamp();
        let expires_at = now + (expiry_days * 86400);

        // Compute versioned leaf
        let leaf_hash =
            self.compute_versioned_leaf(username_hash, password_hash, version, expires_at)?;

        let username_key = hex::encode(username_hash.to_repr());
        let cred = CredentialVersion {
            version,
            created_at: now,
            expires_at,
            revoked: false,
            leaf_hash,
        };

        self.credentials
            .entry(username_key)
            .or_insert_with(Vec::new)
            .push(cred);

        self.save_to_storage()?;
        Ok(leaf_hash)
    }

    /// Rotate password (creates new version)
    pub fn rotate_password(
        &mut self,
        username_hash: &Fp,
        new_password_hash: &Fp,
        expiry_days: u64,
    ) -> Result<Fp> {
        let username_key = hex::encode(username_hash.to_repr());

        // Get next version number
        let next_version = self
            .credentials
            .get(&username_key)
            .map(|versions| versions.len() as u32)
            .unwrap_or(0);

        // Revoke old versions
        if let Some(versions) = self.credentials.get_mut(&username_key) {
            for v in versions.iter_mut() {
                v.revoked = true;
            }
        }

        // Add new version
        let result =
            self.add_credential(username_hash, new_password_hash, next_version, expiry_days)?;
        self.save_to_storage()?;
        Ok(result)
    }

    /// Check if credential is valid
    pub fn is_valid(&self, username_hash: &Fp, leaf_hash: &Fp) -> bool {
        let username_key = hex::encode(username_hash.to_repr());
        let now = crate::get_timestamp();

        if let Some(versions) = self.credentials.get(&username_key) {
            for v in versions {
                if v.leaf_hash == *leaf_hash && !v.revoked && v.expires_at > now {
                    return true;
                }
            }
        }
        false
    }

    /// Revoke specific version
    pub fn revoke_version(&mut self, username_hash: &Fp, version: u32) -> Result<()> {
        let username_key = hex::encode(username_hash.to_repr());

        if let Some(versions) = self.credentials.get_mut(&username_key) {
            if let Some(v) = versions.iter_mut().find(|v| v.version == version) {
                v.revoked = true;
                self.save_to_storage()?;
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Version not found"))
    }

    /// Get active credential version
    pub fn get_active_version(&self, username_hash: &Fp) -> Option<&CredentialVersion> {
        let username_key = hex::encode(username_hash.to_repr());
        let now = crate::get_timestamp();

        self.credentials
            .get(&username_key)?
            .iter()
            .filter(|v| !v.revoked && v.expires_at > now)
            .max_by_key(|v| v.version)
    }

    fn compute_versioned_leaf(
        &self,
        username_hash: &Fp,
        password_hash: &Fp,
        version: u32,
        expires_at: u64,
    ) -> Result<Fp> {
        use halo2_gadgets::poseidon::primitives as poseidon;

        // Hash: H(username, password, version, expiry)
        let version_fp = Fp::from(version as u64);
        let expiry_fp = Fp::from(expires_at);

        let combined =
            poseidon::Hash::<Fp, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
                .hash([*username_hash, *password_hash]);
        let versioned =
            poseidon::Hash::<Fp, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
                .hash([combined, version_fp]);
        Ok(
            poseidon::Hash::<Fp, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
                .hash([versioned, expiry_fp]),
        )
    }

    #[cfg(feature = "rocksdb-storage")]
    fn save_to_storage(&self) -> Result<()> {
        if let Some(ref db_mutex) = self.db {
            let db = db_mutex.lock().unwrap();
            for (username_key, versions) in &self.credentials {
                let key = format!("keyrot:{}", username_key);
                let value = serde_json::to_vec(versions)?;
                db.put(key.as_bytes(), value)?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "rocksdb-storage")]
    fn load_from_rocksdb(&mut self) -> Result<()> {
        if let Some(ref db_mutex) = self.db {
            let db = db_mutex.lock().unwrap();
            let iter = db.prefix_iterator(b"keyrot:");
            for item in iter {
                let (key, value) = item?;
                let key_str = String::from_utf8_lossy(&key);
                if let Some(username_key) = key_str.strip_prefix("keyrot:") {
                    let versions: Vec<CredentialVersion> = serde_json::from_slice(&value)?;
                    self.credentials.insert(username_key.to_string(), versions);
                }
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    fn save_to_storage(&self) -> Result<()> {
        if let Some(ref path) = self.storage_path {
            let json = serde_json::to_string_pretty(&self.credentials)?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    fn load_from_json(&mut self, path: &str) -> Result<()> {
        if !std::path::Path::new(path).exists() {
            return Ok(());
        }

        let json = std::fs::read_to_string(path)?;
        self.credentials = serde_json::from_str(&json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_rotation() {
        let mut manager = KeyRotationManager::new();
        let username = Fp::from(12345u64);
        let password1 = Fp::from(67890u64);
        let password2 = Fp::from(11111u64);

        // Register initial credential
        let leaf1 = manager
            .add_credential(&username, &password1, 0, 90)
            .unwrap();
        assert!(manager.is_valid(&username, &leaf1));

        // Rotate password
        let leaf2 = manager.rotate_password(&username, &password2, 90).unwrap();

        // Old credential should be revoked
        assert!(!manager.is_valid(&username, &leaf1));

        // New credential should be valid
        assert!(manager.is_valid(&username, &leaf2));
    }
}
