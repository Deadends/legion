use hkdf::Hkdf;
use sha3::Sha3_256;
use blake3::Hasher;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use rand::{RngCore, rngs::OsRng};
use argon2::{Argon2, Config};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

// Quantum-resistant key derivation constants
const QUANTUM_SECURITY_LEVEL: usize = 256; // bits
const KEY_DERIVATION_ROUNDS: u32 = 100000;
const SALT_SIZE: usize = 64; // Increased for quantum resistance
const MASTER_KEY_SIZE: usize = 64; // 512-bit master keys
const SESSION_KEY_SIZE: usize = 32; // 256-bit session keys
const FORWARD_SECRECY_INTERVAL: u64 = 3600; // 1 hour

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyDerivationAlgorithm {
    HKDF_SHA3_256,
    HKDF_BLAKE3,
    Argon2id,
    PBKDF2_SHA3,
    QuantumResistant, // Future-proof for post-quantum algorithms
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct QuantumResistantKeySchedule {
    master_secret: Zeroizing<[u8; MASTER_KEY_SIZE]>,
    transcript_hash: [u8; 32],
    derivation_algorithm: KeyDerivationAlgorithm,
    security_level: u8,
    forward_secrecy_counter: u64,
    key_rotation_history: Vec<KeyRotationEvent>,
    quantum_entropy_pool: Zeroizing<[u8; 128]>, // Additional entropy for quantum resistance
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct KeyRotationEvent {
    pub timestamp: SystemTime,
    pub old_key_hash: [u8; 32],
    pub new_key_hash: [u8; 32],
    pub rotation_reason: KeyRotationReason,
    pub security_level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyRotationReason {
    Scheduled,
    SecurityBreach,
    ComplianceRequirement,
    QuantumThreat,
    UserRequest,
    SystemMaintenance,
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct EnhancedSessionKeys {
    pub client_to_server: Zeroizing<[u8; SESSION_KEY_SIZE]>,
    pub server_to_client: Zeroizing<[u8; SESSION_KEY_SIZE]>,
    pub epoch: u32,
    pub derived_at: SystemTime,
    pub expires_at: SystemTime,
    pub key_id: [u8; 16],
    pub algorithm: KeyDerivationAlgorithm,
    pub forward_secrecy_key: Zeroizing<[u8; SESSION_KEY_SIZE]>,
}

// Legacy compatibility
pub type KeySchedule = QuantumResistantKeySchedule;
pub type SessionKeys = EnhancedSessionKeys;

impl KeySchedule {
    pub fn new(shared_secret: &[u8], salt: &[u8], transcript_hash: [u8; 32]) -> Result<Self> {
        let hk = Hkdf::<Sha3_256>::new(Some(salt), shared_secret);
        let mut master_secret = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        
        let mut info = Vec::new();
        info.extend_from_slice(b"LEGION_MASTER_SECRET_V3");
        info.extend_from_slice(&transcript_hash);
        hk.expand(&info, &mut *master_secret)
            .context("Master secret derivation failed")?;
        
        let mut quantum_entropy_pool = Zeroizing::new([0u8; 128]);
        OsRng.fill_bytes(&mut *quantum_entropy_pool);
        
        Ok(Self {
            master_secret,
            transcript_hash,
            derivation_algorithm: KeyDerivationAlgorithm::HKDF_SHA3_256,
            security_level: 128,
            forward_secrecy_counter: 0,
            key_rotation_history: Vec::new(),
            quantum_entropy_pool,
        })
    }

    pub fn derive_session_keys(&self, session_id: &[u8; 32], epoch: u32) -> Result<SessionKeys> {
        let hk = Hkdf::<Sha3_256>::new(None, &*self.master_secret);
        
        // Derive epoch salt
        let mut epoch_info = Vec::new();
        epoch_info.extend_from_slice(b"LEGION_EPOCH_SALT");
        epoch_info.extend_from_slice(&epoch.to_le_bytes());
        epoch_info.extend_from_slice(&self.transcript_hash);
        epoch_info.extend_from_slice(session_id);
        
        let mut epoch_salt = Zeroizing::new([0u8; 32]);
        hk.expand(&epoch_info, &mut *epoch_salt)
            .context("Epoch salt derivation failed")?;
        
        // Derive directional keys
        let hk_epoch = Hkdf::<Sha3_256>::new(Some(&*epoch_salt), &*self.master_secret);
        
        let mut client_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut c2s_info = Vec::new();
        c2s_info.extend_from_slice(b"CLIENT_TO_SERVER");
        c2s_info.extend_from_slice(&self.transcript_hash);
        hk_epoch.expand(&c2s_info, &mut *client_key)
            .context("Client key derivation failed")?;
        
        let mut server_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut s2c_info = Vec::new();
        s2c_info.extend_from_slice(b"SERVER_TO_CLIENT");
        s2c_info.extend_from_slice(&self.transcript_hash);
        hk_epoch.expand(&s2c_info, &mut *server_key)
            .context("Server key derivation failed")?;
        
        // Derive forward secrecy key
        let mut fs_key = Zeroizing::new([0u8; SESSION_KEY_SIZE]);
        let mut fs_info = Vec::new();
        fs_info.extend_from_slice(b"FORWARD_SECRECY");
        fs_info.extend_from_slice(&self.transcript_hash);
        fs_info.extend_from_slice(&epoch.to_le_bytes());
        hk_epoch.expand(&fs_info, &mut *fs_key)
            .context("Forward secrecy key derivation failed")?;
        
        // Generate key ID
        let mut key_id = [0u8; 16];
        let mut id_hasher = Hasher::new();
        id_hasher.update(&*client_key);
        id_hasher.update(&*server_key);
        id_hasher.update(&epoch.to_le_bytes());
        let id_hash = id_hasher.finalize();
        key_id.copy_from_slice(&id_hash.as_bytes()[..16]);
        
        let now = SystemTime::now();
        let expires_at = now + std::time::Duration::from_secs(FORWARD_SECRECY_INTERVAL);
        
        debug!("Derived session keys for epoch {} with key_id {}", epoch, hex::encode(&key_id));
        
        Ok(SessionKeys {
            client_to_server: client_key,
            server_to_client: server_key,
            epoch,
            derived_at: now,
            expires_at,
            key_id,
            algorithm: self.derivation_algorithm.clone(),
            forward_secrecy_key: fs_key,
        })
    }

    pub fn compute_transcript_hash(
        client_hello: &[u8],
        server_hello: &[u8], 
        proof_message: &[u8],
        timestamp: u64
    ) -> [u8; 32] {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_HANDSHAKE_V3");
        hasher.update(client_hello);
        hasher.update(server_hello);
        hasher.update(proof_message);
        hasher.update(&timestamp.to_le_bytes());
        
        *hasher.finalize().as_bytes()
    }
    
    pub fn rotate_keys(&mut self, reason: KeyRotationReason) -> Result<()> {
        let old_key_hash = blake3::hash(&*self.master_secret);
        
        // Generate new master secret with additional entropy
        let mut new_master = Zeroizing::new([0u8; MASTER_KEY_SIZE]);
        OsRng.fill_bytes(&mut *new_master);
        
        // Mix with existing entropy pool for quantum resistance
        for i in 0..MASTER_KEY_SIZE.min(128) {
            new_master[i] ^= self.quantum_entropy_pool[i];
        }
        
        let new_key_hash = blake3::hash(&*new_master);
        
        // Record rotation event
        let rotation_event = KeyRotationEvent {
            timestamp: SystemTime::now(),
            old_key_hash: *old_key_hash.as_bytes(),
            new_key_hash: *new_key_hash.as_bytes(),
            rotation_reason: reason,
            security_level: self.security_level,
        };
        
        self.key_rotation_history.push(rotation_event);
        
        // Update master secret
        self.master_secret = new_master;
        self.forward_secrecy_counter += 1;
        
        // Refresh quantum entropy pool
        OsRng.fill_bytes(&mut *self.quantum_entropy_pool);
        
        info!("Key rotation completed, reason: {:?}", reason);
        Ok(())
    }
    
    pub fn get_rotation_history(&self) -> &[KeyRotationEvent] {
        &self.key_rotation_history
    }
}

// Simplified SessionKeys for backward compatibility
#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SimpleSessionKeys {
    pub client_to_server: Zeroizing<[u8; 32]>,
    pub server_to_client: Zeroizing<[u8; 32]>,
    pub epoch: u32,
}

impl From<EnhancedSessionKeys> for SimpleSessionKeys {
    fn from(enhanced: EnhancedSessionKeys) -> Self {
        Self {
            client_to_server: enhanced.client_to_server,
            server_to_client: enhanced.server_to_client,
            epoch: enhanced.epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt_32_bytes_long_exactly!";
        let transcript = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        
        let ks1 = KeySchedule::new(shared_secret, salt, transcript)?;
        let ks2 = KeySchedule::new(shared_secret, salt, transcript)?;
        
        let keys1 = ks1.derive_session_keys(&session_id, 0)?;
        let keys2 = ks2.derive_session_keys(&session_id, 0)?;
        
        // Same inputs = same keys
        assert_eq!(*keys1.client_to_server, *keys2.client_to_server);
        assert_eq!(*keys1.server_to_client, *keys2.server_to_client);
        
        Ok(())
    }

    #[test]
    fn test_transcript_binding() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt_32_bytes_long_exactly!";
        let transcript1 = [0x42u8; 32];
        let transcript2 = [0x43u8; 32];
        let session_id = [0x01u8; 32];
        
        let ks1 = KeySchedule::new(shared_secret, salt, transcript1)?;
        let ks2 = KeySchedule::new(shared_secret, salt, transcript2)?;
        
        let keys1 = ks1.derive_session_keys(&session_id, 0)?;
        let keys2 = ks2.derive_session_keys(&session_id, 0)?;
        
        // Different transcript = different keys
        assert_ne!(*keys1.client_to_server, *keys2.client_to_server);
        assert_ne!(*keys1.server_to_client, *keys2.server_to_client);
        
        Ok(())
    }

    #[test]
    fn test_epoch_separation() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt_32_bytes_long_exactly!";
        let transcript = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        
        let ks = KeySchedule::new(shared_secret, salt, transcript)?;
        
        let keys_epoch0 = ks.derive_session_keys(&session_id, 0)?;
        let keys_epoch1 = ks.derive_session_keys(&session_id, 1)?;
        
        // Different epoch = different keys
        assert_ne!(*keys_epoch0.client_to_server, *keys_epoch1.client_to_server);
        assert_ne!(*keys_epoch0.server_to_client, *keys_epoch1.server_to_client);
        
        Ok(())
    }
    
    #[test]
    fn test_key_rotation() -> Result<()> {
        let shared_secret = b"test_shared_secret_32_bytes_long";
        let salt = b"test_salt_32_bytes_long_exactly!";
        let transcript = [0x42u8; 32];
        let session_id = [0x01u8; 32];
        
        let mut ks = KeySchedule::new(shared_secret, salt, transcript)?;
        
        let keys_before = ks.derive_session_keys(&session_id, 0)?;
        
        ks.rotate_keys(KeyRotationReason::Scheduled)?;
        
        let keys_after = ks.derive_session_keys(&session_id, 0)?;
        
        // Keys should be different after rotation
        assert_ne!(*keys_before.client_to_server, *keys_after.client_to_server);
        assert_ne!(*keys_before.server_to_client, *keys_after.server_to_client);
        
        // Should have rotation history
        assert_eq!(ks.get_rotation_history().len(), 1);
        assert!(matches!(ks.get_rotation_history()[0].rotation_reason, KeyRotationReason::Scheduled));
        
        Ok(())
    }
}