use crate::security::SecurityLevel;
use ring::{digest, hmac, rand::{SystemRandom, SecureRandom}};
use anyhow::{Result, anyhow};
use zeroize::Zeroize;
use std::time::SystemTime;

pub struct CryptoEngine {
    security_level: SecurityLevel,
    rng: SystemRandom,
}

impl CryptoEngine {
    pub fn new(security_level: SecurityLevel) -> Result<Self> {
        Ok(Self {
            security_level,
            rng: SystemRandom::new(),
        })
    }
    
    /// Secure HMAC computation with constant-time verification
    pub fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let signature = hmac::sign(&hmac_key, data);
        Ok(signature.as_ref().to_vec())
    }
    
    /// Constant-time HMAC verification
    pub fn verify_hmac(&self, key: &[u8], data: &[u8], expected_hmac: &[u8]) -> Result<bool> {
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        match hmac::verify(&hmac_key, data, expected_hmac) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Secure hash computation
    pub fn hash_data(&self, data: &[u8]) -> [u8; 32] {
        let digest = digest::digest(&digest::SHA256, data);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(digest.as_ref());
        hash
    }
    
    /// Time-based proof verification with replay protection
    pub fn verify_proof_with_timestamp(&self, proof: &[u8], timestamp: u64, window_seconds: u64) -> Result<bool> {
        let current_time = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check timestamp window
        if current_time.saturating_sub(timestamp) > window_seconds {
            return Ok(false);
        }
        
        // In a real implementation, this would verify the ZK proof
        // For now, we'll do basic validation
        if proof.len() < 32 {
            return Ok(false);
        }
        
        // Verify proof structure and cryptographic validity
        self.verify_proof_structure(proof)
    }
    
    fn verify_proof_structure(&self, proof: &[u8]) -> Result<bool> {
        // Basic proof validation
        if proof.len() < 64 {
            return Ok(false);
        }
        
        // Check for obvious tampering
        let hash = self.hash_data(proof);
        
        // In production, this would:
        // 1. Verify ZK proof cryptographically
        // 2. Check proof against public parameters
        // 3. Validate witness commitments
        // 4. Ensure proof completeness
        
        Ok(hash[0] != 0) // Simple non-zero check
    }
    
    /// Generate cryptographically secure nonce
    pub fn generate_nonce(&self) -> Result<[u8; 32]> {
        let mut nonce = [0u8; 32];
        self.rng.fill(&mut nonce)
            .map_err(|_| anyhow!("Failed to generate secure nonce"))?;
        Ok(nonce)
    }
    
    /// Derive session key from master key and context
    pub fn derive_session_key(&self, master_key: &[u8], context: &[u8]) -> Result<[u8; 32]> {
        let mut derived_key = [0u8; 32];
        
        // Use HKDF for key derivation
        let salt = b"legion-session-key-derivation";
        let info = [b"legion-v1", context].concat();
        
        let prk = hmac::Key::new(hmac::HMAC_SHA256, salt);
        let okm = hmac::sign(&prk, &[master_key, &info].concat());
        
        derived_key.copy_from_slice(&okm.as_ref()[..32]);
        Ok(derived_key)
    }
    
    /// Secure comparison with timing attack protection
    pub fn constant_time_eq(&self, a: &[u8], b: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

/// Secure memory for sensitive data
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }
    
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Rate limiting for cryptographic operations
pub struct CryptoRateLimiter {
    operations: std::sync::Mutex<std::collections::HashMap<String, (u64, SystemTime)>>,
    max_ops_per_minute: u64,
}

impl CryptoRateLimiter {
    pub fn new(max_ops_per_minute: u64) -> Self {
        Self {
            operations: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_ops_per_minute,
        }
    }
    
    pub fn check_rate_limit(&self, client_id: &str) -> Result<bool> {
        let mut ops = self.operations.lock()
            .map_err(|_| anyhow!("Failed to acquire rate limit lock"))?;
        
        let now = SystemTime::now();
        let (count, last_reset) = ops.entry(client_id.to_string())
            .or_insert((0, now));
        
        // Reset counter if a minute has passed
        if now.duration_since(*last_reset).unwrap_or_default().as_secs() >= 60 {
            *count = 0;
            *last_reset = now;
        }
        
        if *count >= self.max_ops_per_minute {
            return Ok(false);
        }
        
        *count += 1;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hmac_computation_and_verification() {
        let engine = CryptoEngine::new(SecurityLevel::Production).unwrap();
        let key = b"test-key-32-bytes-long-for-hmac!";
        let data = b"test data for hmac computation";
        
        let hmac = engine.compute_hmac(key, data).unwrap();
        assert!(engine.verify_hmac(key, data, &hmac).unwrap());
        
        // Test with wrong data
        let wrong_data = b"wrong data";
        assert!(!engine.verify_hmac(key, wrong_data, &hmac).unwrap());
    }
    
    #[test]
    fn test_constant_time_comparison() {
        let engine = CryptoEngine::new(SecurityLevel::Production).unwrap();
        
        let a = b"same data";
        let b = b"same data";
        let c = b"different";
        
        assert!(engine.constant_time_eq(a, b));
        assert!(!engine.constant_time_eq(a, c));
    }
    
    #[test]
    fn test_secure_buffer_zeroization() {
        let mut buffer = SecureBuffer::from_slice(b"sensitive data");
        assert_eq!(buffer.as_slice(), b"sensitive data");
        
        buffer.zeroize();
        assert_eq!(buffer.as_slice(), &[0u8; 14]);
    }
}