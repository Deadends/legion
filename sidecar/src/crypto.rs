use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha3::Sha3_256;
use rand::RngCore;
use std::collections::HashMap;
use ed25519_dalek::{Signer, Verifier, Signature, SigningKey, VerifyingKey};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    KeyDerivationFailed,
    SignatureFailed,
    VerificationFailed,
    RandomGenerationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
            CryptoError::SignatureFailed => write!(f, "Signature failed"),
            CryptoError::VerificationFailed => write!(f, "Verification failed"),
            CryptoError::RandomGenerationFailed => write!(f, "Random generation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

pub struct LegionCrypto {
    cipher_cache: HashMap<[u8; 32], ChaCha20Poly1305>,
}

impl LegionCrypto {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cipher_cache: HashMap::new(),
        })
    }

    pub fn generate_random_bytes(&self, len: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; len];
        OsRng.fill_bytes(&mut bytes);
        debug!("Generated {} random bytes", len);
        Ok(bytes)
    }

    pub fn derive_key_with_transcript(&self, input: &[u8], salt: &[u8], transcript: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let hk = Hkdf::<Sha3_256>::new(Some(salt), input);
        let mut context = Vec::with_capacity(transcript.len() + info.len() + 32);
        context.extend_from_slice(b"LEGION_V3_HKDF_EXPAND");
        context.extend_from_slice(transcript);
        context.extend_from_slice(info);
        
        let mut output = Zeroizing::new(vec![0u8; output_len]);
        hk.expand(&context, &mut *output)
            .context("Key derivation failed")?;
        
        debug!("Derived key of length {} bytes", output_len);
        Ok(output.to_vec())
    }

    pub fn encrypt_with_aad(&mut self, data: &[u8], key: &[u8; 32], session_id: &[u8; 32], epoch: u64, direction: &str, transcript_hash: &[u8; 32]) -> Result<EncryptionResult> {
        let cipher = self.cipher_cache.entry(*key).or_insert_with(|| {
            ChaCha20Poly1305::new(key.into())
        });

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Construct AAD: session_id || epoch || direction || transcript_hash
        let mut aad = Vec::with_capacity(32 + 8 + direction.len() + 32);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad.extend_from_slice(transcript_hash);

        let encrypted = cipher
            .encrypt(nonce, chacha20poly1305::aead::Payload { msg: data, aad: &aad })
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);

        debug!("Encrypted {} bytes with AAD", data.len());
        Ok(EncryptionResult {
            ciphertext: result,
            nonce: nonce_bytes,
        })
    }

    pub fn encrypt_with_deterministic_nonce(
        &mut self,
        data: &[u8],
        key: &[u8; 32],
        nonce: &[u8; 12],
        session_id: &[u8; 32],
        epoch: u64,
        direction: &str,
        transcript_hash: &[u8; 32],
        sequence_number: u64,
    ) -> Result<Vec<u8>> {
        let cipher = self.cipher_cache.entry(*key).or_insert_with(|| {
            ChaCha20Poly1305::new(key.into())
        });

        let nonce_obj = Nonce::from_slice(nonce);

        // Construct AAD with sequence number for replay protection
        let mut aad = Vec::with_capacity(32 + 8 + direction.len() + 32 + 8);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad.extend_from_slice(transcript_hash);
        aad.extend_from_slice(&sequence_number.to_le_bytes());

        let encrypted = cipher
            .encrypt(nonce_obj, chacha20poly1305::aead::Payload { msg: data, aad: &aad })
            .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(nonce);
        result.extend_from_slice(&encrypted);

        debug!("Encrypted {} bytes with deterministic nonce and sequence {}", data.len(), sequence_number);
        Ok(result)
    }

    pub fn decrypt_with_sequence_validation(
        &mut self,
        encrypted_data: &[u8],
        key: &[u8; 32],
        session_id: &[u8; 32],
        epoch: u64,
        direction: &str,
        transcript_hash: &[u8; 32],
        expected_sequence: u64,
    ) -> Result<Vec<u8>> {
        if encrypted_data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }

        let cipher = self.cipher_cache.entry(*key).or_insert_with(|| {
            ChaCha20Poly1305::new(key.into())
        });

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        // Reconstruct AAD with expected sequence number
        let mut aad = Vec::with_capacity(32 + 8 + direction.len() + 32 + 8);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad.extend_from_slice(transcript_hash);
        aad.extend_from_slice(&expected_sequence.to_le_bytes());

        let decrypted = cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow::anyhow!("Decryption failed or sequence mismatch"))?;

        debug!("Decrypted {} bytes with sequence validation {}", decrypted.len(), expected_sequence);
        Ok(decrypted)
    }

    pub fn decrypt_with_aad(&mut self, encrypted_data: &[u8], key: &[u8; 32], session_id: &[u8; 32], epoch: u64, direction: &str, transcript_hash: &[u8; 32]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 28 {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }

        let cipher = self.cipher_cache.entry(*key).or_insert_with(|| {
            ChaCha20Poly1305::new(key.into())
        });

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];

        // Reconstruct AAD
        let mut aad = Vec::with_capacity(32 + 8 + direction.len() + 32);
        aad.extend_from_slice(session_id);
        aad.extend_from_slice(&epoch.to_le_bytes());
        aad.extend_from_slice(direction.as_bytes());
        aad.extend_from_slice(transcript_hash);

        let decrypted = cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

        debug!("Decrypted {} bytes with AAD", decrypted.len());
        Ok(decrypted)
    }

    pub fn sign_ed25519(&self, data: &[u8], signing_key: &SigningKey) -> Result<Vec<u8>> {
        let signature = signing_key.sign(data);
        debug!("Generated Ed25519 signature for {} bytes", data.len());
        Ok(signature.to_bytes().to_vec())
    }

    pub fn verify_ed25519(&self, data: &[u8], signature: &[u8], public_key: &VerifyingKey) -> Result<bool> {
        if signature.len() != 64 {
            return Ok(false);
        }
        
        let sig_bytes: [u8; 64] = signature.try_into()
            .context("Invalid signature format")?;
        let sig = match Signature::try_from(&sig_bytes[..]) {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        
        match public_key.verify(data, &sig) {
            Ok(()) => {
                debug!("Ed25519 signature verification succeeded");
                Ok(true)
            },
            Err(_) => {
                debug!("Ed25519 signature verification failed");
                Ok(false)
            }
        }
    }

    pub fn generate_ed25519_keypair(&self) -> Result<(SigningKey, VerifyingKey)> {
        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *secret_bytes);
        let signing_key = SigningKey::from_bytes(&*secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        info!("Generated new Ed25519 keypair");
        Ok((signing_key, verifying_key))
    }
    
    pub fn secure_compare(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        
        result == 0
    }
    
    pub fn clear_cache(&mut self) {
        self.cipher_cache.clear();
        info!("Cleared crypto cipher cache");
    }
    
    pub fn get_cache_size(&self) -> usize {
        self.cipher_cache.len()
    }
}

impl Drop for LegionCrypto {
    fn drop(&mut self) {
        self.clear_cache();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encryption_roundtrip() -> Result<()> {
        let mut crypto = LegionCrypto::new()?;
        let key = [42u8; 32];
        let session_id = [1u8; 32];
        let transcript_hash = [2u8; 32];
        let data = b"test message";
        
        let encrypted = crypto.encrypt_with_aad(
            data, &key, &session_id, 1, "test", &transcript_hash
        )?;
        
        let decrypted = crypto.decrypt_with_aad(
            &encrypted.ciphertext, &key, &session_id, 1, "test", &transcript_hash
        )?;
        
        assert_eq!(data, &decrypted[..]);
        Ok(())
    }
    
    #[test]
    fn test_signature_roundtrip() -> Result<()> {
        let crypto = LegionCrypto::new()?;
        let (signing_key, verifying_key) = crypto.generate_ed25519_keypair()?;
        let data = b"test message for signing";
        
        let signature = crypto.sign_ed25519(data, &signing_key)?;
        let is_valid = crypto.verify_ed25519(data, &signature, &verifying_key)?;
        
        assert!(is_valid);
        Ok(())
    }
    
    #[test]
    fn test_secure_compare() -> Result<()> {
        let crypto = LegionCrypto::new()?;
        
        assert!(crypto.secure_compare(b"hello", b"hello"));
        assert!(!crypto.secure_compare(b"hello", b"world"));
        assert!(!crypto.secure_compare(b"hello", b"hello world"));
        
        Ok(())
    }
}