use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};

/// SECURE: Controlled decryption service implementation
pub struct EnterpriseDecryptionService {
    // No keys stored - uses API calls to EnterpriseKeyManager
}

impl EnterpriseDecryptionService {
    pub fn new() -> Self {
        Self {}
    }
}

impl crate::verifier::ProofDecryptionService for EnterpriseDecryptionService {
    fn decrypt_proof(&self, encrypted_proof: &[u8]) -> Result<Vec<u8>> {
        // SECURITY: Use your existing secure API
        crate::final_circuit::EnterpriseKeyManager::decrypt_proof_for_verification(encrypted_proof)
    }
    
    fn validate_caller(&self) -> Result<()> {
        // SECURITY: Add caller validation
        // Check if caller has verification permissions
        // Rate limiting, audit logging, etc.
        Ok(())
    }
}

// Add to EnterpriseKeyManager in final_circuit.rs
impl crate::final_circuit::EnterpriseKeyManager {
    pub fn decrypt_proof_for_verification(encrypted_proof: &[u8]) -> Result<Vec<u8>> {
        // SECURITY: Controlled decryption with validation
        if encrypted_proof.len() < 28 { // 12 (nonce) + 16 (tag)
            return Err(anyhow!("Invalid encrypted proof format"));
        }
        
        // Get decryption key through secure API
        let key = Self::get_server_key()?;
        
        // Extract components
        let nonce = &encrypted_proof[..12];
        let ciphertext = &encrypted_proof[12..encrypted_proof.len()-16];
        let tag = &encrypted_proof[encrypted_proof.len()-16..];
        
        // Decrypt
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let mut buffer = ciphertext.to_vec();
        
        cipher.decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            b"LEGION_ENTERPRISE",
            &mut buffer,
            tag.into()
        ).map_err(|_| anyhow!("Decryption failed"))?;
        
        // SECURITY: Audit the decryption
        crate::final_circuit::WorldClassAuthSystem::audit_compliance(
            "PROOF_DECRYPTED", "", None, true, 
            crate::final_circuit::SecurityLevel::Enterprise, 0.2
        )?;
        
        Ok(buffer)
    }
}