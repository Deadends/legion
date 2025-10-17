/// Post-Quantum Authentication Wrapper
/// Uses ML-DSA (Dilithium) OUTSIDE ZK circuits for quantum resistance
/// This is the PRACTICAL approach - native crypto, not circuit constraints

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumResistantAuth {
    pub zk_proof: Vec<u8>,           // Your lightweight ZK proof (~2K constraints)
    pub pq_signature: Vec<u8>,       // ML-DSA signature (quantum-resistant)
    pub public_key: Vec<u8>,         // ML-DSA public key
}

/// Sign a ZK proof with post-quantum signature
pub fn sign_zk_proof(zk_proof: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "post-quantum")]
    {
        use crate::pq_signatures;
        pq_signatures::sign_message(secret_key, zk_proof)
    }
    
    #[cfg(not(feature = "post-quantum"))]
    {
        // Fallback: Use ed25519 (not quantum-resistant but works)
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(secret_key.try_into()?);
        let signature = key.sign(zk_proof);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Verify post-quantum signature on ZK proof
pub fn verify_pq_signature(zk_proof: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    #[cfg(feature = "post-quantum")]
    {
        use crate::pq_signatures;
        pq_signatures::verify_signature(public_key, zk_proof, signature)
    }
    
    #[cfg(not(feature = "post-quantum"))]
    {
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        let key = VerifyingKey::from_bytes(public_key.try_into()?)?;
        let sig = Signature::from_bytes(signature.try_into()?);
        Ok(key.verify(zk_proof, &sig).is_ok())
    }
}

/// Generate ML-DSA key pair
pub fn generate_pq_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    #[cfg(feature = "post-quantum")]
    {
        use crate::pq_signatures;
        let (sk, vk) = pq_signatures::generate_ml_dsa_keypair();
        Ok((pq_signatures::serialize_verifying_key(&sk), pq_signatures::serialize_verifying_key(&vk)))
    }
    
    #[cfg(not(feature = "post-quantum"))]
    {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Ok((signing_key.to_bytes().to_vec(), verifying_key.to_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_signature() -> Result<()> {
        let (secret_key, public_key) = generate_pq_keypair()?;
        let zk_proof = b"mock_zk_proof_data";
        
        let signature = sign_zk_proof(zk_proof, &secret_key)?;
        let valid = verify_pq_signature(zk_proof, &signature, &public_key)?;
        
        assert!(valid);
        Ok(())
    }
}
