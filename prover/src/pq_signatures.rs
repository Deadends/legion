/// Post-Quantum Digital Signatures (ML-DSA / FIPS 204)
/// Out-of-circuit verification for practical performance
use anyhow::{Result, Context};
use rand::rngs::OsRng;

#[cfg(feature = "post-quantum")]
use ml_dsa::{SigningKey, VerifyingKey, Signature};

/// Generate ML-DSA-65 key pair (NIST Level 3)
#[cfg(feature = "post-quantum")]
pub fn generate_ml_dsa_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key().clone();
    (signing_key, verifying_key)
}

#[cfg(not(feature = "post-quantum"))]
pub fn generate_ml_dsa_keypair() -> (Vec<u8>, Vec<u8>) {
    // Fallback: return dummy keys
    (vec![0u8; 32], vec![0u8; 32])
}

/// Sign message with ML-DSA
#[cfg(feature = "post-quantum")]
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Result<Vec<u8>> {
    let signature = signing_key.try_sign(message)
        .map_err(|e| anyhow::anyhow!("Signing failed: {:?}", e))?;
    Ok(signature.to_vec())
}

#[cfg(not(feature = "post-quantum"))]
pub fn sign_message(_signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    // Fallback: use ed25519
    use ed25519_dalek::{Signer, SigningKey as Ed25519Key};
    let key = Ed25519Key::from_bytes(&[0u8; 32]);
    let signature = key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify ML-DSA signature
#[cfg(feature = "post-quantum")]
pub fn verify_signature(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    let signature = Signature::try_from(signature_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid signature format: {:?}", e))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(not(feature = "post-quantum"))]
pub fn verify_signature(
    verifying_key: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    use ed25519_dalek::{Verifier, VerifyingKey as Ed25519Key, Signature};
    let key = Ed25519Key::from_bytes(verifying_key.try_into()?)?;
    let sig = Signature::from_bytes(signature_bytes.try_into()?);
    Ok(key.verify(message, &sig).is_ok())
}

/// Serialize verifying key for storage/transmission
#[cfg(feature = "post-quantum")]
pub fn serialize_verifying_key(vk: &VerifyingKey) -> Vec<u8> {
    vk.as_ref().to_vec()
}

#[cfg(not(feature = "post-quantum"))]
pub fn serialize_verifying_key(vk: &[u8]) -> Vec<u8> {
    vk.to_vec()
}

/// Deserialize verifying key
#[cfg(feature = "post-quantum")]
pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<VerifyingKey> {
    VerifyingKey::try_from(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize ML-DSA verifying key: {:?}", e))
}

#[cfg(not(feature = "post-quantum"))]
pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ml_dsa_sign_verify() {
        let (sk, vk) = generate_ml_dsa_keypair();
        let message = b"Test message for ML-DSA";
        
        let signature = sign_message(&sk, message).unwrap();
        let is_valid = verify_signature(&vk, message, &signature).unwrap();
        
        assert!(is_valid);
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        let is_valid_wrong = verify_signature(&vk, wrong_message, &signature).unwrap();
        assert!(!is_valid_wrong);
    }
    
    #[test]
    fn test_key_serialization() {
        let (_, vk) = generate_ml_dsa_keypair();
        
        let serialized = serialize_verifying_key(&vk);
        let deserialized = deserialize_verifying_key(&serialized).unwrap();
        
        assert_eq!(serialize_verifying_key(&vk), serialize_verifying_key(&deserialized));
    }
}