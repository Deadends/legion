/// Post-Quantum Forward Secrecy Implementation
/// Hybrid ML-KEM-768 + X25519 following research recommendations
use anyhow::{Context, Result};
use rand::rngs::OsRng;

#[cfg(feature = "post-quantum")]
use ml_kem::{Decapsulate, Encapsulate, KemCore, MlKem768};
#[cfg(feature = "post-quantum")]
use sha3::{Digest, Sha3_256};
#[cfg(feature = "post-quantum")]
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

/// Hybrid ephemeral key state (ML-KEM + X25519)
#[cfg(feature = "post-quantum")]
pub struct HybridKeyState {
    // Post-quantum component
    ml_kem_dk: ml_kem::DecapsulationKey<MlKem768>,
    ml_kem_ek: ml_kem::EncapsulationKey<MlKem768>,

    // Classical component (for hybrid security)
    x25519_secret: EphemeralSecret,
    x25519_public: X25519PublicKey,
}

#[cfg(not(feature = "post-quantum"))]
pub struct HybridKeyState {
    dummy: Vec<u8>,
}

/// Generate hybrid ephemeral keys for one session
#[cfg(feature = "post-quantum")]
pub fn generate_hybrid_keys() -> HybridKeyState {
    // Generate ML-KEM-768 key pair (FIPS 203)
    let (ml_kem_dk, ml_kem_ek) = MlKem768::generate(&mut OsRng);

    // Generate X25519 key pair (classical fallback)
    let x25519_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    HybridKeyState {
        ml_kem_dk,
        ml_kem_ek,
        x25519_secret,
        x25519_public,
    }
}

#[cfg(not(feature = "post-quantum"))]
pub fn generate_hybrid_keys() -> HybridKeyState {
    HybridKeyState {
        dummy: vec![0u8; 32],
    }
}

/// Serialize public keys for transmission
#[cfg(feature = "post-quantum")]
pub fn create_hybrid_payload(state: &HybridKeyState) -> Vec<u8> {
    let mut payload = Vec::new();

    // ML-KEM public key (1184 bytes)
    let ml_kem_bytes = state.ml_kem_ek.as_ref();
    payload.extend_from_slice(&(ml_kem_bytes.len() as u16).to_be_bytes());
    payload.extend_from_slice(ml_kem_bytes);

    // X25519 public key (32 bytes)
    payload.extend_from_slice(state.x25519_public.as_bytes());

    payload
}

/// Process peer's public keys and generate shared secrets
#[cfg(feature = "post-quantum")]
pub fn process_hybrid_payload(peer_payload: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;

    // Parse ML-KEM public key
    if peer_payload.len() < 2 {
        return Err(anyhow::anyhow!("Invalid payload size"));
    }

    let ml_kem_len = u16::from_be_bytes([peer_payload[0], peer_payload[1]]) as usize;
    if peer_payload.len() < 2 + ml_kem_len + 32 {
        return Err(anyhow::anyhow!("Incomplete payload"));
    }

    let ml_kem_bytes = &peer_payload[2..2 + ml_kem_len];
    let x25519_bytes = &peer_payload[2 + ml_kem_len..2 + ml_kem_len + 32];

    // Deserialize peer's ML-KEM public key
    let peer_ml_kem_ek = ml_kem::EncapsulationKey::<MlKem768>::try_from(ml_kem_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to deserialize ML-KEM public key"))?;

    // Encapsulate to generate ML-KEM shared secret
    let (ml_kem_ct, ml_kem_ss) = peer_ml_kem_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow::anyhow!("ML-KEM encapsulation failed"))?;

    // Perform X25519 key agreement
    let our_x25519_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let our_x25519_public = X25519PublicKey::from(&our_x25519_secret);

    let peer_x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(x25519_bytes)?);
    let x25519_ss = our_x25519_secret.diffie_hellman(&peer_x25519_public);

    // Combine both shared secrets using KDF
    let combined_ss = derive_hybrid_secret(ml_kem_ss.as_ref(), x25519_ss.as_bytes());

    // Prepare response payload
    let mut response = Vec::new();
    response.extend_from_slice(ml_kem_ct.as_ref());
    response.extend_from_slice(our_x25519_public.as_bytes());

    Ok((response, combined_ss))
}

/// Finalize key exchange by decapsulating ciphertext
#[cfg(feature = "post-quantum")]
pub fn finalize_hybrid_exchange(state: &HybridKeyState, peer_response: &[u8]) -> Result<Vec<u8>> {
    // Parse ML-KEM ciphertext (1088 bytes) and X25519 public key (32 bytes)
    if peer_response.len() < 1088 + 32 {
        return Err(anyhow::anyhow!("Invalid response size"));
    }

    let ml_kem_ct_bytes = &peer_response[..1088];
    let peer_x25519_bytes = &peer_response[1088..1088 + 32];

    // Decapsulate ML-KEM ciphertext
    let ml_kem_ct = ml_kem::Ciphertext::<MlKem768>::try_from(ml_kem_ct_bytes)
        .map_err(|_| anyhow::anyhow!("Failed to deserialize ML-KEM ciphertext"))?;

    let ml_kem_ss = state
        .ml_kem_dk
        .decapsulate(&ml_kem_ct)
        .map_err(|_| anyhow::anyhow!("ML-KEM decapsulation failed"))?;

    // Perform X25519 key agreement
    let peer_x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(peer_x25519_bytes)?);
    let x25519_ss = state.x25519_secret.diffie_hellman(&peer_x25519_public);

    // Combine both shared secrets
    let combined_ss = derive_hybrid_secret(ml_kem_ss.as_ref(), x25519_ss.as_bytes());

    Ok(combined_ss)
}

/// Derive final shared secret from hybrid components using HKDF
#[cfg(feature = "post-quantum")]
fn derive_hybrid_secret(ml_kem_ss: &[u8], x25519_ss: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(b"LEGION_HYBRID_KDF_V1");
    hasher.update(ml_kem_ss);
    hasher.update(x25519_ss);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        // Party A generates keys
        let state_a = generate_hybrid_keys();
        let payload_a = create_hybrid_payload(&state_a);

        // Party B processes A's keys and generates response
        let (response_b, secret_b) = process_hybrid_payload(&payload_a).unwrap();

        // Party A finalizes exchange
        let secret_a = finalize_hybrid_exchange(&state_a, &response_b).unwrap();

        // Both parties should have same shared secret
        assert_eq!(secret_a, secret_b);
        assert_eq!(secret_a.len(), 32);
    }
}
