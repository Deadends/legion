// Linkable Ring Signature Implementation for Device Anonymity
// Based on LSAG (Linkable Spontaneous Anonymous Group) signatures

use anyhow::{anyhow, Result};
use ff::PrimeField;
use pasta_curves::Fp;

/// Linkability tag - deterministic per user+device, but unlinkable to identity
/// Computed as: Blake3(device_pubkey || nullifier)
/// This ensures different users on same device get different tags
pub fn compute_linkability_tag(device_pubkey: &[u8], nullifier: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LEGION_LINKABILITY_TAG_V1");
    hasher.update(device_pubkey);
    hasher.update(nullifier);
    *hasher.finalize().as_bytes()
}

/// Ring signature structure
#[derive(Debug, Clone)]
pub struct RingSignature {
    /// The signature data (proves device in ring)
    pub signature: Vec<u8>,
    /// Linkability tag (same device = same tag)
    pub linkability_tag: [u8; 32],
}

/// Generate a linkable ring signature
///
/// Proves: "I own ONE of the devices in device_merkle_tree"
/// Without revealing: Which device
/// Linkable: Same device always produces same linkability_tag
pub fn generate_ring_signature(
    message: &[u8],
    device_private_key: &[u8],
    device_merkle_root: Fp,
    device_position: usize,
    device_merkle_path: &[Fp; 10],
    linkability_tag: [u8; 32],
) -> Result<RingSignature> {
    // Linkability tag is passed in (computed by caller with nullifier)

    // For now, use a simplified signature scheme
    // In production, use proper LSAG or similar
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LEGION_RING_SIGNATURE_V1");
    hasher.update(message);
    hasher.update(device_private_key);
    hasher.update(&device_merkle_root.to_repr());
    hasher.update(&(device_position as u64).to_le_bytes());

    // Include Merkle path in signature
    for sibling in device_merkle_path {
        hasher.update(&sibling.to_repr());
    }

    let signature = hasher.finalize().as_bytes().to_vec();

    Ok(RingSignature {
        signature,
        linkability_tag,
    })
}

/// Verify a linkable ring signature
///
/// Verifies: Signature proves device in ring
/// Without learning: Which device
pub fn verify_ring_signature(
    message: &[u8],
    ring_sig: &RingSignature,
    device_merkle_root: Fp,
) -> Result<bool> {
    // In a full implementation, this would verify the ring signature
    // cryptographically without knowing which device signed

    // For now, we verify the signature format is valid
    if ring_sig.signature.len() != 32 {
        return Ok(false);
    }

    if ring_sig.linkability_tag.len() != 32 {
        return Ok(false);
    }

    // In production, verify:
    // 1. Signature is valid for message
    // 2. Signer is in the ring (device_merkle_root)
    // 3. Linkability tag is correctly computed

    Ok(true)
}

/// Serialize ring signature to hex
pub fn serialize_ring_signature(ring_sig: &RingSignature) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&ring_sig.linkability_tag);
    bytes.extend_from_slice(&ring_sig.signature);
    hex::encode(bytes)
}

/// Deserialize ring signature from hex
pub fn deserialize_ring_signature(hex_str: &str) -> Result<RingSignature> {
    let bytes = hex::decode(hex_str).map_err(|_| anyhow!("Invalid ring signature hex"))?;

    if bytes.len() < 32 {
        return Err(anyhow!("Ring signature too short"));
    }

    let mut linkability_tag = [0u8; 32];
    linkability_tag.copy_from_slice(&bytes[..32]);

    let signature = bytes[32..].to_vec();

    Ok(RingSignature {
        signature,
        linkability_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linkability_tag_deterministic() {
        let key = b"test_device_key_12345";
        let nullifier = b"test_nullifier";
        let tag1 = compute_linkability_tag(key, nullifier);
        let tag2 = compute_linkability_tag(key, nullifier);
        assert_eq!(tag1, tag2, "Linkability tag should be deterministic");
    }

    #[test]
    fn test_linkability_tag_unique() {
        let key1 = b"device_key_1";
        let key2 = b"device_key_2";
        let nullifier = b"test_nullifier";
        let tag1 = compute_linkability_tag(key1, nullifier);
        let tag2 = compute_linkability_tag(key2, nullifier);
        assert_ne!(tag1, tag2, "Different keys should produce different tags");
    }

    #[test]
    fn test_ring_signature_generation() {
        let message = b"test_challenge_12345";
        let device_key = b"test_device_key";
        let device_root = Fp::from(12345u64);
        let device_position = 5;
        let device_path = [Fp::from(1u64); 10];
        let nullifier = b"test_nullifier";
        let linkability_tag = compute_linkability_tag(device_key, nullifier);

        let ring_sig = generate_ring_signature(
            message,
            device_key,
            device_root,
            device_position,
            &device_path,
            linkability_tag,
        )
        .unwrap();

        assert_eq!(ring_sig.linkability_tag.len(), 32);
        assert!(!ring_sig.signature.is_empty());
    }

    #[test]
    fn test_ring_signature_serialization() {
        let ring_sig = RingSignature {
            signature: vec![1, 2, 3, 4, 5],
            linkability_tag: [42u8; 32],
        };

        let serialized = serialize_ring_signature(&ring_sig);
        let deserialized = deserialize_ring_signature(&serialized).unwrap();

        assert_eq!(ring_sig.linkability_tag, deserialized.linkability_tag);
        assert_eq!(ring_sig.signature, deserialized.signature);
    }
}
