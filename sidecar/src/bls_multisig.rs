use blake3;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::error::{Result, SidecarError};
use rand::{rngs::OsRng, RngCore};

// BLS12-381 simulation using Ed25519 for now (real BLS would use bls12_381 crate)
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionToken {
    pub client_pubkey: [u8; 32],
    pub domain: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 32],
    pub priority_level: u8,
    pub committee_signature: BlsSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsSignature {
    pub signature: Vec<u8>,
    pub signer_bitmap: u64, // Bitmap of which committee members signed
}

#[derive(Debug, Clone)]
pub struct CommitteeNode {
    pub id: u32,
    pub keypair: Keypair,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct BlsCommittee {
    pub nodes: HashMap<u32, CommitteeNode>,
    pub threshold: u32,
    pub total_nodes: u32,
}

impl BlsCommittee {
    pub fn new_2_of_3() -> Self {
        let mut nodes = HashMap::new();
        
        for i in 0..3 {
            let mut csprng = OsRng;
            let keypair = Keypair::generate(&mut csprng);
            let public_key = keypair.public;
            
            nodes.insert(i, CommitteeNode {
                id: i,
                keypair,
                public_key,
            });
        }
        
        Self {
            nodes,
            threshold: 2,
            total_nodes: 3,
        }
    }

    pub fn issue_token(&self, client_pubkey: [u8; 32], domain: String, ttl_secs: u64) -> Result<AdmissionToken> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        
        let token = AdmissionToken {
            client_pubkey,
            domain,
            issued_at: now,
            expires_at: now + ttl_secs,
            nonce,
            priority_level: 1,
            committee_signature: BlsSignature {
                signature: Vec::new(),
                signer_bitmap: 0,
            },
        };
        
        let signature = self.threshold_sign(&token)?;
        
        Ok(AdmissionToken {
            committee_signature: signature,
            ..token
        })
    }

    fn threshold_sign(&self, token: &AdmissionToken) -> Result<BlsSignature> {
        let message = self.serialize_token_for_signing(token)?;
        let mut signatures = Vec::new();
        let mut signer_bitmap = 0u64;
        
        // Simulate threshold signing with first 2 nodes (2-of-3)
        for (node_id, node) in self.nodes.iter().take(self.threshold as usize) {
            let signature = node.keypair.sign(&message);
            signatures.push((*node_id, signature));
            signer_bitmap |= 1u64 << node_id;
        }
        
        // Aggregate signatures (simplified - real BLS would aggregate)
        let aggregated_sig = self.aggregate_signatures(signatures)?;
        
        Ok(BlsSignature {
            signature: aggregated_sig,
            signer_bitmap,
        })
    }

    fn aggregate_signatures(&self, signatures: Vec<(u32, Signature)>) -> Result<Vec<u8>> {
        // Simplified aggregation - real BLS would use pairing-based aggregation
        let mut aggregated = Vec::new();
        
        for (node_id, sig) in signatures {
            aggregated.extend_from_slice(&node_id.to_le_bytes());
            aggregated.extend_from_slice(&sig.to_bytes());
        }
        
        Ok(aggregated)
    }

    pub fn verify_token(&self, token: &AdmissionToken, revocation_root: &[u8; 32]) -> Result<bool> {
        // Check expiry
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if now > token.expires_at {
            return Ok(false);
        }
        
        // Check revocation (simplified - real implementation would use Merkle proof)
        if self.is_token_revoked(token, revocation_root)? {
            return Ok(false);
        }
        
        // Verify threshold signature
        self.verify_threshold_signature(token)
    }

    fn verify_threshold_signature(&self, token: &AdmissionToken) -> Result<bool> {
        let message = self.serialize_token_for_signing(token)?;
        let signatures = self.deserialize_aggregated_signature(&token.committee_signature.signature)?;
        
        let mut valid_signatures = 0;
        
        for (node_id, signature) in signatures {
            if let Some(node) = self.nodes.get(&node_id) {
                if node.public_key.verify(&message, &signature).is_ok() {
                    valid_signatures += 1;
                }
            }
        }
        
        Ok(valid_signatures >= self.threshold)
    }

    fn deserialize_aggregated_signature(&self, sig_bytes: &[u8]) -> Result<Vec<(u32, Signature)>> {
        let mut signatures = Vec::new();
        let mut offset = 0;
        
        while offset + 68 <= sig_bytes.len() { // 4 bytes node_id + 64 bytes signature
            let node_id = u32::from_le_bytes([
                sig_bytes[offset],
                sig_bytes[offset + 1],
                sig_bytes[offset + 2],
                sig_bytes[offset + 3],
            ]);
            
            let sig_bytes_slice = &sig_bytes[offset + 4..offset + 68];
            let signature = Signature::from_bytes(sig_bytes_slice.try_into()
                .map_err(|_| SidecarError::Internal("Invalid signature bytes".to_string()))?)?;
            
            signatures.push((node_id, signature));
            offset += 68;
        }
        
        Ok(signatures)
    }

    fn serialize_token_for_signing(&self, token: &AdmissionToken) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        data.extend_from_slice(&token.client_pubkey);
        data.extend_from_slice(token.domain.as_bytes());
        data.extend_from_slice(&token.issued_at.to_le_bytes());
        data.extend_from_slice(&token.expires_at.to_le_bytes());
        data.extend_from_slice(&token.nonce);
        data.push(token.priority_level);
        Ok(data)
    }

    fn is_token_revoked(&self, token: &AdmissionToken, revocation_root: &[u8; 32]) -> Result<bool> {
        // Simplified revocation check - real implementation would verify Merkle proof
        let token_hash = blake3::hash(&token.nonce);
        
        // Check if token hash is in revocation tree (simplified)
        let mut hasher = blake3::Hasher::new();
        hasher.update(token_hash.as_bytes());
        hasher.update(revocation_root);
        let combined_hash = hasher.finalize();
        
        // Token is revoked if combined hash has specific pattern (simulation)
        Ok(combined_hash.as_bytes()[0] == 0x00)
    }

    pub fn get_committee_pubkeys(&self) -> Vec<PublicKey> {
        self.nodes.values().map(|node| node.public_key).collect()
    }
}

#[derive(Debug, Clone)]
pub struct RevocationList {
    pub merkle_root: [u8; 32],
    pub revoked_tokens: HashSet<[u8; 32]>, // Token nonces
}

impl RevocationList {
    pub fn new() -> Self {
        Self {
            merkle_root: [0u8; 32],
            revoked_tokens: HashSet::new(),
        }
    }

    pub fn revoke_token(&mut self, token_nonce: [u8; 32]) {
        self.revoked_tokens.insert(token_nonce);
        self.update_merkle_root();
    }

    fn update_merkle_root(&mut self) {
        if self.revoked_tokens.is_empty() {
            self.merkle_root = [0u8; 32];
            return;
        }

        // Simplified Merkle tree construction
        let mut hashes: Vec<[u8; 32]> = self.revoked_tokens.iter().cloned().collect();
        
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]); // Duplicate if odd number
                }
                next_level.push(hasher.finalize().into());
            }
            
            hashes = next_level;
        }
        
        self.merkle_root = hashes[0];
    }

    pub fn is_revoked(&self, token_nonce: &[u8; 32]) -> bool {
        self.revoked_tokens.contains(token_nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_2_of_3_multisig() {
        let committee = BlsCommittee::new_2_of_3();
        let client_pubkey = [1u8; 32];
        let domain = "test.com".to_string();
        
        let token = committee.issue_token(client_pubkey, domain, 3600).unwrap();
        
        let revocation_root = [0u8; 32];
        let is_valid = committee.verify_token(&token, &revocation_root).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_revocation_list() {
        let mut revocation_list = RevocationList::new();
        let token_nonce = [42u8; 32];
        
        assert!(!revocation_list.is_revoked(&token_nonce));
        
        revocation_list.revoke_token(token_nonce);
        assert!(revocation_list.is_revoked(&token_nonce));
        
        // Merkle root should be updated
        assert_ne!(revocation_list.merkle_root, [0u8; 32]);
    }
}