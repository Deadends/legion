use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use once_cell::sync::Lazy;

#[derive(Clone, Debug)]
pub struct BoundSession {
    pub session_id: String,
    pub client_public_key: Vec<u8>,
    pub nullifier: [u8; 32],
    pub created_at: u64,
    pub last_used: u64,
}

static SESSION_STORE: Lazy<Arc<RwLock<HashMap<String, BoundSession>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

pub struct SessionVerifier;

impl SessionVerifier {
    /// Create new session bound to client's public key
    pub fn create_session(
        client_public_key: Vec<u8>,
        nullifier: [u8; 32],
    ) -> Result<String> {
        let session_id = Self::generate_session_id(&client_public_key, &nullifier)?;
        
        let session = BoundSession {
            session_id: session_id.clone(),
            client_public_key,
            nullifier,
            created_at: crate::get_timestamp(),
            last_used: crate::get_timestamp(),
        };
        
        let mut store = SESSION_STORE.write().unwrap();
        store.insert(session_id.clone(), session);
        
        Ok(session_id)
    }
    
    /// Verify request signature matches session's public key
    pub fn verify_request(
        session_id: &str,
        request_data: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let mut store = SESSION_STORE.write().unwrap();
        
        let session = store.get_mut(session_id)
            .ok_or_else(|| anyhow!("Session not found"))?;
        
        // Update last used timestamp
        session.last_used = crate::get_timestamp();
        
        // Verify signature
        let expected_sig = Self::compute_signature(
            session_id,
            &session.client_public_key,
            request_data,
        )?;
        
        Ok(signature == expected_sig.as_slice())
    }
    
    /// Get session info
    pub fn get_session(session_id: &str) -> Result<BoundSession> {
        let store = SESSION_STORE.read().unwrap();
        store.get(session_id)
            .cloned()
            .ok_or_else(|| anyhow!("Session not found"))
    }
    
    /// Cleanup expired sessions
    pub fn cleanup_expired(max_age_seconds: u64) -> usize {
        let now = crate::get_timestamp();
        let cutoff = now.saturating_sub(max_age_seconds);
        
        let mut store = SESSION_STORE.write().unwrap();
        let expired: Vec<String> = store
            .iter()
            .filter(|(_, session)| session.last_used < cutoff)
            .map(|(id, _)| id.clone())
            .collect();
        
        let count = expired.len();
        for id in expired {
            store.remove(&id);
        }
        
        count
    }
    
    fn generate_session_id(public_key: &[u8], nullifier: &[u8; 32]) -> Result<String> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SESSION_ID_V1");
        hasher.update(public_key);
        hasher.update(nullifier);
        hasher.update(&crate::get_timestamp().to_le_bytes());
        
        Ok(hex::encode(hasher.finalize().as_bytes()))
    }
    
    fn compute_signature(
        session_id: &str,
        public_key: &[u8],
        request_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Reconstruct bound key (client does: HMAC(session_id || private_key))
        // Server verifies using public key
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"REQUEST_SIGNATURE_V1");
        hasher.update(session_id.as_bytes());
        hasher.update(public_key);
        hasher.update(request_data);
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }
}
