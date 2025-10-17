use crate::error::{Result, SidecarError};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use bloomfilter::Bloom;
use lru::LruCache;
use tracing::{debug, warn};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const BLOOM_FILTER_SIZE: usize = 1_000_000;
const BLOOM_FALSE_POSITIVE_RATE: f64 = 0.01;
const LRU_CACHE_SIZE: usize = 10_000;
const MAX_TICKET_AGE_SECS: u64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketRequest {
    pub client_id: String,
    pub ticket: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageAResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedTicket {
    client_id: String,
    expiry: u64,
    signature: [u8; 32],
}

pub trait KeyProvider: Send + Sync {
    fn get_hmac_key(&self, client_id: &str) -> Result<Zeroizing<Vec<u8>>>;
}

pub struct MockKeyProvider {
    keys: HashMap<String, Vec<u8>>,
}

impl MockKeyProvider {
    pub fn new() -> Self {
        let mut keys = HashMap::new();
        keys.insert("client1".to_string(), b"test-key-client1-32bytes-long!!".to_vec());
        keys.insert("client2".to_string(), b"test-key-client2-32bytes-long!!".to_vec());
        Self { keys }
    }
}

impl KeyProvider for MockKeyProvider {
    fn get_hmac_key(&self, client_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.keys.get(client_id)
            .map(|k| Zeroizing::new(k.clone()))
            .ok_or_else(|| SidecarError::Auth(format!("Unknown client_id: {}", client_id)))
    }
}

pub struct StageAFilter {
    key_provider: Arc<dyn KeyProvider>,
    replay_bloom: Arc<RwLock<Bloom<String>>>,
    replay_cache: Arc<RwLock<LruCache<String, u64>>>,
}

impl StageAFilter {
    pub fn new(key_provider: Arc<dyn KeyProvider>) -> Self {
        let bloom = Bloom::new_for_fp_rate(BLOOM_FILTER_SIZE, BLOOM_FALSE_POSITIVE_RATE);
        let cache = LruCache::new(LRU_CACHE_SIZE.try_into().unwrap());
        
        Self {
            key_provider,
            replay_bloom: Arc::new(RwLock::new(bloom)),
            replay_cache: Arc::new(RwLock::new(cache)),
        }
    }
    
    pub fn verify_ticket(&self, request: TicketRequest) -> StageAResponse {
        match self.verify_ticket_internal(request) {
            Ok(_) => StageAResponse { status: "ok".to_string(), error: None },
            Err(e) => {
                warn!("Ticket verification failed: {}", e);
                StageAResponse { 
                    status: "rejected".to_string(), 
                    error: Some(e.to_string()) 
                }
            }
        }
    }
    
    fn verify_ticket_internal(&self, request: TicketRequest) -> Result<()> {
        // Parse ticket
        let parsed = self.parse_ticket(&request.ticket)?;
        
        // Verify client_id matches
        if parsed.client_id != request.client_id {
            return Err(SidecarError::Auth("Client ID mismatch".to_string()));
        }
        
        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        if now > parsed.expiry {
            return Err(SidecarError::Auth("Ticket expired".to_string()));
        }
        
        if parsed.expiry > now + MAX_TICKET_AGE_SECS {
            return Err(SidecarError::Auth("Ticket too far in future".to_string()));
        }
        
        // Check replay protection
        let ticket_hash = format!("{}:{}:{}", parsed.client_id, parsed.expiry, hex::encode(parsed.signature));
        
        if self.is_replayed(&ticket_hash)? {
            return Err(SidecarError::Auth("Replay attack detected".to_string()));
        }
        
        // Verify HMAC signature
        self.verify_hmac_signature(&parsed, request.timestamp)?;
        
        // Mark as used
        self.mark_ticket_used(ticket_hash, parsed.expiry);
        
        debug!("Ticket verified successfully for client: {}", parsed.client_id);
        Ok(())
    }
    
    fn parse_ticket(&self, ticket: &str) -> Result<ParsedTicket> {
        let bytes = hex::decode(ticket)
            .map_err(|_| SidecarError::Auth("Invalid ticket format".to_string()))?;
        
        if bytes.len() < 40 { // min: 4 + 4 + 32 bytes
            return Err(SidecarError::Auth("Ticket too short".to_string()));
        }
        
        let client_id_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        
        if client_id_len > 64 || bytes.len() < 8 + client_id_len + 32 {
            return Err(SidecarError::Auth("Invalid ticket structure".to_string()));
        }
        
        let client_id = String::from_utf8(bytes[8..8 + client_id_len].to_vec())
            .map_err(|_| SidecarError::Auth("Invalid client_id encoding".to_string()))?;
        
        let expiry = u64::from_le_bytes([
            bytes[8 + client_id_len],
            bytes[9 + client_id_len],
            bytes[10 + client_id_len],
            bytes[11 + client_id_len],
            bytes[12 + client_id_len],
            bytes[13 + client_id_len],
            bytes[14 + client_id_len],
            bytes[15 + client_id_len],
        ]);
        
        let mut signature = [0u8; 32];
        signature.copy_from_slice(&bytes[16 + client_id_len..48 + client_id_len]);
        
        Ok(ParsedTicket { client_id, expiry, signature })
    }
    
    fn verify_hmac_signature(&self, parsed: &ParsedTicket, timestamp: u64) -> Result<()> {
        let key = self.key_provider.get_hmac_key(&parsed.client_id)?;
        
        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| SidecarError::Internal(format!("HMAC key error: {}", e)))?;
        
        // HMAC over: client_id || expiry || timestamp
        mac.update(parsed.client_id.as_bytes());
        mac.update(&parsed.expiry.to_le_bytes());
        mac.update(&timestamp.to_le_bytes());
        
        let expected = mac.finalize().into_bytes();
        
        if expected.as_slice() != parsed.signature {
            return Err(SidecarError::Auth("Invalid HMAC signature".to_string()));
        }
        
        Ok(())
    }
    
    fn is_replayed(&self, ticket_hash: &str) -> Result<bool> {
        // Check Bloom filter first (fast)
        {
            let bloom = self.replay_bloom.read();
            if bloom.check(&ticket_hash.to_string()) {
                // Potential replay, check LRU cache for confirmation
                let cache = self.replay_cache.read();
                return Ok(cache.contains(ticket_hash));
            }
        }
        
        Ok(false)
    }
    
    fn mark_ticket_used(&self, ticket_hash: String, expiry: u64) {
        // Add to Bloom filter
        {
            let mut bloom = self.replay_bloom.write();
            bloom.set(&ticket_hash);
        }
        
        // Add to LRU cache with expiry
        {
            let mut cache = self.replay_cache.write();
            cache.put(ticket_hash, expiry);
        }
    }
    
    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        let mut cache = self.replay_cache.write();
        let mut to_remove = Vec::new();
        
        for (key, &expiry) in cache.iter() {
            if now > expiry + 60 { // Grace period
                to_remove.push(key.clone());
            }
        }
        
        for key in to_remove {
            cache.pop(&key);
        }
    }
}

pub fn create_ticket(client_id: &str, expiry: u64, timestamp: u64, key: &[u8]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| SidecarError::Internal(format!("HMAC key error: {}", e)))?;
    
    mac.update(client_id.as_bytes());
    mac.update(&expiry.to_le_bytes());
    mac.update(&timestamp.to_le_bytes());
    
    let signature = mac.finalize().into_bytes();
    
    let mut ticket_bytes = Vec::new();
    ticket_bytes.extend_from_slice(&(client_id.len() as u32).to_le_bytes());
    ticket_bytes.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    ticket_bytes.extend_from_slice(client_id.as_bytes());
    ticket_bytes.extend_from_slice(&expiry.to_le_bytes());
    ticket_bytes.extend_from_slice(&signature);
    
    Ok(hex::encode(ticket_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    
    #[test]
    fn test_ticket_creation_and_verification() {
        let key_provider = Arc::new(MockKeyProvider::new());
        let filter = StageAFilter::new(key_provider);
        
        let client_id = "client1";
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expiry = now + 300;
        let key = b"test-key-client1-32bytes-long!!";
        
        let ticket = create_ticket(client_id, expiry, now, key).unwrap();
        
        let request = TicketRequest {
            client_id: client_id.to_string(),
            ticket,
            timestamp: now,
        };
        
        let response = filter.verify_ticket(request);
        assert_eq!(response.status, "ok");
    }
    
    #[test]
    fn test_expired_ticket_rejection() {
        let key_provider = Arc::new(MockKeyProvider::new());
        let filter = StageAFilter::new(key_provider);
        
        let client_id = "client1";
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expiry = now - 100; // Expired
        let key = b"test-key-client1-32bytes-long!!";
        
        let ticket = create_ticket(client_id, expiry, now, key).unwrap();
        
        let request = TicketRequest {
            client_id: client_id.to_string(),
            ticket,
            timestamp: now,
        };
        
        let response = filter.verify_ticket(request);
        assert_eq!(response.status, "rejected");
    }
    
    #[test]
    fn test_replay_protection() {
        let key_provider = Arc::new(MockKeyProvider::new());
        let filter = StageAFilter::new(key_provider);
        
        let client_id = "client1";
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let expiry = now + 300;
        let key = b"test-key-client1-32bytes-long!!";
        
        let ticket = create_ticket(client_id, expiry, now, key).unwrap();
        
        let request = TicketRequest {
            client_id: client_id.to_string(),
            ticket: ticket.clone(),
            timestamp: now,
        };
        
        // First request should succeed
        let response1 = filter.verify_ticket(request.clone());
        assert_eq!(response1.status, "ok");
        
        // Second request should be rejected as replay
        let response2 = filter.verify_ticket(request);
        assert_eq!(response2.status, "rejected");
    }
}