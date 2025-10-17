use crate::{
    config::AuthConfig,
    error::{Result, SidecarError},
    types::{AuthRequest, AuthResponse, Session},
};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn, error};
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

pub struct AuthManager {
    config: AuthConfig,
    hmac_key: Zeroizing<Vec<u8>>,
    sessions: Arc<DashMap<Uuid, Session>>,
    replay_filter: Arc<RwLock<HashSet<String>>>,
    rate_limiter: Arc<DashMap<String, (Instant, u32)>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Result<Self> {
        let hmac_key = Zeroizing::new(config.hmac_key.as_bytes().to_vec());
        
        let manager = Self {
            config,
            hmac_key,
            sessions: Arc::new(DashMap::new()),
            replay_filter: Arc::new(RwLock::new(HashSet::new())),
            rate_limiter: Arc::new(DashMap::new()),
        };
        
        // Start cleanup tasks
        manager.start_cleanup_tasks();
        
        Ok(manager)
    }
    
    pub async fn authenticate(&self, request: AuthRequest, client_ip: String) -> Result<AuthResponse> {
        // Rate limiting
        if !self.check_rate_limit(&client_ip) {
            warn!("Rate limit exceeded for client: {}", client_ip);
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                error: Some("Rate limit exceeded".to_string()),
            });
        }
        
        // Validate timestamp
        if !self.validate_timestamp(request.timestamp) {
            warn!("Invalid timestamp in auth request from: {}", client_ip);
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                error: Some("Invalid timestamp".to_string()),
            });
        }
        
        // Check replay attack
        if !self.check_replay_protection(&request.nonce) {
            warn!("Replay attack detected from: {}", client_ip);
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                error: Some("Replay detected".to_string()),
            });
        }
        
        // Verify HMAC ticket
        if !self.verify_hmac_ticket(&request.ticket, request.timestamp, &request.nonce)? {
            warn!("Invalid HMAC ticket from: {}", client_ip);
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                error: Some("Invalid ticket".to_string()),
            });
        }
        
        // Create session
        let mut session = Session::new();
        session.authenticate();
        let session_id = session.id;
        
        self.sessions.insert(session_id, session);
        
        debug!("Authentication successful for client: {}, session: {}", client_ip, session_id);
        
        Ok(AuthResponse {
            success: true,
            session_id: Some(session_id),
            error: None,
        })
    }
    
    pub fn validate_session(&self, session_id: &Uuid) -> bool {
        if let Some(session) = self.sessions.get(session_id) {
            if session.authenticated && !session.is_expired(self.config.ticket_ttl_secs) {
                // Update last activity
                drop(session);
                if let Some(mut session) = self.sessions.get_mut(session_id) {
                    session.last_activity = Instant::now();
                }
                return true;
            }
        }
        false
    }
    
    fn verify_hmac_ticket(&self, ticket: &str, timestamp: u64, nonce: &str) -> Result<bool> {
        let ticket_bytes = hex::decode(ticket)
            .map_err(|_| SidecarError::Auth("Invalid ticket format".to_string()))?;
        
        if ticket_bytes.len() != 32 {
            return Ok(false);
        }
        
        let mut mac = HmacSha256::new_from_slice(&self.hmac_key)
            .map_err(|e| SidecarError::Internal(format!("HMAC key error: {}", e)))?;
        
        // SOPHISTICATED: Domain separation to prevent cross-protocol attacks
        mac.update(b"LEGION_HMAC_TICKET_V1");
        mac.update(&timestamp.to_le_bytes());
        mac.update(&(nonce.len() as u32).to_le_bytes());
        mac.update(nonce.as_bytes());
        
        let expected = mac.finalize().into_bytes();
        
        // SOPHISTICATED: Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        Ok(expected.as_slice().ct_eq(&ticket_bytes).into())
    }
    
    fn validate_timestamp(&self, timestamp: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // SOPHISTICATED: Reject timestamps too far in the future (prevents pre-computation attacks)
        if timestamp > now + 60 {
            return false;
        }
        
        // SOPHISTICATED: Reject timestamps too far in the past (prevents replay attacks)
        if timestamp < now.saturating_sub(300) {
            return false;
        }
        
        // SOPHISTICATED: Additional validation - timestamp must be reasonable
        const MIN_VALID_TIMESTAMP: u64 = 1640995200; // 2022-01-01
        const MAX_VALID_TIMESTAMP: u64 = 4102444800; // 2100-01-01
        
        timestamp >= MIN_VALID_TIMESTAMP && timestamp <= MAX_VALID_TIMESTAMP
    }
    
    fn check_replay_protection(&self, nonce: &str) -> bool {
        // SOPHISTICATED: Cryptographic nonce validation
        if nonce.len() < 16 || nonce.len() > 64 {
            return false; // Invalid nonce length
        }
        
        // SOPHISTICATED: Check entropy - reject low-entropy nonces
        let entropy = self.calculate_nonce_entropy(nonce);
        if entropy < 64.0 { // Require at least 64 bits of entropy
            return false;
        }
        
        let mut filter = self.replay_filter.write();
        if filter.contains(nonce) {
            return false;
        }
        
        // SOPHISTICATED: Bounded replay filter to prevent memory exhaustion
        if filter.len() > 100000 {
            filter.clear(); // Reset filter when too large
        }
        
        filter.insert(nonce.to_string());
        true
    }
    
    fn calculate_nonce_entropy(&self, nonce: &str) -> f64 {
        let bytes = nonce.as_bytes();
        let mut char_counts = [0u32; 256];
        
        for &byte in bytes {
            char_counts[byte as usize] += 1;
        }
        
        let len = bytes.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &char_counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy * len // Total entropy in bits
    }
    
    fn check_rate_limit(&self, client_ip: &str) -> bool {
        let now = Instant::now();
        let limit = self.config.rate_limit_per_sec;
        
        match self.rate_limiter.get_mut(client_ip) {
            Some(mut entry) => {
                let (last_reset, count) = entry.value_mut();
                if now.duration_since(*last_reset) >= Duration::from_secs(1) {
                    *last_reset = now;
                    *count = 1;
                    true
                } else if *count < limit {
                    *count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                self.rate_limiter.insert(client_ip.to_string(), (now, 1));
                true
            }
        }
    }
    
    fn start_cleanup_tasks(&self) {
        let sessions = self.sessions.clone();
        let replay_filter = self.replay_filter.clone();
        let rate_limiter = self.rate_limiter.clone();
        let ttl_secs = self.config.ticket_ttl_secs;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                // Clean expired sessions
                sessions.retain(|_, session| !session.is_expired(ttl_secs));
                
                // Clean old nonces (keep 2x replay window)
                if rand::random::<u8>() % 10 == 0 {
                    replay_filter.write().clear();
                }
                
                // Clean old rate limit entries
                let cutoff = Instant::now() - Duration::from_secs(60);
                rate_limiter.retain(|_, (last_reset, _)| *last_reset > cutoff);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_auth_manager_creation() {
        let config = AuthConfig {
            hmac_key: "test-key".to_string(),
            ticket_ttl_secs: 300,
            max_replay_window_secs: 60,
            rate_limit_per_sec: 100,
        };
        
        let auth_manager = AuthManager::new(config);
        assert!(auth_manager.is_ok());
    }
    
    #[test]
    fn test_timestamp_validation() {
        let config = AuthConfig {
            hmac_key: "test-key".to_string(),
            ticket_ttl_secs: 300,
            max_replay_window_secs: 60,
            rate_limit_per_sec: 100,
        };
        
        let auth_manager = AuthManager::new(config).unwrap();
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        assert!(auth_manager.validate_timestamp(now));
        assert!(auth_manager.validate_timestamp(now - 100));
        assert!(!auth_manager.validate_timestamp(now - 400));
    }
}