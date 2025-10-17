use anyhow::Result;
use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use serde::{Serialize, Deserialize};

#[cfg(feature = "redis")]
use redis;

use crate::{
    authentication_protocol::AuthenticationProtocol,
    standardized_auth_system::StandardizedAuthSystem,
    auth_circuit::AuthCircuit,
    get_timestamp,
};

pub use crate::authentication_protocol::SecurityLevel;

/// Compute anonymous user ID from username using Argon2
/// This ensures no username collisions and preserves anonymity
fn compute_user_id_hash(username: &str) -> Result<String> {
    let argon2_hash = AuthCircuit::argon2_hash_password(username.as_bytes(), b"USER_ID_SALT")?;
    Ok(hex::encode(&argon2_hash[..16])) // 32 hex chars, unique
}

/// Application-level authentication service
pub struct ApplicationService {
    protocol: Arc<AuthenticationProtocol>,
    session_store: Arc<RwLock<HashMap<String, UserSession>>>,
    rate_limiter: Arc<RwLock<HashMap<String, RateLimitInfo>>>,
    #[cfg(feature = "webauthn")]
    webauthn: Arc<crate::webauthn_service::WebAuthnService>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSession {
    pub session_id: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub security_level: SecurityLevel,
    pub permissions: Vec<String>,
    pub webauthn_credential_id: Option<String>,
    pub client_ip: Option<String>,
    pub device_fingerprint: Option<String>,
    pub user_agent: Option<String>,
    pub last_activity: u64,
}

#[derive(Debug, Clone)]
struct RateLimitInfo {
    attempts: u32,
    last_attempt: u64,
    locked_until: Option<u64>,
}



impl ApplicationService {
    pub fn new() -> Result<Self> {
        StandardizedAuthSystem::initialize()?;
        
        #[cfg(feature = "webauthn")]
        let webauthn = Arc::new(crate::webauthn_service::WebAuthnService::new(
            "localhost",
            "http://localhost:8080"
        )?);
        
        Ok(Self {
            protocol: Arc::new(AuthenticationProtocol::new()?),
            session_store: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "webauthn")]
            webauthn,
        })
    }
    
    pub fn with_protocol(protocol: Arc<AuthenticationProtocol>) -> Result<Self> {
        StandardizedAuthSystem::initialize()?;
        
        #[cfg(feature = "webauthn")]
        let webauthn = Arc::new(crate::webauthn_service::WebAuthnService::new(
            "localhost",
            "http://localhost:8080"
        )?);
        
        Ok(Self {
            protocol,
            session_store: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "webauthn")]
            webauthn,
        })
    }
    
    // ZCASH MODEL: Expose protocol for public data access
    pub fn get_protocol(&self) -> Arc<AuthenticationProtocol> {
        self.protocol.clone()
    }
    

    
    /// REAL ENFORCEMENT: Validates session AND verifies hardware signature
    /// This is the ONLY secure validation for protected resources
    #[cfg(feature = "webauthn")]
    pub fn validate_session_with_hardware_proof(
        &self,
        session_id: &str,
        auth_credential: &webauthn_rs::prelude::PublicKeyCredential,
    ) -> Result<Option<UserSession>> {
        // 1. Check if session exists and is not expired
        if let Some(session) = self.validate_session(session_id)? {
            // 2. Enforce hardware binding - reject if not bound
            if session.webauthn_credential_id.is_none() {
                return Err(anyhow::anyhow!("Session is not hardware-bound"));
            }
            
            // 3. 🔒 CRITICAL ENFORCEMENT: Verify cryptographic signature
            let state = self.webauthn.get_auth_state(session_id)?;
            self.webauthn.finish_authentication(auth_credential, state)?;
            
            // 4. Signature valid - session fully authenticated
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
    
    /// Validate session with anti-hijacking checks (DEPRECATED - use validate_session_with_hardware_proof)
    pub fn validate_session_secure(&self, session_id: &str, client_ip: Option<&str>, user_agent: Option<&str>) -> Result<Option<UserSession>> {
        if let Some(session) = self.validate_session(session_id)? {
            // Check IP binding (strict for Enterprise)
            if session.security_level == SecurityLevel::Enterprise {
                if let (Some(session_ip), Some(request_ip)) = (&session.client_ip, client_ip) {
                    if session_ip != request_ip {
                        println!("⚠️  Session hijacking detected: IP mismatch");
                        return Ok(None);  // Reject session
                    }
                }
            }
            
            // Check user agent (warning for all levels)
            if let (Some(session_ua), Some(request_ua)) = (&session.user_agent, user_agent) {
                if session_ua != request_ua {
                    println!("⚠️  Suspicious: User agent changed");
                    // Log but don't reject (UA can change legitimately)
                }
            }
            
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }
    
    /// Validate session (basic, no hijacking checks)
    pub fn validate_session(&self, session_id: &str) -> Result<Option<UserSession>> {
        // ✅ FIXED: Check Redis first (persistent storage)
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                if let Ok(Some(session_json)) = redis::cmd("GET")
                    .arg(format!("legion:session:{}", session_id))
                    .query::<Option<String>>(&mut conn) {
                    if let Ok(session) = serde_json::from_str::<UserSession>(&session_json) {
                        let now = get_timestamp();
                        if now < session.expires_at {
                            return Ok(Some(session));
                        }
                    }
                }
            }
        }
        
        // Fallback to memory store
        let store = self.session_store.read().unwrap();
        
        if let Some(session) = store.get(session_id) {
            let now = get_timestamp();
            if now < session.expires_at {
                Ok(Some(session.clone()))
            } else {
                // Session expired
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    /// Logout user
    pub fn logout(&self, session_id: &str) -> Result<bool> {
        let mut store = self.session_store.write().unwrap();
        Ok(store.remove(session_id).is_some())
    }
    
    /// Get user permissions
    pub fn get_permissions(&self, session_id: &str) -> Result<Vec<String>> {
        if let Some(session) = self.validate_session(session_id)? {
            Ok(session.permissions)
        } else {
            Ok(vec![])
        }
    }
    
    // Private helper methods
    

    
    fn create_session(&self, user_id_hash: &str, security_level: SecurityLevel, webauthn_credential_id: Option<&str>) -> Result<UserSession> {
        let session_id = self.generate_session_id()?;
        let now = get_timestamp();
        let ttl = self.get_session_duration(security_level);
        let expires_at = now + ttl;
        
        let session = UserSession {
            session_id: session_id.clone(),
            user_id: user_id_hash.to_string(),
            created_at: now,
            expires_at,
            security_level,
            permissions: self.get_default_permissions(security_level),
            webauthn_credential_id: webauthn_credential_id.map(|s| s.to_string()),
            client_ip: None,
            device_fingerprint: None,
            user_agent: None,
            last_activity: now,
        };
        
        // ✅ FIXED: Store session in Redis (persistent across restarts)
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                let session_json = serde_json::to_string(&session)?;
                let _: () = redis::cmd("SETEX")
                    .arg(format!("legion:session:{}", session_id))
                    .arg(ttl)
                    .arg(session_json)
                    .query(&mut conn)?;
            }
        }
        
        // Also store in memory for fast access
        {
            let mut store = self.session_store.write().unwrap();
            store.insert(session_id.clone(), session.clone());
        }
        
        Ok(session)
    }
    
    fn generate_session_id(&self) -> Result<String> {
        use crate::fill_random_bytes;
        
        let mut bytes = [0u8; 32];
        fill_random_bytes(&mut bytes)?;
        Ok(hex::encode(bytes))
    }
    
    fn get_session_duration(&self, security_level: SecurityLevel) -> u64 {
        match security_level {
            SecurityLevel::Standard => 3600 * 8,    // 8 hours
            SecurityLevel::Production => 3600 * 4,  // 4 hours
            SecurityLevel::Quantum => 3600 * 2,     // 2 hours
            SecurityLevel::Enterprise => 3600,      // 1 hour
        }
    }
    
    fn get_default_permissions(&self, security_level: SecurityLevel) -> Vec<String> {
        match security_level {
            SecurityLevel::Standard => vec!["read".to_string()],
            SecurityLevel::Production => vec!["read".to_string(), "write".to_string()],
            SecurityLevel::Quantum => vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            SecurityLevel::Enterprise => vec!["read".to_string(), "write".to_string(), "admin".to_string(), "super_admin".to_string()],
        }
    }
    
    fn is_rate_limited(&self, ip: &str) -> Result<bool> {
        let limiter = self.rate_limiter.read().unwrap();
        
        if let Some(info) = limiter.get(ip) {
            let now = get_timestamp();
            
            // Check if locked
            if let Some(locked_until) = info.locked_until {
                if now < locked_until {
                    return Ok(true);
                }
            }
            
            // Check attempt rate
            if info.attempts >= 5 && (now - info.last_attempt) < 300 {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    fn update_rate_limit(&self, ip: &str) -> Result<()> {
        let mut limiter = self.rate_limiter.write().unwrap();
        let now = get_timestamp();
        
        let info = limiter.entry(ip.to_string()).or_insert(RateLimitInfo {
            attempts: 0,
            last_attempt: now,
            locked_until: None,
        });
        
        info.attempts += 1;
        info.last_attempt = now;
        
        // Lock after 5 attempts
        if info.attempts >= 5 {
            info.locked_until = Some(now + 3600); // 1 hour lockout
        }
        
        Ok(())
    }
    
    fn reset_rate_limit(&self, ip: &str) -> Result<()> {
        let mut limiter = self.rate_limiter.write().unwrap();
        limiter.remove(ip);
        Ok(())
    }
    
    #[cfg(feature = "redis")]
    fn get_redis_connection(&self) -> Result<redis::Connection> {
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url)?;
        Ok(client.get_connection()?)
    }
    
    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&self) -> Result<usize> {
        let mut store = self.session_store.write().unwrap();
        let now = get_timestamp();
        
        let expired_sessions: Vec<String> = store
            .iter()
            .filter(|(_, session)| session.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();
        
        let count = expired_sessions.len();
        for session_id in expired_sessions {
            store.remove(&session_id);
        }
        
        Ok(count)
    }

    // WebAuthn integration methods
    #[cfg(feature = "webauthn")]
    pub fn webauthn_start_registration(&self, username: &str) -> Result<webauthn_rs::prelude::CreationChallengeResponse> {
        let user_id_hash = compute_user_id_hash(username)?;
        let (ccr, state) = self.webauthn.start_registration(&user_id_hash)?;
        self.webauthn.store_reg_state(&user_id_hash, state);
        Ok(ccr)
    }

    #[cfg(feature = "webauthn")]
    pub fn webauthn_finish_registration(&self, username: &str, reg: &webauthn_rs::prelude::RegisterPublicKeyCredential) -> Result<String> {
        let user_id_hash = compute_user_id_hash(username)?;
        let state = self.webauthn.get_reg_state(&user_id_hash)?;
        self.webauthn.finish_registration(reg, state)
    }

    #[cfg(feature = "webauthn")]
    pub fn webauthn_start_authentication(&self, session_id: &str) -> Result<webauthn_rs::prelude::RequestChallengeResponse> {
        let (rcr, state) = self.webauthn.start_authentication(session_id)?;
        self.webauthn.store_auth_state(session_id, state);
        Ok(rcr)
    }

    #[cfg(feature = "webauthn")]
    pub fn webauthn_finish_authentication(&self, session_id: &str, auth: &webauthn_rs::prelude::PublicKeyCredential) -> Result<String> {
        let state = self.webauthn.get_auth_state(session_id)?;
        self.webauthn.finish_authentication(auth, state)
    }
    
    /// Public helper: Compute anonymous user ID from username
    pub fn compute_anonymous_user_id(username: &str) -> Result<String> {
        compute_user_id_hash(username)
    }
}

impl Default for ApplicationService {
    fn default() -> Self {
        #[cfg(feature = "webauthn")]
        {
            Self::new().unwrap_or_else(|_| Self {
                protocol: Arc::new(AuthenticationProtocol::default()),
                session_store: Arc::new(RwLock::new(HashMap::new())),
                rate_limiter: Arc::new(RwLock::new(HashMap::new())),
                webauthn: Arc::new(crate::webauthn_service::WebAuthnService::new("localhost", "http://localhost:8080").unwrap()),
            })
        }
        
        #[cfg(not(feature = "webauthn"))]
        Self::new().unwrap_or_else(|_| Self {
            protocol: Arc::new(AuthenticationProtocol::default()),
            session_store: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    

}