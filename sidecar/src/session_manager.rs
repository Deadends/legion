use crate::crypto::LegionCrypto;
use std::collections::{HashMap, BTreeMap, VecDeque};
use std::time::{SystemTime, Duration, UNIX_EPOCH, Instant};
use serde::{Serialize, Deserialize};
use blake3::Hasher;
use rand::RngCore;
use chacha20poly1305::aead::OsRng;
use std::sync::{Arc, RwLock, Mutex};
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use dashmap::DashMap;
use rayon::prelude::*;
use std::net::SocketAddr;
use std::hash::{Hash, Hasher as StdHasher};
use std::collections::hash_map::DefaultHasher;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;

const SESSION_LIFETIME: Duration = Duration::from_secs(24 * 3600); // 24 hours
const ROTATION_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour
const MAX_SESSIONS_PER_USER: usize = 50; // Increased for enterprise
const MAX_CLUSTER_NODES: usize = 100;
const REPLICATION_FACTOR: usize = 3;
const LOAD_BALANCE_THRESHOLD: f64 = 0.8; // 80% capacity
const SESSION_SYNC_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const NODE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SESSION_MIGRATIONS: usize = 1000;
const CLUSTER_GOSSIP_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTicket {
    pub session_id: [u8; 32],
    pub user_hash: [u8; 32],
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub security_level: u8,
    pub nonce_counter: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
pub struct SessionData {
    pub master_key: Zeroizing<[u8; 32]>,
    pub client_to_server_key: Zeroizing<[u8; 32]>,
    pub server_to_client_key: Zeroizing<[u8; 32]>,
    pub transcript_hash: [u8; 32],
    pub epoch: u64,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
    pub expires_at: SystemTime,
    pub user_hash: [u8; 32],
    pub nonce_counter_c2s: u64,
    pub nonce_counter_s2c: u64,
    pub rotation_due: SystemTime,
}

pub struct SessionManager {
    crypto: LegionCrypto,
    sessions: HashMap<[u8; 32], SessionData>,
    user_sessions: HashMap<[u8; 32], Vec<[u8; 32]>>,
    replay_cache: HashMap<[u8; 16], SystemTime>,
    resumption_key: Zeroizing<[u8; 32]>,
    key_rotation_time: SystemTime,
}

impl SessionManager {
    pub fn new() -> Result<Self> {
        let mut resumption_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *resumption_key);
        
        Ok(Self {
            crypto: LegionCrypto::new()?,
            sessions: HashMap::new(),
            user_sessions: HashMap::new(),
            replay_cache: HashMap::new(),
            resumption_key,
            key_rotation_time: SystemTime::now(),
        })
    }

    pub fn create_session(
        &mut self,
        user_hash: [u8; 32],
        master_key: [u8; 32],
        transcript_hash: [u8; 32],
        _security_level: u8,
    ) -> Result<[u8; 32]> {
        // Generate unique session ID
        let session_id = self.generate_session_id(&user_hash)?;
        
        // Enforce session limits per user
        self.enforce_session_limits(&user_hash)?;
        
        // Derive directional keys
        let salt = self.crypto.generate_random_bytes(32)?;
        let c2s_key: [u8; 32] = self.crypto.derive_key_with_transcript(
            &master_key, &salt, &transcript_hash, b"CLIENT_TO_SERVER_V3", 32
        )?.try_into()
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        
        let s2c_key: [u8; 32] = self.crypto.derive_key_with_transcript(
            &master_key, &salt, &transcript_hash, b"SERVER_TO_CLIENT_V3", 32
        )?.try_into()
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        
        let now = SystemTime::now();
        let session_data = SessionData {
            master_key: Zeroizing::new(master_key),
            client_to_server_key: Zeroizing::new(c2s_key),
            server_to_client_key: Zeroizing::new(s2c_key),
            transcript_hash,
            epoch: 0,
            created_at: now,
            last_used: now,
            expires_at: now + SESSION_LIFETIME,
            user_hash,
            nonce_counter_c2s: 0,
            nonce_counter_s2c: 0,
            rotation_due: now + ROTATION_INTERVAL,
        };
        
        self.sessions.insert(session_id, session_data);
        self.user_sessions.entry(user_hash).or_insert_with(Vec::new).push(session_id);
        
        info!("Created session {} for user {}", hex::encode(&session_id[..8]), hex::encode(&user_hash[..8]));
        Ok(session_id)
    }

    pub fn encrypt_message(
        &mut self,
        session_id: &[u8; 32],
        data: &[u8],
        direction: &str,
    ) -> Result<Vec<u8>> {
        // Check session validity first
        {
            let session = self.sessions.get(session_id)
                .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
            self.check_session_validity(session)?;
        }
        
        self.check_rotation_needed(session_id)?;
        
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        let (key, nonce_counter) = match direction {
            "client_to_server" => (&*session.client_to_server_key, &mut session.nonce_counter_c2s),
            "server_to_client" => (&*session.server_to_client_key, &mut session.nonce_counter_s2c),
            _ => return Err(anyhow::anyhow!("Invalid direction")),
        };
        
        // Use monotonic nonce counter for replay protection
        *nonce_counter += 1;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());
        nonce[8..].copy_from_slice(&session.epoch.to_le_bytes()[..4]);
        
        let encrypted = self.crypto.encrypt_with_deterministic_nonce(
            data,
            key,
            &nonce,
            session_id,
            session.epoch,
            direction,
            &session.transcript_hash,
            *nonce_counter,
        )?;
        
        session.last_used = SystemTime::now();
        debug!("Encrypted message for session {} direction {} with sequence {}", 
               hex::encode(&session_id[..8]), direction, *nonce_counter);
        Ok(encrypted)
    }

    pub fn decrypt_message(
        &mut self,
        session_id: &[u8; 32],
        encrypted_data: &[u8],
        direction: &str,
    ) -> Result<Vec<u8>> {
        // Check session validity first
        {
            let session = self.sessions.get(session_id)
                .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
            self.check_session_validity(session)?;
        }
        
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        // Extract and validate nonce counter for replay protection
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Invalid encrypted data"));
        }
        
        let nonce_bytes = &encrypted_data[..12];
        let received_counter = u64::from_le_bytes(
            nonce_bytes[..8].try_into()
                .context("Invalid nonce")?
        );
        
        let expected_counter = match direction {
            "client_to_server" => session.nonce_counter_c2s + 1,
            "server_to_client" => session.nonce_counter_s2c + 1,
            _ => return Err(anyhow::anyhow!("Invalid direction")),
        };
        
        if received_counter != expected_counter {
            return Err(anyhow::anyhow!("Replay attack detected: expected {}, got {}", expected_counter, received_counter));
        }
        
        let key = match direction {
            "client_to_server" => &*session.client_to_server_key,
            "server_to_client" => &*session.server_to_client_key,
            _ => return Err(anyhow::anyhow!("Invalid direction")),
        };
        
        let decrypted = self.crypto.decrypt_with_sequence_validation(
            encrypted_data,
            key,
            session_id,
            session.epoch,
            direction,
            &session.transcript_hash,
            received_counter,
        )?;
        
        // Update nonce counter after successful decryption
        match direction {
            "client_to_server" => session.nonce_counter_c2s = received_counter,
            "server_to_client" => session.nonce_counter_s2c = received_counter,
            _ => unreachable!(),
        }
        
        session.last_used = SystemTime::now();
        debug!("Decrypted message for session {} direction {} with sequence {}", 
               hex::encode(&session_id[..8]), direction, received_counter);
        Ok(decrypted)
    }

    pub fn rotate_session_keys(&mut self, session_id: &[u8; 32]) -> Result<()> {
        let session = self.sessions.get_mut(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        session.epoch += 1;
        
        // Derive new keys with updated epoch
        let salt = self.crypto.generate_random_bytes(32)?;
        let epoch_info = format!("EPOCH_{}", session.epoch);
        
        let c2s_key: [u8; 32] = self.crypto.derive_key_with_transcript(
            &*session.master_key, &salt, &session.transcript_hash,
            &format!("CLIENT_TO_SERVER_{}", epoch_info).as_bytes(), 32
        )?.try_into()
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        
        let s2c_key: [u8; 32] = self.crypto.derive_key_with_transcript(
            &*session.master_key, &salt, &session.transcript_hash,
            &format!("SERVER_TO_CLIENT_{}", epoch_info).as_bytes(), 32
        )?.try_into()
            .map_err(|_| anyhow::anyhow!("Key derivation failed"))?;
        
        session.client_to_server_key = Zeroizing::new(c2s_key);
        session.server_to_client_key = Zeroizing::new(s2c_key);
        
        // Reset nonce counters for new epoch
        session.nonce_counter_c2s = 0;
        session.nonce_counter_s2c = 0;
        session.rotation_due = SystemTime::now() + ROTATION_INTERVAL;
        
        info!("Rotated keys for session {} to epoch {}", hex::encode(&session_id[..8]), session.epoch);
        Ok(())
    }

    pub fn create_resumption_ticket(&self, session_id: &[u8; 32]) -> Result<SessionTicket> {
        let session = self.sessions.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        
        let mut ticket = SessionTicket {
            session_id: *session_id,
            user_hash: session.user_hash,
            created_at: session.created_at,
            expires_at: session.expires_at,
            security_level: 1,
            nonce_counter: session.nonce_counter_c2s.max(session.nonce_counter_s2c),
            signature: Vec::new(),
        };
        
        // Sign the ticket with HMAC
        ticket.signature = self.sign_resumption_ticket(&ticket)?;
        
        debug!("Created signed resumption ticket for session {}", hex::encode(&session_id[..8]));
        Ok(ticket)
    }
    
    fn sign_resumption_ticket(&self, ticket: &SessionTicket) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&*self.resumption_key)
            .map_err(|_| anyhow::anyhow!("Invalid HMAC key"))?;
        
        // Create ticket payload for signing
        let mut payload = Vec::with_capacity(128);
        payload.extend_from_slice(&ticket.session_id);
        payload.extend_from_slice(&ticket.user_hash);
        payload.extend_from_slice(&ticket.created_at.duration_since(UNIX_EPOCH)
            .context("Invalid timestamp")?
            .as_secs().to_le_bytes());
        payload.extend_from_slice(&ticket.expires_at.duration_since(UNIX_EPOCH)
            .context("Invalid timestamp")?
            .as_secs().to_le_bytes());
        payload.push(ticket.security_level);
        payload.extend_from_slice(&ticket.nonce_counter.to_le_bytes());
        
        mac.update(&payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }
    
    fn verify_resumption_ticket(&self, ticket: &SessionTicket) -> Result<bool> {
        if ticket.signature.is_empty() {
            return Ok(false);
        }
        
        let expected_signature = self.sign_resumption_ticket(&SessionTicket {
            session_id: ticket.session_id,
            user_hash: ticket.user_hash,
            created_at: ticket.created_at,
            expires_at: ticket.expires_at,
            security_level: ticket.security_level,
            nonce_counter: ticket.nonce_counter,
            signature: Vec::new(), // Don't include signature in verification
        })?;
        
        Ok(self.crypto.secure_compare(&ticket.signature, &expected_signature))
    }

    pub fn resume_from_ticket(&mut self, ticket: &SessionTicket) -> Result<[u8; 32]> {
        // Validate ticket expiration
        if ticket.expires_at < SystemTime::now() {
            return Err(anyhow::anyhow!("Ticket expired"));
        }
        
        // Verify ticket signature
        if !self.verify_resumption_ticket(ticket)? {
            return Err(anyhow::anyhow!("Invalid ticket signature"));
        }
        
        // Check if session still exists and matches
        if let Some(session) = self.sessions.get(&ticket.session_id) {
            if session.user_hash == ticket.user_hash {
                info!("Resumed session {} from valid signed ticket", hex::encode(&ticket.session_id[..8]));
                return Ok(ticket.session_id);
            }
        }
        
        Err(anyhow::anyhow!("Session not found or user mismatch"))
    }

    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let now = SystemTime::now();
        let mut expired_sessions = Vec::new();
        
        for (session_id, session) in &self.sessions {
            if session.expires_at < now {
                expired_sessions.push(*session_id);
            }
        }
        
        let expired_count = expired_sessions.len();
        
        for session_id in expired_sessions {
            if let Some(session) = self.sessions.remove(&session_id) {
                // Remove from user sessions
                if let Some(user_sessions) = self.user_sessions.get_mut(&session.user_hash) {
                    user_sessions.retain(|&id| id != session_id);
                    if user_sessions.is_empty() {
                        self.user_sessions.remove(&session.user_hash);
                    }
                }
            }
        }
        
        // Cleanup old replay cache entries
        self.replay_cache.retain(|_, &mut timestamp| {
            now.duration_since(timestamp).unwrap_or_default() < Duration::from_secs(300)
        });
        
        if expired_count > 0 {
            info!("Cleaned up {} expired sessions", expired_count);
        }
        
        expired_count
    }

    fn generate_session_id(&self, user_hash: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = Hasher::new();
        hasher.update(b"LEGION_SESSION_ID_V3");
        hasher.update(user_hash);
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH)
            .context("System time error")?
            .as_nanos().to_le_bytes());
        
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);
        
        let mut session_id = [0u8; 32];
        session_id.copy_from_slice(&hasher.finalize().as_bytes()[..32]);
        Ok(session_id)
    }

    fn enforce_session_limits(&mut self, user_hash: &[u8; 32]) -> Result<()> {
        if let Some(user_sessions) = self.user_sessions.get_mut(user_hash) {
            if user_sessions.len() >= MAX_SESSIONS_PER_USER {
                // Remove oldest session
                if let Some(oldest_session_id) = user_sessions.first().copied() {
                    self.sessions.remove(&oldest_session_id);
                    user_sessions.remove(0);
                    debug!("Removed oldest session for user {} due to limit", hex::encode(&user_hash[..8]));
                }
            }
        }
        Ok(())
    }

    fn check_session_validity(&self, session: &SessionData) -> Result<()> {
        let now = SystemTime::now();
        if session.expires_at < now {
            return Err(anyhow::anyhow!("Session expired"));
        }
        
        // Check for session inactivity
        if now.duration_since(session.last_used).unwrap_or_default() > Duration::from_secs(3600) {
            return Err(anyhow::anyhow!("Session inactive too long"));
        }
        
        Ok(())
    }

    fn check_rotation_needed(&mut self, session_id: &[u8; 32]) -> Result<()> {
        let needs_rotation = {
            let session = self.sessions.get(session_id)
                .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
            SystemTime::now() >= session.rotation_due
        };
        
        if needs_rotation {
            self.rotate_session_keys(session_id)?;
        }
        
        Ok(())
    }

    pub fn get_session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_user_session_count(&self, user_hash: &[u8; 32]) -> usize {
        self.user_sessions.get(user_hash).map(|sessions| sessions.len()).unwrap_or(0)
    }
    
    pub fn get_session_stats(&self) -> SessionManagerStats {
        let now = SystemTime::now();
        let active_sessions = self.sessions.iter()
            .filter(|(_, session)| session.expires_at > now)
            .count();
        
        let total_users = self.user_sessions.len();
        let avg_sessions_per_user = if total_users > 0 {
            self.sessions.len() as f64 / total_users as f64
        } else {
            0.0
        };
        
        SessionManagerStats {
            total_sessions: self.sessions.len(),
            active_sessions,
            total_users,
            avg_sessions_per_user,
            replay_cache_size: self.replay_cache.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SessionManagerStats {
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub total_users: usize,
    pub avg_sessions_per_user: f64,
    pub replay_cache_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_creation() -> Result<()> {
        let mut manager = SessionManager::new()?;
        let user_hash = [1u8; 32];
        let master_key = [2u8; 32];
        let transcript_hash = [3u8; 32];
        
        let session_id = manager.create_session(user_hash, master_key, transcript_hash, 128)?;
        assert_eq!(manager.get_session_count(), 1);
        assert_eq!(manager.get_user_session_count(&user_hash), 1);
        
        Ok(())
    }
    
    #[test]
    fn test_session_cleanup() -> Result<()> {
        let mut manager = SessionManager::new()?;
        let user_hash = [1u8; 32];
        let master_key = [2u8; 32];
        let transcript_hash = [3u8; 32];
        
        let _session_id = manager.create_session(user_hash, master_key, transcript_hash, 128)?;
        assert_eq!(manager.get_session_count(), 1);
        
        // Sessions should not be expired immediately
        let cleaned = manager.cleanup_expired_sessions();
        assert_eq!(cleaned, 0);
        assert_eq!(manager.get_session_count(), 1);
        
        Ok(())
    }
}