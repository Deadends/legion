use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub ticket: String,
    pub timestamp: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub success: bool,
    pub session_id: Option<Uuid>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofRequest {
    pub session_id: Uuid,
    pub proof_data: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub circuit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofResponse {
    pub verified: bool,
    pub proof_id: Option<Uuid>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNonceRequest {
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNonceResponse {
    pub server_nonce: String, // hex-encoded
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SidecarRequest {
    #[serde(rename = "auth")]
    Auth(AuthRequest),
    #[serde(rename = "zk_proof")]
    ZkProof(ZkProofRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SidecarResponse {
    #[serde(rename = "auth")]
    Auth(AuthResponse),
    #[serde(rename = "zk_proof")]
    ZkProof(ZkProofResponse),
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub authenticated: bool,
}

impl Session {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            id: Uuid::new_v4(),
            created_at: now,
            last_activity: now,
            authenticated: false,
        }
    }
    
    pub fn authenticate(&mut self) {
        self.authenticated = true;
        self.last_activity = std::time::Instant::now();
    }
    
    pub fn is_expired(&self, ttl_secs: u64) -> bool {
        self.last_activity.elapsed().as_secs() > ttl_secs
    }
}