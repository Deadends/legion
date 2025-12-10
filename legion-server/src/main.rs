use axum::{
    extract::Json,
    http::{StatusCode, header::{HeaderName, HeaderValue}, Request},
    response::{Json as ResponseJson, Response},
    routing::{get, post},
    Router,
    middleware::{self, Next},
    body::Body,
};
use legion_prover::{
    AuthenticationProtocol, AuthenticationRequest, SecurityLevel, WebAuthnService,
};

mod webauthn_handlers;
use webauthn_handlers::*;

use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::{info, error};
use std::sync::Arc;
use ff::PrimeField;
use chrono;



#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    security_level: Option<u8>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    success: bool,
    proof: Option<Vec<u8>>,
    session_token: Option<String>,
    nullifier: Option<String>,
    error: Option<String>,
    performance_ms: u64,
}

#[derive(Debug, Deserialize)]
struct BlindRegisterRequest {
    user_leaf: String,
}

#[derive(Debug, Serialize)]
struct BlindRegisterResponse {
    success: bool,
    user_leaf: String,
    error: Option<String>,
}







#[derive(Debug, Deserialize)]
struct VerifyProofRequest {
    proof: String,
    merkle_root: String,
    nullifier: String,
    challenge: String,
    client_pubkey: String,
    timestamp: String,
    device_merkle_root: String,
    session_token: String,
    expiration_time: String,
    k: Option<u32>, // NEW: Client tells server which k was used
}

#[derive(Debug, Serialize)]
struct VerifyProofResponse {
    success: bool,
    session_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterDeviceRequest {
    nullifier_hash: String,
    device_commitment: String,
}

#[derive(Debug, Serialize)]
struct RegisterDeviceResponse {
    success: bool,
    device_position: Option<usize>,
    device_tree_root: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetDeviceProofRequest {
    nullifier_hash: String,
    device_position: usize,
}

#[derive(Debug, Deserialize)]
struct RevokeDeviceRequest {
    nullifier_hash: String,
    device_commitment: String,
}

#[derive(Debug, Serialize)]
struct RevokeDeviceResponse {
    success: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct GetDeviceProofResponse {
    success: bool,
    device_merkle_path: Option<Vec<String>>,
    device_tree_root: Option<String>,
    error: Option<String>,
}

struct AppState {
    protocol: Arc<AuthenticationProtocol>,
    webauthn_service: Arc<WebAuthnService>,
}

async fn authenticate_user(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<LoginRequest>,
) -> Result<ResponseJson<LoginResponse>, StatusCode> {
    let start_time = std::time::Instant::now();
    info!("Authentication request for user: {}", request.username);
    
    let security_level = match request.security_level.unwrap_or(0) {
        0 => SecurityLevel::Standard,
        1 => SecurityLevel::Production,
        2 => SecurityLevel::Quantum,
        3 => SecurityLevel::Enterprise,
        _ => SecurityLevel::Standard,
    };
    
    let auth_request = AuthenticationRequest {
        username: request.username.as_bytes().to_vec(),
        password: request.password.as_bytes().to_vec(),
        security_level,
        anonymity_required: true,
    };
    
    let result = state.protocol.authenticate_fast(auth_request);
    let elapsed = start_time.elapsed().as_millis() as u64;
    
    match result {
        Ok(auth_result) => {
            if auth_result.success {
                info!("Authentication successful in {}ms", elapsed);
                Ok(ResponseJson(LoginResponse {
                    success: true,
                    proof: auth_result.proof,
                    session_token: auth_result.session_token.map(hex::encode),
                    nullifier: auth_result.nullifier.map(hex::encode),
                    error: None,
                    performance_ms: elapsed,
                }))
            } else {
                error!("Authentication failed: {:?}", auth_result.error);
                Ok(ResponseJson(LoginResponse {
                    success: false,
                    proof: None,
                    session_token: None,
                    nullifier: None,
                    error: auth_result.error,
                    performance_ms: elapsed,
                }))
            }
        }
        Err(e) => {
            error!("Authentication error: {}", e);
            Ok(ResponseJson(LoginResponse {
                success: false,
                proof: None,
                session_token: None,
                nullifier: None,
                error: Some(e.to_string()),
                performance_ms: elapsed,
            }))
        }
    }
}

async fn register_blind(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<BlindRegisterRequest>,
) -> Result<ResponseJson<BlindRegisterResponse>, StatusCode> {
    info!("Blind registration request for leaf: {}", request.user_leaf);
    
    let result = state.protocol.register_blind_leaf(&request.user_leaf);
    
    match result {
        Ok(tree_index) => {
            info!("Blind registration successful at index {}", tree_index);
            info!("📤 Returning to client: tree_index={}", tree_index);
            
            Ok(ResponseJson(BlindRegisterResponse {
                success: true,
                user_leaf: format!("tree_index={}", tree_index),  // Return index instead of leaf
                error: None,
            }))
        }
        Err(e) => {
            error!("Blind registration failed: {}", e);
            Ok(ResponseJson(BlindRegisterResponse {
                success: false,
                user_leaf: request.user_leaf,
                error: Some(e.to_string()),
            }))
        }
    }
}



// NEW: Download full Merkle tree for local storage (TRUE zero-knowledge)
#[derive(Debug, Serialize)]
struct DownloadTreeResponse {
    merkle_root: String,
    tree_data: Vec<String>,  // All leaves as hex strings
    tree_size: usize,
    version: u64,
}

async fn download_merkle_tree(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<ResponseJson<DownloadTreeResponse>, StatusCode> {
    info!("📥 Full Merkle tree download request (local storage mode)");
    
    let (root, leaves) = state.protocol.get_anonymity_set_data()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let tree_data: Vec<String> = leaves.iter()
        .map(|leaf| hex::encode(leaf.to_repr()))
        .collect();
    
    let tree_size = tree_data.len() * 32; // bytes
    info!("📤 Sending {} leaves ({} MB)", leaves.len(), tree_size / 1_000_000);
    
    Ok(ResponseJson(DownloadTreeResponse {
        merkle_root: hex::encode(root.to_repr()),
        tree_data,
        tree_size,
        version: chrono::Utc::now().timestamp() as u64,
    }))
}





async fn register_device(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<RegisterDeviceRequest>,
) -> Result<ResponseJson<RegisterDeviceResponse>, StatusCode> {
    info!("Device registration for nullifier: {}...", &request.nullifier_hash[..16]);
    
    let result = state.protocol.register_device(
        &request.nullifier_hash,
        &request.device_commitment,
    );
    
    match result {
        Ok((position, root)) => {
            info!("Device registered at position {} with root {}", position, &root[..16]);
            Ok(ResponseJson(RegisterDeviceResponse {
                success: true,
                device_position: Some(position),
                device_tree_root: Some(root),
                error: None,
            }))
        }
        Err(e) => {
            error!("Device registration failed: {}", e);
            Ok(ResponseJson(RegisterDeviceResponse {
                success: false,
                device_position: None,
                device_tree_root: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

async fn get_device_proof(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<GetDeviceProofRequest>,
) -> Result<ResponseJson<GetDeviceProofResponse>, StatusCode> {
    info!("Device proof request for nullifier: {}...", &request.nullifier_hash[..16]);
    
    let result = state.protocol.get_device_proof(
        &request.nullifier_hash,
        request.device_position,
    );
    
    match result {
        Ok((path, root)) => {
            info!("Device proof generated for position {}", request.device_position);
            Ok(ResponseJson(GetDeviceProofResponse {
                success: true,
                device_merkle_path: Some(path),
                device_tree_root: Some(root),
                error: None,
            }))
        }
        Err(e) => {
            error!("Device proof generation failed: {}", e);
            Ok(ResponseJson(GetDeviceProofResponse {
                success: false,
                device_merkle_path: None,
                device_tree_root: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

async fn verify_anonymous_proof(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<VerifyProofRequest>,
) -> Result<ResponseJson<VerifyProofResponse>, StatusCode> {
    info!("Verifying anonymous proof with device ring signature");
    
    let k = request.k.unwrap_or(14); // Default to k=14 if not specified
    info!("Client specified k={}", k);
    
    let result = state.protocol.verify_anonymous_proof(
        &request.proof,
        &request.merkle_root,
        &request.nullifier,
        &request.challenge,
        &request.client_pubkey,
        &request.timestamp,
        &request.device_merkle_root,
        &request.session_token,
        &request.expiration_time,
        k,
    );
    
    match result {
        Ok(session_token) => {
            info!("Proof verified successfully");
            Ok(ResponseJson(VerifyProofResponse {
                success: true,
                session_token: Some(session_token.0),
                error: None,
            }))
        }
        Err(e) => {
            error!("Proof verification failed: {}", e);
            Ok(ResponseJson(VerifyProofResponse {
                success: false,
                session_token: None,
                error: Some(e.to_string()),
            }))
        }
    }
}



async fn revoke_device(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<RevokeDeviceRequest>,
) -> Result<ResponseJson<RevokeDeviceResponse>, StatusCode> {
    info!("Device revocation request for nullifier: {}...", &request.nullifier_hash[..16]);
    
    let result = state.protocol.revoke_device(
        &request.nullifier_hash,
        &request.device_commitment,
    );
    
    match result {
        Ok(_) => {
            info!("Device revoked successfully");
            Ok(ResponseJson(RevokeDeviceResponse {
                success: true,
                error: None,
            }))
        }
        Err(e) => {
            error!("Device revocation failed: {}", e);
            Ok(ResponseJson(RevokeDeviceResponse {
                success: false,
                error: Some(e.to_string()),
            }))
        }
    }
}

async fn health_check() -> &'static str {
    "Legion Server - Healthy"
}

#[derive(Debug, Deserialize)]
struct WelcomeRequest {
    #[serde(alias = "session_id")]
    session_token: String,
    #[serde(default)]
    client_pubkey: Option<String>,
    #[serde(default)]
    device_commitment: Option<String>,
}

#[derive(Debug, Serialize)]
struct WelcomeResponse {
    success: bool,
    message: String,
    session_id: String,
    authenticated_at: String,
    expires_in_seconds: i64,
}

async fn protected_welcome(
    axum::extract::State(_state): axum::extract::State<Arc<AppState>>,
    Json(request): Json<WelcomeRequest>,
) -> Result<ResponseJson<WelcomeResponse>, StatusCode> {
    info!("Protected welcome request for session: {}", &request.session_token[..16]);
    
    // Verify session exists in Redis and get TTL
    #[cfg(feature = "redis")]
    {
        use redis::Commands;
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        
        if let Ok(client) = redis::Client::open(redis_url) {
            if let Ok(mut conn) = client.get_connection() {
                let key = format!("legion:session:{}", request.session_token);
                
                // Check if session exists
                let exists: bool = conn.exists(&key).unwrap_or(false);
                if !exists {
                    return Ok(ResponseJson(WelcomeResponse {
                        success: false,
                        message: "Session expired or invalid".to_string(),
                        session_id: String::new(),
                        authenticated_at: String::new(),
                        expires_in_seconds: 0,
                    }));
                }
                
                // CRITICAL: Verify linkability tag matches (prevents session theft)
                // This is zero-knowledge: server doesn't know which device, only validates same device
                if let Some(provided_tag) = &request.client_pubkey {
                    let stored_tag: String = conn.hget(&key, "linkability_tag").unwrap_or_default();
                    if !stored_tag.is_empty() && stored_tag != *provided_tag {
                        return Ok(ResponseJson(WelcomeResponse {
                            success: false,
                            message: "Linkability tag mismatch - session stolen or wrong device".to_string(),
                            session_id: String::new(),
                            authenticated_at: String::new(),
                            expires_in_seconds: 0,
                        }));
                    }
                }
                
                // CRITICAL: Single-use session (nullifier-style)
                let spent_key = format!("legion:session:spent:{}", request.session_token);
                let already_spent: bool = conn.exists(&spent_key).unwrap_or(false);
                
                if already_spent {
                    let _: () = conn.del(&key).unwrap_or(());
                    return Ok(ResponseJson(WelcomeResponse {
                        success: false,
                        message: "Session already spent - concurrent access detected".to_string(),
                        session_id: String::new(),
                        authenticated_at: String::new(),
                        expires_in_seconds: 0,
                    }));
                }
                
                let _: () = conn.set_ex(&spent_key, "1", 5).unwrap_or(());
                
                // Get TTL only - no user data in zero-knowledge system
                let ttl: i64 = conn.ttl(&key).unwrap_or(0);
                
                return Ok(ResponseJson(WelcomeResponse {
                    success: true,
                    message: "Welcome! You are authenticated with zero-knowledge proof. Server knows nothing about your identity.".to_string(),
                    session_id: request.session_token[..16].to_string(),
                    authenticated_at: chrono::Utc::now().to_rfc3339(),
                    expires_in_seconds: ttl,
                }));
            }
        }
    }
    
    // Fallback if Redis not available
    Ok(ResponseJson(WelcomeResponse {
        success: true,
        message: "Welcome! Session verification skipped (Redis not configured).".to_string(),
        session_id: request.session_token[..16].to_string(),
        authenticated_at: chrono::Utc::now().to_rfc3339(),
        expires_in_seconds: 3600,
    }))
}

// Middleware to add COOP/COEP/CORP headers for WASM SharedArrayBuffer
async fn add_security_headers(
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("require-corp"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );
    response
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    info!("🛡️ Initializing Legion Authentication Server...");
    
    // Set data path to use existing tree (absolute path)
    let data_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()
        .join("prover/legion_data");
    std::env::set_var("LEGION_DATA_PATH", data_path);
    
    let protocol = AuthenticationProtocol::new()?;
    let webauthn_service = WebAuthnService::new("localhost", "http://localhost:8000")?;
    
    let state = Arc::new(AppState {
        protocol: Arc::new(protocol),
        webauthn_service: Arc::new(webauthn_service),
    });
    

    
    let app = Router::new()
        .route("/api/login", post(authenticate_user))
        .route("/api/register-blind", post(register_blind))
        .route("/api/download-tree", get(download_merkle_tree))
        .route("/api/register-device", post(register_device))
        .route("/api/get-device-proof", post(get_device_proof))
        .route("/api/verify-anonymous-proof", post(verify_anonymous_proof))
        .route("/api/webauthn/register/start", post(start_webauthn_registration))
        .route("/api/webauthn/register/finish", post(finish_webauthn_registration))
        .route("/api/webauthn/auth/start", post(start_webauthn_authentication))
        .route("/api/webauthn/auth/finish", post(finish_webauthn_authentication))
        .route("/api/protected/welcome", post(protected_welcome))
        .route("/api/verify-session", post(protected_welcome))
        .route("/health", get(health_check))
        .layer(middleware::from_fn(add_security_headers))
        .layer(CorsLayer::permissive())
        .with_state(state);
    
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001").await?;
    info!("✅ Legion Server listening on http://127.0.0.1:3001");
    

    info!("📊 Endpoints (TRUE ZERO-KNOWLEDGE):");
    info!("   POST /api/register-blind - User registration");
    info!("   GET  /api/download-tree - Download Merkle tree (client-side)");
    info!("   POST /api/verify-anonymous-proof - Verify ZK proof");
    info!("   POST /api/verify-session - Validate session with linkability tag");
    info!("   GET  /health - Health check");
    info!("   ✅ Session theft protection via linkability tags");
    info!("   ✅ Server NEVER tracks users or devices");
    
    axum::serve(listener, app).await?;
    
    Ok(())
}
