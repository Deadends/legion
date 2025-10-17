use crate::{
    auth::AuthManager,
    config::Config,
    error::{Result, SidecarError},
    tls::TlsManager,
    tls_binding::{server_export_binding_rustls, tls_binding_field, ServerNonce},
    types::{SidecarRequest, SidecarResponse, AuthRequest, ZkProofRequest, SessionNonceRequest, SessionNonceResponse},
    zk::ZkManager,
    stage_a::{StageAFilter, TicketRequest, MockKeyProvider},
    stage_b::{StageBVerifier, ProofRequest, BatchVerifyResponse},
};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use dashmap::DashMap;
use axum_server::tls_rustls::RustlsConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
};
use tracing::{info, warn, error, Level};

#[derive(Clone)]
pub struct AppState {
    pub auth_manager: Arc<AuthManager>,
    pub zk_manager: Arc<ZkManager>,
    pub stage_a_filter: Arc<StageAFilter>,
    pub stage_b_verifier: Arc<StageBVerifier>,
    pub config: Config,
    pub session_nonces: Arc<DashMap<String, ServerNonce>>,
}

pub struct SidecarServer {
    config: Config,
    app_state: AppState,
    tls_config: RustlsConfig,
}

impl SidecarServer {
    pub async fn new(config: Config) -> Result<Self> {
        // Validate configuration
        config.validate()?;
        
        // Initialize TLS
        let tls_manager = TlsManager::new(&config.tls)?;
        let tls_config = RustlsConfig::from_config(tls_manager.server_config());
        
        // Initialize managers
        let auth_manager = Arc::new(AuthManager::new(config.auth.clone())?);
        let zk_manager = Arc::new(ZkManager::new(config.zk.clone())?);
        let key_provider = Arc::new(MockKeyProvider::new());
        let stage_a_filter = Arc::new(StageAFilter::new(key_provider));
        let stage_b_verifier = Arc::new(StageBVerifier::new(16, config.zk.verifier_pool_size)?);
        
        let app_state = AppState {
            auth_manager,
            zk_manager,
            stage_a_filter,
            stage_b_verifier,
            config: config.clone(),
            session_nonces: Arc::new(DashMap::new()),
        };
        
        Ok(Self {
            config,
            app_state,
            tls_config,
        })
    }
    
    pub async fn run(self) -> Result<()> {
        let app = self.create_app();
        
        let addr = SocketAddr::new(
            self.config.server.host.parse()
                .map_err(|e| SidecarError::Config(anyhow::anyhow!("Invalid host: {}", e)))?,
            self.config.server.port,
        );
        
        info!("Starting Legion Sidecar server on https://{}", addr);
        
        // Start server with graceful shutdown
        axum_server::bind_rustls(addr, self.tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| SidecarError::Internal(format!("Server error: {}", e)))?;
        
        info!("Legion Sidecar server stopped");
        Ok(())
    }
    
    fn create_app(&self) -> Router {
        Router::new()
            .route("/stage-a", post(handle_stage_a))
            .route("/stage-b", post(handle_stage_b))
            .route("/auth", post(handle_auth))
            .route("/zk-proof", post(handle_zk_proof))
            .route("/session-nonce", post(handle_session_nonce))
            .route("/health", axum::routing::get(handle_health))
            .route("/metrics", axum::routing::get(handle_metrics))
            .layer(
                ServiceBuilder::new()
                    .layer(
                        TraceLayer::new_for_http()
                            .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                            .on_request(DefaultOnRequest::new().level(Level::INFO))
                            .on_response(DefaultOnResponse::new().level(Level::INFO)),
                    )
                    .layer(CorsLayer::permissive())
                    .timeout(Duration::from_secs(self.config.server.request_timeout_secs))
                    .into_inner(),
            )
            .with_state(self.app_state.clone())
    }
}

async fn handle_stage_a(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<TicketRequest>,
) -> Result<Json<crate::stage_a::StageAResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&addr, &HeaderMap::new());
    
    tracing::info!("Stage A ticket verification from {} for client {}", client_ip, request.client_id);
    
    // TODO: Extract TLS binding from connection and include in admission workflow
    // This would require access to the TLS stream which isn't directly available in axum handlers
    // For now, we proceed with existing verification
    
    let response = state.stage_a_filter.verify_ticket(request);
    
    if response.status == "rejected" {
        return Err((StatusCode::UNAUTHORIZED, response.error.unwrap_or_default()));
    }
    
    Ok(Json(response))
}

async fn handle_stage_b(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(proofs): Json<Vec<ProofRequest>>,
) -> Result<Json<BatchVerifyResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&addr, &HeaderMap::new());
    
    tracing::info!("Stage B batch verification from {} with {} proofs", client_ip, proofs.len());
    
    if proofs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty proof batch".to_string()));
    }
    
    if proofs.len() > 32 {
        return Err((StatusCode::BAD_REQUEST, "Batch size exceeds limit of 32".to_string()));
    }
    
    match state.stage_b_verifier.verify_batch(proofs).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Stage B verification error: {}", e);
            Err((StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))
        }
    }
}

async fn handle_auth(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AuthRequest>,
) -> Result<Json<SidecarResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&addr, &headers);
    
    tracing::info!("Auth request from {}", client_ip);
    
    match state.auth_manager.authenticate(request, client_ip).await {
        Ok(response) => Ok(Json(SidecarResponse::Auth(response))),
        Err(e) => {
            error!("Authentication error: {}", e);
            Err((StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))
        }
    }
}

async fn handle_zk_proof(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<ZkProofRequest>,
) -> Result<Json<SidecarResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&addr, &HeaderMap::new());
    
    tracing::info!("ZK proof request from {} for session {}", client_ip, request.session_id);
    
    // Validate session
    if !state.auth_manager.validate_session(&request.session_id) {
        warn!("Invalid session {} from {}", request.session_id, client_ip);
        return Err((StatusCode::UNAUTHORIZED, "Invalid session".to_string()));
    }
    
    match state.zk_manager.verify_proof(request).await {
        Ok(response) => Ok(Json(SidecarResponse::ZkProof(response))),
        Err(e) => {
            error!("ZK proof verification error: {}", e);
            Err((StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))
        }
    }
}

async fn handle_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "legion-sidecar"
    }))
}

async fn handle_session_nonce(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<SessionNonceRequest>,
) -> Result<Json<SessionNonceResponse>, (StatusCode, String)> {
    let client_ip = extract_client_ip(&addr, &HeaderMap::new());
    
    tracing::info!("Session nonce request from {} for client {}", client_ip, request.client_id);
    
    // Clean up expired nonces
    state.session_nonces.retain(|_, nonce| !nonce.is_expired());
    
    // Generate new server nonce with 2-minute TTL
    let server_nonce = ServerNonce::new(120);
    let nonce_id = uuid::Uuid::new_v4().to_string();
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() + 120;
    
    let hex_nonce = hex::encode(server_nonce.nonce);
    state.session_nonces.insert(nonce_id, server_nonce);
    
    Ok(Json(SessionNonceResponse {
        server_nonce: hex_nonce,
        expires_at,
    }))
}

async fn handle_metrics(State(state): State<AppState>) -> Json<serde_json::Value> {
    let (active_proofs, queue_length) = state.zk_manager.get_queue_stats();
    
    Json(serde_json::json!({
        "zk_verifier": {
            "active_proofs": active_proofs,
            "queue_length": queue_length,
            "pool_size": state.config.zk.verifier_pool_size
        },
        "stage_b": {
            "queue_length": state.stage_b_verifier.get_stats().0,
            "batch_count": state.stage_b_verifier.get_stats().1
        },
        "auth": {
            "rate_limit_per_sec": state.config.auth.rate_limit_per_sec,
            "ticket_ttl_secs": state.config.auth.ticket_ttl_secs
        },
        "server": {
            "max_connections": state.config.server.max_connections,
            "request_timeout_secs": state.config.server.request_timeout_secs
        },
        "session_nonces": {
            "active_count": state.session_nonces.len()
        }
    }))
}

fn extract_client_ip(addr: &SocketAddr, headers: &HeaderMap) -> String {
    // Check for forwarded headers first
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }
    
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(real_ip_str) = real_ip.to_str() {
            return real_ip_str.to_string();
        }
    }
    
    // Fall back to connection IP
    match addr.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down gracefully");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_extract_client_ip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
        let headers = HeaderMap::new();
        
        let ip = extract_client_ip(&addr, &headers);
        assert_eq!(ip, "192.168.1.100");
    }
    
    #[test]
    fn test_extract_forwarded_ip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.1, 192.168.1.1".parse().unwrap());
        
        let ip = extract_client_ip(&addr, &headers);
        assert_eq!(ip, "203.0.113.1");
    }
}