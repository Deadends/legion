mod tls;
mod tickets;
mod replay;
mod session;
mod security;

// Use existing security system

use axum::{
    body::Bytes,
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{Json, Response},
    routing::{get, post},
    Router,
};


use serde_json::json;
use std::net::SocketAddr;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::tls::TlsConfig;
use crate::tickets::{parse_and_validate_ticket, get_ticket_skew_seconds};
use crate::replay::{create_redis_pool, check_replay_with_bloom, ReplayProtection};
use crate::session::issue_token;
use crate::security::{initialize_security, SecurityConfig, KeyProviderType, SecurityLevel, SecurityManager};
use tower::Service;
use deadpool_redis::Pool as RedisPool;
use std::sync::Arc;
use anyhow::Context;





async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "legion-sidecar",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn stage_a_handler(
    body: Bytes,
    redis_pool: Arc<RedisPool>,
    replay_protection: Arc<ReplayProtection>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let skew_seconds = get_ticket_skew_seconds();
    
    // Parse and validate CBOR ticket
    let ticket = match parse_and_validate_ticket(&body, skew_seconds) {
        Ok(ticket) => ticket,
        Err(e) => {
            tracing::warn!("Ticket validation failed: {}", e);
            return Err(StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::BAD_REQUEST));
        }
    };
    
    // Check for replay attacks
    let ttl_seconds = 3600; // 1 hour TTL
    match check_replay_with_bloom(&redis_pool, &replay_protection, &ticket.client_id, &ticket.nonce, ttl_seconds).await {
        Ok(is_replay) => {
            if is_replay {
                tracing::warn!("Replay attack detected for client: {}", ticket.client_id);
                return Err(StatusCode::FORBIDDEN);
            }
        }
        Err(e) => {
            tracing::error!("Replay check failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    
    // TODO: HMAC verification would go here
    
    Ok(Json(json!({
        "status": "success",
        "client_id": ticket.client_id,
        "nonce_len": ticket.nonce.len(),
        "timestamp": ticket.ts,
        "next_stage": "stage_b"
    })))
}

async fn mtls_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract client certificate info if mTLS is enabled
    // This would be populated by rustls during TLS handshake
    let response = next.run(request).await;
    Ok(response)
}

#[derive(Clone)]
struct AppState {
    redis_pool: Arc<RedisPool>,
    replay_protection: Arc<ReplayProtection>,
    security_manager: Arc<SecurityManager>,
}

async fn stage_a_handler_with_state(
    axum::extract::State(state): axum::extract::State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    stage_a_handler(body, state.redis_pool, state.replay_protection).await
}

async fn stage_b_handler_with_state(
    axum::extract::State(state): axum::extract::State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    stage_b_handler(body, state.security_manager).await
}

async fn stage_b_handler(
    body: Bytes,
    security_manager: Arc<SecurityManager>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Parse ZK proof (simplified for now)
    let proof_data: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let client_id = proof_data["client_id"].as_str()
        .ok_or(StatusCode::BAD_REQUEST)?;
    
    // Mock proof hash for demonstration
    let proof_hash = [0xAB; 32]; // In reality, this would be computed from the ZK proof
    
    // Issue session token after successful ZK verification
    let token = issue_token(
        security_manager,
        proof_hash,
        client_id,
        "legion-service",
        3600, // 1 hour expiry
    ).await.map_err(|e| {
        tracing::error!("Failed to issue token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    
    Ok(Json(json!({
        "token": token,
        "token_type": "PASETO-V4-PUBLIC"
    })))
}

fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/", get(|| async { "Legion Sidecar" }))
        .route("/stage-a", post(stage_a_handler_with_state))
        .route("/stage-b", post(stage_b_handler_with_state))
        .layer(middleware::from_fn(mtls_middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "legion_sidecar=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Legion Sidecar");

    // Initialize Redis pool
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());
    let redis_pool = Arc::new(create_redis_pool(&redis_url)
        .context("Failed to create Redis pool")?);
    
    // Initialize replay protection
    let replay_protection = Arc::new(ReplayProtection::new());
    
    info!("Redis pool and replay protection initialized");

    // Load TLS configuration
    let tls_config = match TlsConfig::new() {
        Ok(config) => {
            info!("TLS enabled");
            Some(config)
        }
        Err(e) => {
            warn!("TLS disabled: {}", e);
            None
        }
    };

    // Initialize security system
    let key_provider_type = match std::env::var("KEY_PROVIDER_TYPE").as_deref() {
        Ok("vault") => KeyProviderType::Vault {
            addr: std::env::var("VAULT_ADDR").unwrap_or_else(|_| "http://localhost:8200".to_string()),
            token: std::env::var("VAULT_TOKEN").unwrap_or_else(|_| "dev-token".to_string()),
        },
        _ => KeyProviderType::File,
    };
    
    let security_config = SecurityConfig {
        key_provider_type,
        audit_enabled: true,
        security_level: SecurityLevel::Production,
    };
    
    let security_manager = initialize_security(security_config).await
        .context("Failed to initialize security system")?;
    
    let app_state = AppState {
        redis_pool: redis_pool.clone(),
        replay_protection: replay_protection.clone(),
        security_manager,
    };
    let app = create_app(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));

    if let Some(tls_config) = tls_config {
        // HTTPS server with proper axum 0.7 + hyper 1.0 compatibility
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.server_config);
        let listener = tokio::net::TcpListener::bind(addr).await?;
        
        info!("Starting HTTPS server on {}", addr);
        
        loop {
            tokio::select! {
                conn_result = listener.accept() => {
                    match conn_result {
                        Ok((tcp_stream, _remote_addr)) => {
                            let tls_acceptor = acceptor.clone();
                            let tower_service = app.clone();
                            
                            tokio::spawn(async move {
                                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                    Ok(tls_stream) => tls_stream,
                                    Err(err) => {
                                        tracing::error!("failed to perform tls handshake: {err:#}");
                                        return;
                                    }
                                };
                                
                                let hyper_service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                                    tower_service.clone().call(request)
                                });
                                
                                if let Err(err) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                                    .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                                    .await
                                {
                                    tracing::error!("failed to serve connection: {err:#}");
                                }
                            });
                        }
                        Err(err) => {
                            tracing::error!("failed to accept connection: {err:#}");
                        }
                    }
                }
                _ = shutdown_signal() => {
                    info!("Graceful shutdown initiated");
                    break;
                }
            }
        }
    } else {
        // HTTP fallback
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!("Starting HTTP server on {}", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await?;
    }

    info!("Server shutdown complete");
    Ok(())
}