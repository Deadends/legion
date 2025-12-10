use crate::{
    config::Config,
    error::{Result, SidecarError},
    stage_a::{StageAFilter, TicketRequest, MockKeyProvider},
    stage_b::{StageBVerifier, ProofRequest},
    tls::TlsConfig,
};
use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
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
pub struct SidecarState {
    pub stage_a: Arc<StageAFilter>,
    pub stage_b: Arc<StageBVerifier>,
    pub config: Config,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageARequest {
    pub client_id: String,
    pub ticket: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageAResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageBRequest {
    pub proofs: Vec<ProofRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StageBResponse {
    pub batch_id: u64,
    pub results: Vec<ProofVerificationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofVerificationResult {
    pub client_id: String,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct SidecarServer {
    config: Config,
    state: SidecarState,
}

impl SidecarServer {
    pub async fn new() -> Result<Self> {
        let config = Config::load()?;
        config.validate()?;

        info!("Initializing Legion Sidecar");
        info!("  - Host: {}:{}", config.server.host, config.server.port);
        info!("  - TLS: enabled");
        info!("  - Stage A: HMAC ticket validation + replay filter");
        info!("  - Stage B: ZK proof verifier pool (size: {})", config.zk.verifier_pool_size);

        let key_provider = Arc::new(MockKeyProvider::new());
        let stage_a = Arc::new(StageAFilter::new(key_provider));
        let stage_b = Arc::new(StageBVerifier::new(16, config.zk.verifier_pool_size)?);

        let state = SidecarState {
            stage_a,
            stage_b,
            config: config.clone(),
        };

        Ok(Self { config, state })
    }

    pub async fn run(self) -> Result<()> {
        let app = self.create_router();

        let addr: SocketAddr = format!("{}:{}", self.config.server.host, self.config.server.port)
            .parse()
            .map_err(|e| SidecarError::Config(anyhow::anyhow!("Invalid address: {}", e)))?;

        info!("Loading TLS configuration");
        let tls_config = TlsConfig::new()?;

        info!("Starting Legion Sidecar on https://{}", addr);
        info!("Press Ctrl+C to shutdown");

        let listener = tokio::net::TcpListener::bind(addr).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_config.server_config);

        loop {
            tokio::select! {
                conn_result = listener.accept() => {
                    match conn_result {
                        Ok((tcp_stream, remote_addr)) => {
                            let tls_acceptor = acceptor.clone();
                            let tower_service = app.clone();

                            tokio::spawn(async move {
                                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                    Ok(stream) => stream,
                                    Err(err) => {
                                        error!("TLS handshake failed from {}: {}", remote_addr, err);
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
                                    error!("Connection error from {}: {}", remote_addr, err);
                                }
                            });
                        }
                        Err(err) => {
                            error!("Failed to accept connection: {}", err);
                        }
                    }
                }
                _ = shutdown_signal() => {
                    info!("Shutdown signal received, stopping server");
                    break;
                }
            }
        }

        info!("Legion Sidecar stopped");
        Ok(())
    }

    fn create_router(&self) -> Router {
        Router::new()
            .route("/health", get(health_handler))
            .route("/stage-a", post(stage_a_handler))
            .route("/stage-b", post(stage_b_handler))
            .route("/metrics", get(metrics_handler))
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
            .with_state(self.state.clone())
    }
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "legion-sidecar",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn stage_a_handler(
    State(state): State<SidecarState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<StageARequest>,
) -> Result<Json<StageAResponse>, (StatusCode, String)> {
    info!("Stage A request from {} for client {}", addr.ip(), request.client_id);

    let ticket_req = TicketRequest {
        client_id: request.client_id.clone(),
        ticket: request.ticket,
        timestamp: request.timestamp,
    };

    let response = state.stage_a.verify_ticket(ticket_req);

    if response.status == "rejected" {
        warn!("Stage A rejected for client {} from {}", request.client_id, addr.ip());
        return Err((
            StatusCode::UNAUTHORIZED,
            response.error.unwrap_or_else(|| "Ticket validation failed".to_string()),
        ));
    }

    info!("Stage A passed for client {}", request.client_id);

    Ok(Json(StageAResponse {
        status: "ok".to_string(),
        error: None,
        session_token: Some(format!("session_{}", uuid::Uuid::new_v4())),
    }))
}

async fn stage_b_handler(
    State(state): State<SidecarState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<StageBRequest>,
) -> Result<Json<StageBResponse>, (StatusCode, String)> {
    info!("Stage B request from {} with {} proofs", addr.ip(), request.proofs.len());

    if request.proofs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty proof batch".to_string()));
    }

    if request.proofs.len() > 32 {
        return Err((StatusCode::BAD_REQUEST, "Batch size exceeds limit of 32".to_string()));
    }

    match state.stage_b.verify_batch(request.proofs).await {
        Ok(batch_response) => {
            let verified_count = batch_response.results.iter().filter(|r| r.verified).count();
            info!("Stage B completed: {}/{} proofs verified", verified_count, batch_response.results.len());

            let results = batch_response
                .results
                .into_iter()
                .map(|r| ProofVerificationResult {
                    client_id: r.client_id,
                    verified: r.verified,
                    error: r.error,
                })
                .collect();

            Ok(Json(StageBResponse {
                batch_id: batch_response.batch_id,
                results,
            }))
        }
        Err(e) => {
            error!("Stage B verification error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

async fn metrics_handler(State(state): State<SidecarState>) -> Json<serde_json::Value> {
    let (queue_len, batch_count) = state.stage_b.get_stats();

    Json(serde_json::json!({
        "stage_a": {
            "ticket_ttl_secs": state.config.auth.ticket_ttl_secs,
            "rate_limit_per_sec": state.config.auth.rate_limit_per_sec
        },
        "stage_b": {
            "queue_length": queue_len,
            "batch_count": batch_count,
            "pool_size": state.config.zk.verifier_pool_size
        },
        "server": {
            "max_connections": state.config.server.max_connections,
            "request_timeout_secs": state.config.server.request_timeout_secs
        }
    }))
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
            info!("Received Ctrl+C");
        },
        _ = terminate => {
            info!("Received SIGTERM");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sidecar_initialization() {
        let server = SidecarServer::new().await;
        assert!(server.is_ok());
    }
}
