use crate::{
    anycast::AnycastNode,
    bls_multisig::BlsCommittee,
    sharding::{ShardConfig, ShardRouter},
    stage_a::StageAFilter,
    stage_b::StageBVerifier,
    config::Config,
    error::Result,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, Level};

#[derive(Clone)]
pub struct ScalableAppState {
    pub anycast_node: Arc<AnycastNode>,
    pub stage_a_filter: Arc<StageAFilter>,
    pub stage_b_verifier: Arc<StageBVerifier>,
    pub config: Config,
}

pub struct ScalableServer {
    config: Config,
    app_state: ScalableAppState,
}

impl ScalableServer {
    pub async fn new(config: Config, shard_config: ShardConfig) -> Result<Self> {
        // Initialize sharding
        let shard_router = Arc::new(ShardRouter::new(shard_config));
        
        // Initialize BLS committee
        let committee = Arc::new(BlsCommittee::new_2_of_3());
        
        // Initialize anycast node
        let anycast_node = Arc::new(AnycastNode::new(shard_router, committee));
        
        // Initialize existing components
        let key_provider = Arc::new(crate::stage_a::MockKeyProvider::new());
        let stage_a_filter = Arc::new(StageAFilter::new(key_provider));
        let stage_b_verifier = Arc::new(StageBVerifier::new(16, config.zk.verifier_pool_size)?);
        
        let app_state = ScalableAppState {
            anycast_node,
            stage_a_filter,
            stage_b_verifier,
            config: config.clone(),
        };
        
        Ok(Self { config, app_state })
    }

    pub async fn run(self) -> Result<()> {
        let app = self.create_app();
        
        let addr = SocketAddr::new(
            self.config.server.host.parse()?,
            self.config.server.port,
        );
        
        info!("Starting Legion Scalable Server on https://{}", addr);
        info!("Shard ID: {}", self.app_state.anycast_node.shard_router.config.local_shard_id);
        
        axum::Server::bind(&addr)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown_signal())
            .await?;
        
        info!("Legion Scalable Server stopped");
        Ok(())
    }

    fn create_app(&self) -> Router {
        Router::new()
            // Anycast routing endpoints
            .route("/route", post(crate::anycast::handle_routing))
            .route("/issue-token", post(crate::anycast::handle_token_issuance))
            .route("/revoke-token", post(crate::anycast::handle_token_revocation))
            
            // Existing Stage A/B endpoints
            .route("/stage-a", post(handle_stage_a))
            .route("/stage-b", post(handle_stage_b))
            
            // Management endpoints
            .route("/health", get(handle_health))
            .route("/metrics", get(handle_metrics))
            .route("/shard-info", get(handle_shard_info))
            
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http().make_span_with(
                        tower_http::trace::DefaultMakeSpan::new().level(Level::INFO)
                    ))
                    .layer(CorsLayer::permissive())
                    .into_inner(),
            )
            .with_state(self.app_state.clone())
    }
}

async fn handle_stage_a(
    State(state): State<ScalableAppState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    Json(request): Json<crate::stage_a::TicketRequest>,
) -> Result<Json<crate::stage_a::StageAResponse>, (StatusCode, String)> {
    let client_ip = format!("{}", addr.ip());
    
    // Check if request should be processed locally
    let client_pubkey = blake3::hash(request.client_id.as_bytes()).into();
    if !state.anycast_node.shard_router.is_local_shard(&client_pubkey, "default") {
        return Err((StatusCode::BAD_REQUEST, "Request routed to wrong shard".to_string()));
    }
    
    let response = state.stage_a_filter.verify_ticket(request);
    
    if response.status == "rejected" {
        return Err((StatusCode::UNAUTHORIZED, response.error.unwrap_or_default()));
    }
    
    Ok(Json(response))
}

async fn handle_stage_b(
    State(state): State<ScalableAppState>,
    Json(proofs): Json<Vec<crate::stage_b::ProofRequest>>,
) -> Result<Json<crate::stage_b::BatchVerifyResponse>, (StatusCode, String)> {
    if proofs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty proof batch".to_string()));
    }
    
    // Verify all proofs belong to this shard
    for proof in &proofs {
        let client_pubkey = blake3::hash(proof.client_id.as_bytes()).into();
        if !state.anycast_node.shard_router.is_local_shard(&client_pubkey, "default") {
            return Err((StatusCode::BAD_REQUEST, "Proof routed to wrong shard".to_string()));
        }
    }
    
    match state.stage_b_verifier.verify_batch(proofs).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

async fn handle_health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "legion-scalable-sidecar"
    }))
}

async fn handle_metrics(State(state): State<ScalableAppState>) -> Json<serde_json::Value> {
    let (stage_b_queue, stage_b_batches) = state.stage_b_verifier.get_stats();
    
    Json(json!({
        "shard": {
            "id": state.anycast_node.shard_router.config.local_shard_id,
            "total_shards": state.anycast_node.shard_router.config.shard_count
        },
        "stage_b": {
            "queue_length": stage_b_queue,
            "batch_count": stage_b_batches
        },
        "committee": {
            "threshold": state.anycast_node.committee.threshold,
            "total_nodes": state.anycast_node.committee.total_nodes
        }
    }))
}

async fn handle_shard_info(State(state): State<ScalableAppState>) -> Json<serde_json::Value> {
    let shard_router = &state.anycast_node.shard_router;
    
    Json(json!({
        "local_shard_id": shard_router.config.local_shard_id,
        "total_shards": shard_router.config.shard_count,
        "shard_nodes": shard_router.config.shard_nodes
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
            info!("Received Ctrl+C, shutting down gracefully");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully");
        },
    }
}