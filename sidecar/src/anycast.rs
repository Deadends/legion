use crate::{
    sharding::{ShardRouter, RouteDecision},
    bls_multisig::{AdmissionToken, BlsCommittee, RevocationList},
    error::{Result, SidecarError},
};
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRequest {
    pub client_pubkey: [u8; 32],
    pub domain: String,
    pub admission_token: Option<AdmissionToken>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingResponse {
    pub status: String,
    pub shard_id: Option<u32>,
    pub redirect_nodes: Option<Vec<SocketAddr>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnycastNode {
    pub shard_router: Arc<ShardRouter>,
    pub committee: Arc<BlsCommittee>,
    pub revocation_list: Arc<RwLock<RevocationList>>,
}

impl AnycastNode {
    pub fn new(
        shard_router: Arc<ShardRouter>,
        committee: Arc<BlsCommittee>,
    ) -> Self {
        Self {
            shard_router,
            committee,
            revocation_list: Arc::new(RwLock::new(RevocationList::new())),
        }
    }

    pub async fn route_request(&self, request: RoutingRequest) -> Result<RoutingResponse> {
        // Validate admission token for high-priority flows
        if let Some(token) = &request.admission_token {
            if !self.validate_admission_token(token).await? {
                return Ok(RoutingResponse {
                    status: "rejected".to_string(),
                    shard_id: None,
                    redirect_nodes: None,
                    error: Some("Invalid admission token".to_string()),
                });
            }
        }

        // Determine routing decision
        let route_decision = self.shard_router.route_request(&request.client_pubkey, &request.domain)?;

        match route_decision {
            RouteDecision::ProcessLocally => {
                debug!("Processing request locally for client: {:?}", hex::encode(request.client_pubkey));
                Ok(RoutingResponse {
                    status: "process_locally".to_string(),
                    shard_id: Some(self.shard_router.config.local_shard_id),
                    redirect_nodes: None,
                    error: None,
                })
            }
            RouteDecision::ForwardTo { shard_id, nodes } => {
                info!("Forwarding request to shard {} with {} nodes", shard_id, nodes.len());
                Ok(RoutingResponse {
                    status: "redirect".to_string(),
                    shard_id: Some(shard_id),
                    redirect_nodes: Some(nodes),
                    error: None,
                })
            }
        }
    }

    async fn validate_admission_token(&self, token: &AdmissionToken) -> Result<bool> {
        let revocation_list = self.revocation_list.read().await;
        let revocation_root = revocation_list.merkle_root;
        drop(revocation_list);

        self.committee.verify_token(token, &revocation_root)
    }

    pub async fn revoke_token(&self, token_nonce: [u8; 32]) -> Result<()> {
        let mut revocation_list = self.revocation_list.write().await;
        revocation_list.revoke_token(token_nonce);
        info!("Token revoked: {}", hex::encode(token_nonce));
        Ok(())
    }

    pub fn create_router(&self) -> Router<Arc<Self>> {
        Router::new()
            .route("/route", post(handle_routing))
            .route("/issue-token", post(handle_token_issuance))
            .route("/revoke-token", post(handle_token_revocation))
    }
}

async fn handle_routing(
    State(anycast): State<Arc<AnycastNode>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<RoutingRequest>,
) -> Result<Json<RoutingResponse>, (StatusCode, String)> {
    debug!("Routing request from {}", addr);

    match anycast.route_request(request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            warn!("Routing error: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[derive(Debug, Deserialize)]
struct TokenIssuanceRequest {
    client_pubkey: [u8; 32],
    domain: String,
    ttl_secs: u64,
}

async fn handle_token_issuance(
    State(anycast): State<Arc<AnycastNode>>,
    Json(request): Json<TokenIssuanceRequest>,
) -> Result<Json<AdmissionToken>, (StatusCode, String)> {
    match anycast.committee.issue_token(request.client_pubkey, request.domain, request.ttl_secs) {
        Ok(token) => {
            info!("Issued admission token for client: {}", hex::encode(request.client_pubkey));
            Ok(Json(token))
        }
        Err(e) => {
            warn!("Token issuance failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[derive(Debug, Deserialize)]
struct TokenRevocationRequest {
    token_nonce: [u8; 32],
}

async fn handle_token_revocation(
    State(anycast): State<Arc<AnycastNode>>,
    Json(request): Json<TokenRevocationRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match anycast.revoke_token(request.token_nonce).await {
        Ok(_) => Ok(Json(serde_json::json!({"status": "revoked"}))),
        Err(e) => {
            warn!("Token revocation failed: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharding::{ShardConfig, ShardRouter};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_anycast_routing() {
        let mut shard_nodes = HashMap::new();
        shard_nodes.insert(0, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000)]);
        shard_nodes.insert(1, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001)]);

        let shard_config = ShardConfig {
            shard_count: 2,
            shard_nodes,
            local_shard_id: 0,
        };

        let shard_router = Arc::new(ShardRouter::new(shard_config));
        let committee = Arc::new(BlsCommittee::new_2_of_3());
        let anycast = AnycastNode::new(shard_router, committee);

        let request = RoutingRequest {
            client_pubkey: [1u8; 32],
            domain: "test.com".to_string(),
            admission_token: None,
            payload: vec![1, 2, 3, 4],
        };

        let response = anycast.route_request(request).await.unwrap();
        assert!(response.status == "process_locally" || response.status == "redirect");
    }

    #[tokio::test]
    async fn test_token_validation() {
        let mut shard_nodes = HashMap::new();
        shard_nodes.insert(0, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000)]);

        let shard_config = ShardConfig {
            shard_count: 1,
            shard_nodes,
            local_shard_id: 0,
        };

        let shard_router = Arc::new(ShardRouter::new(shard_config));
        let committee = Arc::new(BlsCommittee::new_2_of_3());
        let anycast = AnycastNode::new(shard_router, committee.clone());

        // Issue a token
        let token = committee.issue_token([1u8; 32], "test.com".to_string(), 3600).unwrap();

        // Validate token
        let is_valid = anycast.validate_admission_token(&token).await.unwrap();
        assert!(is_valid);

        // Revoke token
        anycast.revoke_token(token.nonce).await.unwrap();

        // Token should now be invalid
        let is_valid_after_revocation = anycast.validate_admission_token(&token).await.unwrap();
        assert!(!is_valid_after_revocation);
    }
}