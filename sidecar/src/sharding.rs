use blake3;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use crate::error::{Result, SidecarError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardConfig {
    pub shard_count: u32,
    pub shard_nodes: HashMap<u32, Vec<SocketAddr>>,
    pub local_shard_id: u32,
}

#[derive(Debug, Clone)]
pub struct ShardRouter {
    config: ShardConfig,
}

impl ShardRouter {
    pub fn new(config: ShardConfig) -> Self {
        Self { config }
    }

    pub fn get_shard_id(&self, client_pubkey: &[u8], domain: &str) -> u32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(client_pubkey);
        hasher.update(domain.as_bytes());
        let hash = hasher.finalize();
        
        let hash_u64 = u64::from_le_bytes([
            hash.as_bytes()[0], hash.as_bytes()[1], hash.as_bytes()[2], hash.as_bytes()[3],
            hash.as_bytes()[4], hash.as_bytes()[5], hash.as_bytes()[6], hash.as_bytes()[7],
        ]);
        
        (hash_u64 % self.config.shard_count as u64) as u32
    }

    pub fn is_local_shard(&self, client_pubkey: &[u8], domain: &str) -> bool {
        self.get_shard_id(client_pubkey, domain) == self.config.local_shard_id
    }

    pub fn get_shard_nodes(&self, shard_id: u32) -> Option<&Vec<SocketAddr>> {
        self.config.shard_nodes.get(&shard_id)
    }

    pub fn route_request(&self, client_pubkey: &[u8], domain: &str) -> Result<RouteDecision> {
        let shard_id = self.get_shard_id(client_pubkey, domain);
        
        if shard_id == self.config.local_shard_id {
            Ok(RouteDecision::ProcessLocally)
        } else {
            let nodes = self.get_shard_nodes(shard_id)
                .ok_or_else(|| SidecarError::Internal(format!("No nodes for shard {}", shard_id)))?;
            
            Ok(RouteDecision::ForwardTo {
                shard_id,
                nodes: nodes.clone(),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub enum RouteDecision {
    ProcessLocally,
    ForwardTo {
        shard_id: u32,
        nodes: Vec<SocketAddr>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_deterministic_sharding() {
        let mut shard_nodes = HashMap::new();
        shard_nodes.insert(0, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8000)]);
        shard_nodes.insert(1, vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8001)]);
        
        let config = ShardConfig {
            shard_count: 2,
            shard_nodes,
            local_shard_id: 0,
        };
        
        let router = ShardRouter::new(config);
        
        let client_pubkey = b"test_client_pubkey_12345678901234567890";
        let domain = "example.com";
        
        // Same inputs should always map to same shard
        let shard1 = router.get_shard_id(client_pubkey, domain);
        let shard2 = router.get_shard_id(client_pubkey, domain);
        assert_eq!(shard1, shard2);
        
        // Different inputs should potentially map to different shards
        let shard3 = router.get_shard_id(b"different_client_pubkey_1234567890123", domain);
        // Note: May be same shard due to hash collision, but deterministic
    }
}