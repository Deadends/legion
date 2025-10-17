use deadpool_redis::{Pool as RedisPool, Connection};
use bloomfilter::Bloom;
use std::sync::{Arc, Mutex};
use prometheus::{Counter, register_counter};
use thiserror::Error;
use tracing::{warn, debug};

#[derive(Error, Debug)]
pub enum ReplayError {
    #[error("Redis pool error: {0}")]
    Pool(#[from] deadpool_redis::PoolError),
    #[error("Redis error: {0}")]
    Redis(#[from] deadpool_redis::redis::RedisError),
}

lazy_static::lazy_static! {
    static ref REDIS_HITS: Counter = register_counter!(
        "legion_redis_nonce_store_hits_total",
        "Total Redis nonce store hits (duplicates found)"
    ).unwrap();
    
    static ref REDIS_MISSES: Counter = register_counter!(
        "legion_redis_nonce_store_misses_total", 
        "Total Redis nonce store misses (new nonces)"
    ).unwrap();
    
    static ref BLOOM_FP: Counter = register_counter!(
        "legion_bloom_filter_fp_count_total",
        "Total Bloom filter false positives"
    ).unwrap();
}

pub struct ReplayProtection {
    bloom_filter: Arc<Mutex<Bloom<Vec<u8>>>>,
}

impl ReplayProtection {
    pub fn new() -> Self {
        let bloom = Bloom::new_for_fp_rate(1_000_000, 0.001);
        Self {
            bloom_filter: Arc::new(Mutex::new(bloom)),
        }
    }

    pub fn fast_precheck(&self, nonce: &[u8]) -> bool {
        let nonce_vec = nonce.to_vec();
        let mut bloom = self.bloom_filter.lock().unwrap();
        if bloom.check(&nonce_vec) {
            true // Maybe seen
        } else {
            bloom.set(&nonce_vec);
            false // Definitely not seen
        }
    }
}

pub async fn seen_nonce(
    redis_pool: &RedisPool,
    client_id: &str,
    nonce: &[u8],
    ttl_seconds: u64,
) -> Result<bool, ReplayError> {
    let key = format!("legion:replay:{}:{}", client_id, hex::encode(nonce));
    let mut conn: Connection = redis_pool.get().await?;
    
    // Atomic SET NX EX command
    let result: Option<String> = deadpool_redis::redis::cmd("SET")
        .arg(&key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ttl_seconds)
        .query_async(&mut *conn)
        .await?;
    
    match result {
        Some(_) => {
            debug!("Nonce stored: {}:{}", client_id, hex::encode(nonce));
            REDIS_MISSES.inc();
            Ok(false) // Not seen before
        }
        None => {
            warn!("Replay detected: {}:{}", client_id, hex::encode(nonce));
            REDIS_HITS.inc();
            Ok(true) // Already exists (replay)
        }
    }
}

pub async fn check_replay_with_bloom(
    redis_pool: &RedisPool,
    replay_protection: &ReplayProtection,
    client_id: &str,
    nonce: &[u8],
    ttl_seconds: u64,
) -> Result<bool, ReplayError> {
    if !replay_protection.fast_precheck(nonce) {
        // Bloom says definitely not seen
        return seen_nonce(redis_pool, client_id, nonce, ttl_seconds).await;
    }
    
    // Bloom says maybe seen - check Redis
    let is_replay = seen_nonce(redis_pool, client_id, nonce, ttl_seconds).await?;
    
    if !is_replay {
        BLOOM_FP.inc();
        debug!("Bloom false positive: {}", hex::encode(nonce));
    }
    
    Ok(is_replay)
}

pub fn create_redis_pool(redis_url: &str) -> Result<RedisPool, deadpool_redis::CreatePoolError> {
    let cfg = deadpool_redis::Config::from_url(redis_url);
    cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter() {
        let replay = ReplayProtection::new();
        let nonce1 = b"test_nonce_1";
        let nonce2 = b"test_nonce_2";
        
        assert!(!replay.fast_precheck(nonce1));
        assert!(replay.fast_precheck(nonce1));
        assert!(!replay.fast_precheck(nonce2));
    }
}