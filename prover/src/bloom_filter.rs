// Bloom filter for fast nullifier checks (1ms vs 200ms)
use anyhow::Result;

#[cfg(feature = "redis")]
use redis::{Commands, Connection};

const BLOOM_SIZE: usize = 10000;
const HASH_COUNT: usize = 3;

pub struct BloomFilter {
    #[cfg(feature = "redis")]
    conn: Option<Connection>,
}

impl BloomFilter {
    pub fn new() -> Result<Self> {
        #[cfg(feature = "redis")]
        {
            let redis_url = std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
            
            match redis::Client::open(redis_url) {
                Ok(client) => match client.get_connection() {
                    Ok(conn) => Ok(Self { conn: Some(conn) }),
                    Err(_) => Ok(Self { conn: None }),
                },
                Err(_) => Ok(Self { conn: None }),
            }
        }
        #[cfg(not(feature = "redis"))]
        Ok(Self {})
    }
    
    pub fn check(&mut self, nullifier: &[u8; 32]) -> Result<bool> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                for i in 0..HASH_COUNT {
                    let bit_pos = Self::hash(nullifier, i) % BLOOM_SIZE;
                    let exists: bool = conn.getbit("bloom:nullifiers", bit_pos)?;
                    if !exists {
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }
    
    pub fn add(&mut self, nullifier: &[u8; 32]) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                for i in 0..HASH_COUNT {
                    let bit_pos = Self::hash(nullifier, i) % BLOOM_SIZE;
                    let _: () = conn.setbit("bloom:nullifiers", bit_pos, true)?;
                }
            }
        }
        Ok(())
    }
    
    fn hash(data: &[u8; 32], seed: usize) -> usize {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&seed.to_le_bytes());
        hasher.update(data);
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();
        usize::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3], 0, 0, 0, 0])
    }
}
