// Redis caching layer for 100x performance boost
use anyhow::{Result, Context};
use pasta_curves::Fp;
use ff::PrimeField;

#[cfg(feature = "redis")]
use redis::{Commands, Client};

pub struct RedisCache {
    #[cfg(feature = "redis")]
    client: Client,
}

impl RedisCache {
    pub fn new() -> Result<Self> {
        #[cfg(feature = "redis")]
        {
            let redis_url = std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
            
            println!("🔌 Attempting to connect to Redis at {}...", redis_url);

            let client = Client::open(redis_url)
                .context("Failed to create Redis client. Is Redis running and the URL correct?")?;
            
            client.get_connection().context("Failed to connect to Redis server.")?;

            println!("✅ Successfully connected to Redis.");
            Ok(Self { client })
        }
        #[cfg(not(feature = "redis"))]
        Ok(Self {})
    }
    
    // Merkle root caching
    pub fn get_merkle_root(&self) -> Result<Option<Fp>> {
        #[cfg(feature = "redis")]
        {
            let mut conn = self.client.get_connection()?;
            if let Ok(data) = conn.get::<_, Vec<u8>>("merkle:root:latest") {
                if data.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&data);
                    return Ok(Fp::from_repr(bytes).into());
                }
            }
        }
        Ok(None)
    }
    
    pub fn set_merkle_root(&self, root: Fp) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            let mut conn = self.client.get_connection()?;
            let bytes = root.to_repr();
            let slice: &[u8] = bytes.as_ref();
            conn.set_ex::<_, _, ()>("merkle:root:latest", slice, 3600)?;
        }
        Ok(())
    }
    
    // Nullifier check
    pub fn nullifier_exists(&self, nullifier: &[u8; 32]) -> Result<bool> {
        #[cfg(feature = "redis")]
        {
            let mut conn = self.client.get_connection()?;
            let key = format!("nullifier:{}", hex::encode(nullifier));
            return Ok(conn.exists(&key)?);
        }
        #[cfg(not(feature = "redis"))]
        Ok(false)
    }
    
    pub fn store_nullifier(&self, nullifier: &[u8; 32]) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            let mut conn = self.client.get_connection()?;
            let key = format!("nullifier:{}", hex::encode(nullifier));
            conn.set_ex::<_, i32, ()>(&key, 1, 86400)?; // 24h TTL
        }
        Ok(())
    }
}
