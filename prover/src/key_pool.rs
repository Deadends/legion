// Pre-generated key pool for instant key access
use anyhow::Result;

#[cfg(feature = "redis")]
use redis::{Commands, Connection};

pub struct KeyPool {
    #[cfg(feature = "redis")]
    conn: Option<Connection>,
}

impl KeyPool {
    pub fn new() -> Result<Self> {
        #[cfg(feature = "redis")]
        {
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

            match redis::Client::open(redis_url) {
                Ok(client) => match client.get_connection() {
                    Ok(conn) => {
                        let mut pool = Self { conn: Some(conn) };
                        pool.ensure_pool_filled()?;
                        Ok(pool)
                    }
                    Err(_) => Ok(Self { conn: None }),
                },
                Err(_) => Ok(Self { conn: None }),
            }
        }
        #[cfg(not(feature = "redis"))]
        Ok(Self {})
    }

    pub fn pop_key(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                if let Ok(Some(data)) = conn.lpop::<_, Option<Vec<u8>>>("keypool:ml_dsa", None) {
                    if data.len() >= 64 {
                        let sk = data[..32].to_vec();
                        let pk = data[32..64].to_vec();

                        // Async refill if pool is low
                        if let Ok(len) = conn.llen::<_, usize>("keypool:ml_dsa") {
                            if len < 10 {
                                self.refill_pool()?;
                            }
                        }

                        return Ok(Some((sk, pk)));
                    }
                }
            }
        }
        Ok(None)
    }

    fn ensure_pool_filled(&mut self) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                let len: usize = conn.llen("keypool:ml_dsa").unwrap_or(0);
                if len < 10 {
                    self.refill_pool()?;
                }
            }
        }
        Ok(())
    }

    fn refill_pool(&mut self) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                for _ in 0..20 {
                    let mut sk = [0u8; 32];
                    let mut pk = [0u8; 32];
                    crate::fill_random_bytes(&mut sk)?;
                    crate::fill_random_bytes(&mut pk)?;

                    let mut key_pair = Vec::with_capacity(64);
                    key_pair.extend_from_slice(&sk);
                    key_pair.extend_from_slice(&pk);

                    let _: () = conn.rpush("keypool:ml_dsa", key_pair)?;
                }
            }
        }
        Ok(())
    }
}
