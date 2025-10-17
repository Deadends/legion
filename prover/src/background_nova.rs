// Background Nova proof generation for refresh tokens
use anyhow::Result;

#[cfg(feature = "nova")]
use pasta_curves::Fp;

#[cfg(feature = "redis")]
use redis::{Commands, Connection};

pub struct BackgroundNova {
    #[cfg(feature = "redis")]
    conn: Option<Connection>,
}

impl BackgroundNova {
    pub fn new() -> Result<Self> {
        #[cfg(feature = "redis")]
        {
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

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

    pub fn queue_nova_generation(
        &mut self,
        user_hash: &str,
        username: &[u8],
        password: &[u8],
    ) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                let task = format!(
                    "{}:{}:{}",
                    user_hash,
                    hex::encode(username),
                    hex::encode(password)
                );
                let _: () = conn.rpush("nova:queue", task)?;
            }
        }
        Ok(())
    }

    pub fn get_cached_nova_proof(&mut self, user_hash: &str) -> Result<Option<Vec<u8>>> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                let key = format!("nova:proof:{}", user_hash);
                if let Ok(data) = conn.get::<_, Vec<u8>>(&key) {
                    return Ok(Some(data));
                }
            }
        }
        Ok(None)
    }

    pub fn store_nova_proof(&mut self, user_hash: &str, proof: &[u8]) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                let key = format!("nova:proof:{}", user_hash);
                let _: () = conn.set_ex(&key, proof, 86400)?; // 24h TTL
            }
        }
        Ok(())
    }

    #[cfg(feature = "nova")]
    pub fn process_queue(&mut self) -> Result<usize> {
        let mut processed = 0;

        #[cfg(feature = "redis")]
        {
            if let Some(conn) = &mut self.conn {
                while let Ok(Some(task)) = conn.lpop::<_, Option<String>>("nova:queue", None) {
                    let parts: Vec<&str> = task.split(':').collect();
                    if parts.len() == 3 {
                        let user_hash = parts[0].to_string();
                        let username = hex::decode(parts[1]).unwrap_or_default();
                        let password = hex::decode(parts[2]).unwrap_or_default();

                        // Generate proof without borrowing self
                        if let Ok(proof) = Self::generate_nova_proof_static(&username, &password) {
                            // Store after generation
                            let key = format!("nova:proof:{}", user_hash);
                            let _: () = conn.set_ex(&key, &proof, 86400)?;
                            processed += 1;
                        }
                    }
                }
            }
        }

        Ok(processed)
    }

    #[cfg(feature = "nova")]
    fn generate_nova_proof_static(username: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        use crate::nova_accumulator::run_legion_nova_auth;

        run_legion_nova_auth(
            username,
            password,
            Fp::from(42u64),
            Fp::from(crate::get_timestamp()),
            3,
        )
    }
}
