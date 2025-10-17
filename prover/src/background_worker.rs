// Background worker for Nova proof generation
use anyhow::Result;
use std::sync::{Arc, Mutex};

#[cfg(feature = "redis")]
use redis::{Commands, Connection};

pub struct BackgroundWorker {
    #[cfg(feature = "redis")]
    conn: Arc<Mutex<Option<Connection>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl BackgroundWorker {
    pub fn new() -> Result<Self> {
        #[cfg(feature = "redis")]
        {
            let redis_url =
                std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

            let conn_opt = match redis::Client::open(redis_url) {
                Ok(client) => client.get_connection().ok(),
                Err(_) => None,
            };

            Ok(Self {
                conn: Arc::new(Mutex::new(conn_opt)),
                running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })
        }

        #[cfg(not(feature = "redis"))]
        Ok(Self {
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    pub fn start(&self) -> Result<()> {
        #[cfg(feature = "redis")]
        {
            if self.conn.lock().unwrap().is_none() {
                println!("⚠️  Redis not available, background worker disabled");
                return Ok(());
            }

            self.running
                .store(true, std::sync::atomic::Ordering::SeqCst);

            let running_clone = self.running.clone();
            let conn_clone = self.conn.clone();

            println!("🔄 Background worker started");

            std::thread::spawn(move || {
                while running_clone.load(std::sync::atomic::Ordering::SeqCst) {
                    match Self::process_queue_static(&conn_clone) {
                        Ok(count) if count > 0 => {
                            println!("✅ Processed {} Nova tasks", count);
                        }
                        Err(e) => {
                            eprintln!("❌ Background worker error: {}", e);
                        }
                        _ => {}
                    }

                    std::thread::sleep(std::time::Duration::from_secs(5));
                }

                println!("🛑 Background worker stopped");
            });
        }

        Ok(())
    }

    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[cfg(feature = "redis")]
    fn process_queue_static(conn_arc: &Arc<Mutex<Option<Connection>>>) -> Result<usize> {
        let mut processed = 0;
        let mut conn_guard = conn_arc.lock().unwrap();

        if let Some(conn) = conn_guard.as_mut() {
            for _ in 0..10 {
                match conn.lpop::<_, Option<String>>("nova:queue", None) {
                    Ok(Some(task)) => {
                        let parts: Vec<&str> = task.split(':').collect();
                        if parts.len() == 3 {
                            let user_hash = parts[0];
                            let username = hex::decode(parts[1]).unwrap_or_default();
                            let password = hex::decode(parts[2]).unwrap_or_default();

                            println!("🔄 Generating Nova proof for user {}", &user_hash[..8]);

                            if let Ok(proof) = Self::generate_proof_static(&username, &password) {
                                let key = format!("nova:proof:{}", user_hash);
                                let _: () = conn.set_ex(&key, &proof, 86400)?;
                                println!("✅ Nova proof cached for {}", &user_hash[..8]);
                                processed += 1;
                            }
                        }
                    }
                    _ => break,
                }
            }
        }

        Ok(processed)
    }

    #[cfg(not(feature = "redis"))]
    fn process_queue_static(_conn_arc: &Arc<Mutex<Option<()>>>) -> Result<usize> {
        Ok(0)
    }

    #[cfg(feature = "nova")]
    fn generate_proof_static(username: &[u8], password: &[u8]) -> Result<Vec<u8>> {
        use crate::nova_accumulator::run_legion_nova_auth;
        use pasta_curves::Fp;

        run_legion_nova_auth(
            username,
            password,
            Fp::from(42u64),
            Fp::from(crate::get_timestamp()),
            3,
        )
    }

    #[cfg(not(feature = "nova"))]
    fn generate_proof_static(_username: &[u8], _password: &[u8]) -> Result<Vec<u8>> {
        Err(anyhow::anyhow!("Nova not enabled"))
    }
}

impl Drop for BackgroundWorker {
    fn drop(&mut self) {
        self.stop();
    }
}
