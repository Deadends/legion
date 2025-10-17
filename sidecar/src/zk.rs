use crate::{
    config::ZkConfig,
    error::{Result, SidecarError},
    types::{ZkProofRequest, ZkProofResponse},
};
use crossbeam_channel::{bounded, Receiver, Sender};
use parking_lot::Mutex;
use rayon::ThreadPoolBuilder;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ProofJob {
    pub id: Uuid,
    pub request: ZkProofRequest,
    pub submitted_at: Instant,
    pub response_sender: tokio::sync::oneshot::Sender<ZkProofResponse>,
}

pub struct ZkManager {
    config: ZkConfig,
    job_queue: Sender<ProofJob>,
    active_jobs: Arc<Mutex<HashMap<Uuid, Instant>>>,
    thread_pool: rayon::ThreadPool,
}

impl ZkManager {
    pub fn new(config: ZkConfig) -> Result<Self> {
        let (job_sender, job_receiver) = bounded(config.queue_capacity);
        
        let thread_pool = ThreadPoolBuilder::new()
            .num_threads(config.verifier_pool_size)
            .thread_name(|i| format!("zk-verifier-{}", i))
            .build()
            .map_err(|e| SidecarError::Internal(format!("Failed to create thread pool: {}", e)))?;
        
        let active_jobs = Arc::new(Mutex::new(HashMap::new()));
        
        let manager = Self {
            config: config.clone(),
            job_queue: job_sender,
            active_jobs: active_jobs.clone(),
            thread_pool,
        };
        
        // Start verifier workers
        manager.start_verifier_workers(job_receiver, active_jobs);
        
        // Start cleanup task
        manager.start_cleanup_task();
        
        info!("ZK Manager initialized with {} verifiers", config.verifier_pool_size);
        
        Ok(manager)
    }
    
    pub async fn verify_proof(&self, request: ZkProofRequest) -> Result<ZkProofResponse> {
        let job_id = Uuid::new_v4();
        let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
        
        let job = ProofJob {
            id: job_id,
            request,
            submitted_at: Instant::now(),
            response_sender,
        };
        
        // Add to active jobs tracking
        self.active_jobs.lock().insert(job_id, job.submitted_at);
        
        // Submit to queue
        self.job_queue.send(job)
            .map_err(|_| SidecarError::Internal("ZK verification queue full".to_string()))?;
        
        debug!("ZK proof job {} submitted to queue", job_id);
        
        // Wait for response with timeout
        let timeout = Duration::from_secs(self.config.proof_timeout_secs);
        
        match tokio::time::timeout(timeout, response_receiver).await {
            Ok(Ok(response)) => {
                self.active_jobs.lock().remove(&job_id);
                Ok(response)
            }
            Ok(Err(_)) => {
                self.active_jobs.lock().remove(&job_id);
                Err(SidecarError::Internal("Verifier response channel closed".to_string()))
            }
            Err(_) => {
                self.active_jobs.lock().remove(&job_id);
                warn!("ZK proof verification timeout for job {}", job_id);
                Ok(ZkProofResponse {
                    verified: false,
                    proof_id: None,
                    error: Some("Verification timeout".to_string()),
                })
            }
        }
    }
    
    fn start_verifier_workers(&self, job_receiver: Receiver<ProofJob>, active_jobs: Arc<Mutex<HashMap<Uuid, Instant>>>) {
        let receiver = Arc::new(job_receiver);
        let pool = self.thread_pool.clone();
        
        for worker_id in 0..self.config.verifier_pool_size {
            let receiver = receiver.clone();
            let active_jobs = active_jobs.clone();
            
            pool.spawn(move || {
                info!("ZK verifier worker {} started", worker_id);
                
                while let Ok(job) = receiver.recv() {
                    debug!("Worker {} processing job {}", worker_id, job.id);
                    
                    let response = Self::process_proof_job(&job);
                    
                    if let Err(_) = job.response_sender.send(response) {
                        warn!("Failed to send response for job {}", job.id);
                    }
                    
                    active_jobs.lock().remove(&job.id);
                }
                
                info!("ZK verifier worker {} stopped", worker_id);
            });
        }
    }
    
    fn process_proof_job(job: &ProofJob) -> ZkProofResponse {
        let start_time = Instant::now();
        
        // Simulate ZK proof verification
        // In production, this would integrate with your actual ZK circuit verification
        let verification_result = Self::verify_zk_proof(&job.request);
        
        let duration = start_time.elapsed();
        debug!("ZK proof {} verification completed in {:?}", job.id, duration);
        
        match verification_result {
            Ok(verified) => ZkProofResponse {
                verified,
                proof_id: if verified { Some(job.id) } else { None },
                error: None,
            },
            Err(e) => {
                error!("ZK proof verification error for job {}: {}", job.id, e);
                ZkProofResponse {
                    verified: false,
                    proof_id: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }
    
    fn verify_zk_proof(request: &ZkProofRequest) -> Result<bool> {
        // Basic validation
        if request.proof_data.is_empty() {
            return Err(SidecarError::ZkVerification("Empty proof data".to_string()));
        }
        
        if request.public_inputs.is_empty() {
            return Err(SidecarError::ZkVerification("No public inputs provided".to_string()));
        }
        
        // Validate circuit ID
        match request.circuit_id.as_str() {
            "auth_circuit" | "merkle_circuit" | "nullifier_circuit" => {
                // Circuit-specific verification logic would go here
                // For now, we'll do basic proof structure validation
                
                // Check proof size (example: expecting at least 256 bytes for a valid proof)
                if request.proof_data.len() < 256 {
                    return Ok(false);
                }
                
                // Validate public inputs format
                for input in &request.public_inputs {
                    if input.is_empty() || input.len() > 64 {
                        return Ok(false);
                    }
                }
                
                // Simulate computation-heavy verification
                let verification_hash = blake3::hash(&request.proof_data);
                let input_hash = blake3::hash(&request.public_inputs.join("").as_bytes());
                
                // Simple verification: check if proof and inputs have valid relationship
                let combined = [verification_hash.as_bytes(), input_hash.as_bytes()].concat();
                let final_hash = blake3::hash(&combined);
                
                // Accept proof if hash has certain properties (simulation)
                Ok(final_hash.as_bytes()[0] % 4 != 0) // ~75% success rate for testing
            }
            _ => Err(SidecarError::ZkVerification(format!("Unknown circuit ID: {}", request.circuit_id))),
        }
    }
    
    fn start_cleanup_task(&self) {
        let active_jobs = self.active_jobs.clone();
        let timeout_secs = self.config.proof_timeout_secs;
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let cutoff = Instant::now() - Duration::from_secs(timeout_secs);
                let mut jobs = active_jobs.lock();
                let initial_count = jobs.len();
                
                jobs.retain(|_, submitted_at| *submitted_at > cutoff);
                
                let cleaned = initial_count - jobs.len();
                if cleaned > 0 {
                    warn!("Cleaned {} timed-out ZK proof jobs", cleaned);
                }
            }
        });
    }
    
    pub fn get_queue_stats(&self) -> (usize, usize) {
        let active_count = self.active_jobs.lock().len();
        let queue_len = self.job_queue.len();
        (active_count, queue_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZkProofRequest;
    
    #[tokio::test]
    async fn test_zk_manager_creation() {
        let config = ZkConfig {
            verifier_pool_size: 2,
            queue_capacity: 100,
            proof_timeout_secs: 30,
            batch_size: 10,
        };
        
        let zk_manager = ZkManager::new(config);
        assert!(zk_manager.is_ok());
    }
    
    #[tokio::test]
    async fn test_proof_verification() {
        let config = ZkConfig {
            verifier_pool_size: 1,
            queue_capacity: 10,
            proof_timeout_secs: 5,
            batch_size: 1,
        };
        
        let zk_manager = ZkManager::new(config).unwrap();
        
        let request = ZkProofRequest {
            session_id: Uuid::new_v4(),
            proof_data: vec![0u8; 512], // Valid size
            public_inputs: vec!["input1".to_string(), "input2".to_string()],
            circuit_id: "auth_circuit".to_string(),
        };
        
        let response = zk_manager.verify_proof(request).await;
        assert!(response.is_ok());
    }
}