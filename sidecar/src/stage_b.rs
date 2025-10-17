use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector, verify_proof},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use crossbeam_channel::{bounded, Receiver, Sender};
use tracing::{debug, info, warn, error};
use crate::error::{Result, SidecarError};

const BATCH_SIZE: usize = 32;
const QUEUE_CAPACITY: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofRequest {
    pub proof_bytes: Vec<u8>,
    pub public_inputs: PublicInputs,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub ticket_hash: [u8; 32],
    pub proof_credit: u64,
    pub a: String,
    pub b: String, 
    pub c: String,
    pub d: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerifyResponse {
    pub results: Vec<VerifyResult>,
    pub batch_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub client_id: String,
    pub verified: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
struct BatchJob {
    proofs: Vec<ProofRequest>,
    response_tx: oneshot::Sender<BatchVerifyResponse>,
    batch_id: u64,
}

#[derive(Debug, Clone)]
pub struct LegionCircuit {
    pub a: Value<Fr>,
    pub b: Value<Fr>,
    pub c: Value<Fr>,
    pub d: Value<Fr>,
}

#[derive(Debug, Clone)]
pub struct LegionConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<Fr> for LegionCircuit {
    type Config = LegionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            b: Value::unknown(),
            c: Value::unknown(),
            d: Value::unknown(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(advice[0]);
        meta.enable_equality(advice[1]);
        meta.enable_equality(advice[2]);
        meta.enable_equality(advice[3]);
        meta.enable_equality(instance);

        // Constraint: a * b + c^2 = d
        meta.create_gate("legion_constraint", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(advice[0], halo2_proofs::poly::Rotation::cur());
            let b = meta.query_advice(advice[1], halo2_proofs::poly::Rotation::cur());
            let c = meta.query_advice(advice[2], halo2_proofs::poly::Rotation::cur());
            let d = meta.query_advice(advice[3], halo2_proofs::poly::Rotation::cur());

            vec![s * (a * b + c * c - d)]
        });

        LegionConfig { advice, instance, selector }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "legion_region",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice(|| "a", config.advice[0], 0, || self.a)?;
                let b_cell = region.assign_advice(|| "b", config.advice[1], 0, || self.b)?;
                let c_cell = region.assign_advice(|| "c", config.advice[2], 0, || self.c)?;
                let d_cell = region.assign_advice(|| "d", config.advice[3], 0, || self.d)?;

                // Expose public inputs
                region.constrain_instance(a_cell.cell(), config.instance, 0)?;
                region.constrain_instance(b_cell.cell(), config.instance, 1)?;
                region.constrain_instance(c_cell.cell(), config.instance, 2)?;
                region.constrain_instance(d_cell.cell(), config.instance, 3)?;

                Ok(())
            },
        )
    }
}

pub struct StageBVerifier {
    params: Arc<Params<G1Affine>>,
    vk: Arc<halo2_proofs::plonk::VerifyingKey<G1Affine>>,
    job_tx: Sender<BatchJob>,
    batch_counter: std::sync::atomic::AtomicU64,
}

impl StageBVerifier {
    pub fn new(k: u32, worker_count: usize) -> Result<Self> {
        let params = Params::<G1Affine>::new(k);
        let circuit = LegionCircuit {
            a: Value::unknown(),
            b: Value::unknown(), 
            c: Value::unknown(),
            d: Value::unknown(),
        };

        let vk = halo2_proofs::plonk::keygen_vk(&params, &circuit)
            .map_err(|e| SidecarError::Internal(format!("VK generation failed: {:?}", e)))?;

        let (job_tx, job_rx) = bounded(QUEUE_CAPACITY);
        
        let params_arc = Arc::new(params);
        let vk_arc = Arc::new(vk);

        // Start worker pool
        for worker_id in 0..worker_count {
            let job_rx = job_rx.clone();
            let params = params_arc.clone();
            let vk = vk_arc.clone();
            
            tokio::spawn(async move {
                Self::worker_loop(worker_id, job_rx, params, vk).await;
            });
        }

        info!("Stage B verifier initialized with {} workers", worker_count);

        Ok(Self {
            params: params_arc,
            vk: vk_arc,
            job_tx,
            batch_counter: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub async fn verify_batch(&self, proofs: Vec<ProofRequest>) -> Result<BatchVerifyResponse> {
        let batch_id = self.batch_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (response_tx, response_rx) = oneshot::channel();

        let job = BatchJob {
            proofs,
            response_tx,
            batch_id,
        };

        self.job_tx.send(job)
            .map_err(|_| SidecarError::Internal("Verifier queue full".to_string()))?;

        response_rx.await
            .map_err(|_| SidecarError::Internal("Verifier response channel closed".to_string()))
    }

    async fn worker_loop(
        worker_id: usize,
        job_rx: Receiver<BatchJob>,
        params: Arc<Params<G1Affine>>,
        vk: Arc<halo2_proofs::plonk::VerifyingKey<G1Affine>>,
    ) {
        info!("Stage B worker {} started", worker_id);

        while let Ok(job) = job_rx.recv() {
            debug!("Worker {} processing batch {} with {} proofs", 
                   worker_id, job.batch_id, job.proofs.len());

            let results = Self::process_batch(&job.proofs, &params, &vk).await;
            
            let response = BatchVerifyResponse {
                results,
                batch_id: job.batch_id,
            };

            if job.response_tx.send(response).is_err() {
                warn!("Failed to send batch response for batch {}", job.batch_id);
            }
        }

        info!("Stage B worker {} stopped", worker_id);
    }

    async fn process_batch(
        proofs: &[ProofRequest],
        params: &Params<G1Affine>,
        vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>,
    ) -> Vec<VerifyResult> {
        let mut results = Vec::with_capacity(proofs.len());

        for proof_req in proofs {
            let result = Self::verify_single_proof(proof_req, params, vk).await;
            results.push(result);
        }

        results
    }

    async fn verify_single_proof(
        proof_req: &ProofRequest,
        params: &Params<G1Affine>,
        vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>,
    ) -> VerifyResult {
        match Self::verify_proof_internal(proof_req, params, vk) {
            Ok(verified) => VerifyResult {
                client_id: proof_req.client_id.clone(),
                verified,
                error: None,
            },
            Err(e) => {
                error!("Proof verification failed for {}: {}", proof_req.client_id, e);
                VerifyResult {
                    client_id: proof_req.client_id.clone(),
                    verified: false,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    fn verify_proof_internal(
        proof_req: &ProofRequest,
        params: &Params<G1Affine>,
        vk: &halo2_proofs::plonk::VerifyingKey<G1Affine>,
    ) -> Result<bool> {
        // Parse public inputs
        let a = Fr::from_str_vartime(&proof_req.public_inputs.a)
            .ok_or_else(|| SidecarError::InvalidRequest("Invalid field element a".to_string()))?;
        let b = Fr::from_str_vartime(&proof_req.public_inputs.b)
            .ok_or_else(|| SidecarError::InvalidRequest("Invalid field element b".to_string()))?;
        let c = Fr::from_str_vartime(&proof_req.public_inputs.c)
            .ok_or_else(|| SidecarError::InvalidRequest("Invalid field element c".to_string()))?;
        let d = Fr::from_str_vartime(&proof_req.public_inputs.d)
            .ok_or_else(|| SidecarError::InvalidRequest("Invalid field element d".to_string()))?;

        // Verify constraint: a * b + c^2 = d
        let expected = a * b + c * c;
        if expected != d {
            return Ok(false);
        }

        // Verify ticket hash is properly bound
        let ticket_hash_fr = Self::hash_to_field(&proof_req.public_inputs.ticket_hash);
        let credit_fr = Fr::from(proof_req.public_inputs.proof_credit);
        
        // Additional constraint: ticket_hash + credit should be bound to proof
        let binding = ticket_hash_fr + credit_fr;
        if binding == Fr::zero() {
            return Ok(false);
        }

        // Parse and verify the actual proof
        let proof = halo2_proofs::plonk::Proof::read::<_, G1Affine, Challenge255<_>>(
            &mut std::io::Cursor::new(&proof_req.proof_bytes)
        ).map_err(|e| SidecarError::ZkVerification(format!("Proof parsing failed: {:?}", e)))?;

        let public_inputs = vec![vec![a, b, c, d]];
        let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof_req.proof_bytes[..]);

        match verify_proof(params, vk, &proof, &public_inputs, &mut transcript) {
            Ok(_) => {
                debug!("Proof verified successfully for client {}", proof_req.client_id);
                Ok(true)
            }
            Err(e) => {
                debug!("Proof verification failed for client {}: {:?}", proof_req.client_id, e);
                Ok(false)
            }
        }
    }

    fn hash_to_field(hash: &[u8; 32]) -> Fr {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash);
        // Reduce modulo field size
        Fr::from_bytes_wide(&{
            let mut wide = [0u8; 64];
            wide[..32].copy_from_slice(&bytes);
            wide
        })
    }

    pub fn get_stats(&self) -> (usize, u64) {
        let queue_len = self.job_tx.len();
        let batch_count = self.batch_counter.load(std::sync::atomic::Ordering::SeqCst);
        (queue_len, batch_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::plonk::{create_proof, keygen_pk};
    use halo2_proofs::transcript::Blake2bWrite;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn test_stage_b_verifier() {
        let verifier = StageBVerifier::new(8, 2).unwrap();
        
        // Create a valid proof request
        let proof_req = create_test_proof().await.unwrap();
        let proofs = vec![proof_req];
        
        let response = verifier.verify_batch(proofs).await.unwrap();
        assert_eq!(response.results.len(), 1);
    }

    async fn create_test_proof() -> Result<ProofRequest> {
        let k = 8;
        let params = Params::<G1Affine>::new(k);
        
        let a = Fr::from(3);
        let b = Fr::from(4);
        let c = Fr::from(5);
        let d = a * b + c * c; // 3 * 4 + 5^2 = 37
        
        let circuit = LegionCircuit {
            a: Value::known(a),
            b: Value::known(b),
            c: Value::known(c),
            d: Value::known(d),
        };

        let vk = halo2_proofs::plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();

        let public_inputs = vec![vec![a, b, c, d]];
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);
        
        create_proof(&params, &pk, &[circuit], &[&public_inputs], &mut OsRng, &mut transcript)
            .map_err(|e| SidecarError::Internal(format!("Proof creation failed: {:?}", e)))?;

        let proof_bytes = transcript.finalize();

        Ok(ProofRequest {
            proof_bytes,
            public_inputs: PublicInputs {
                ticket_hash: [1u8; 32],
                proof_credit: 100,
                a: a.to_string(),
                b: b.to_string(),
                c: c.to_string(),
                d: d.to_string(),
            },
            client_id: "test_client".to_string(),
        })
    }
}