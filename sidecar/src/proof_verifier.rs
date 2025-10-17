use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use halo2curves::pasta::{Fp, EqAffine};
use legion_prover::WorldClassAuthCircuit;
use anyhow::{Result, Context};
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    #[error("Parameter error: {0}")]
    ParameterError(#[from] anyhow::Error),
    #[error("Internal verification error: {0}")]
    InternalError(String),
    #[error("Transcript error: malformed proof data")]
    TranscriptError,
}

pub struct ProofVerifier {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}

impl ProofVerifier {
    pub fn new(k: u32) -> Result<Self, VerifyError> {
        let params = Params::<EqAffine>::new(k);
        let empty_circuit = WorldClassAuthCircuit::default();
        let vk = halo2_proofs::plonk::keygen_vk(&params, &empty_circuit)
            .map_err(|e| VerifyError::ParameterError(anyhow::anyhow!("Keygen failed: {}", e)))?;
        
        debug!("Initialized proof verifier with k={}", k);
        Ok(Self { params, vk })
    }
    
    pub fn verify_proof(&self, proof: &[u8], public_inputs: &[Fp]) -> Result<(), VerifyError> {
        if proof.is_empty() {
            return Err(VerifyError::InvalidProof("Empty proof".to_string()));
        }
        
        if public_inputs.is_empty() {
            return Err(VerifyError::InvalidProof("No public inputs provided".to_string()));
        }
        
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        let instance_slice = &public_inputs[..];
        let instances = &[instance_slice];
        
        match verify_proof(
            &self.params,
            &self.vk,
            halo2_proofs::plonk::SingleVerifier::new(&self.params),
            &[instances],
            &mut transcript,
        ) {
            Ok(()) => {
                debug!("Proof verification succeeded");
                Ok(())
            },
            Err(e) => {
                let error_msg = format!("Proof verification failed: {}", e);
                warn!("{}", error_msg);
                
                // Categorize the error based on the error type
                if error_msg.contains("transcript") || error_msg.contains("malformed") {
                    Err(VerifyError::TranscriptError)
                } else if error_msg.contains("parameter") || error_msg.contains("setup") {
                    Err(VerifyError::ParameterError(anyhow::anyhow!(error_msg)))
                } else {
                    Err(VerifyError::InvalidProof(error_msg))
                }
            }
        }
    }
    
    pub fn verify_proof_safe(&self, proof: &[u8], public_inputs: &[Fp]) -> Result<bool, VerifyError> {
        match self.verify_proof(proof, public_inputs) {
            Ok(()) => Ok(true),
            Err(VerifyError::InvalidProof(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}