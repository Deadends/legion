use anyhow::Result;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pasta_curves::Fp;

/// Off-circuit oracle verification (MUCH safer)
pub struct OracleVerifier {
    oracle_public_key: VerifyingKey,
}

impl OracleVerifier {
    pub fn new(oracle_pubkey_bytes: &[u8; 32]) -> Result<Self> {
        let oracle_public_key = VerifyingKey::from_bytes(oracle_pubkey_bytes)?;
        Ok(Self { oracle_public_key })
    }

    /// Verify oracle signature OFF-CIRCUIT (fast & secure)
    pub fn verify_timestamp(&self, timestamp: u64, signature: &[u8; 64]) -> Result<bool> {
        let message = format!("ORACLE_TIMESTAMP:{}", timestamp);
        let sig = Signature::from_bytes(signature);

        match self.oracle_public_key.verify(message.as_bytes(), &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Get verified timestamp as circuit input (simple & clean)
    pub fn get_verified_timestamp_for_circuit(
        &self,
        timestamp: u64,
        signature: &[u8; 64],
    ) -> Result<Fp> {
        if self.verify_timestamp(timestamp, signature)? {
            Ok(Fp::from(timestamp))
        } else {
            Err(anyhow::anyhow!("Oracle signature verification failed"))
        }
    }
}
