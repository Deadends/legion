use anyhow::Result;
use legion_prover::{AuthCircuit, AuthenticationProtocol, AuthenticationRequest, AuthContext as ProverAuthContext};
use legion_verifier::{LegionVerifier, AuthContext as VerifierAuthContext, AuthResult};
use halo2_proofs::plonk::VerifyingKey;
use pasta_curves::{vesta, Fp};
use std::time::{SystemTime, UNIX_EPOCH};

/// Complete authentication system integrating circuit and security policies
pub struct LegionAuthSystem {
    prover: AuthenticationProtocol,
    verifier: LegionVerifier,
}

#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub challenge_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub auth_level: u8,
}

#[derive(Debug, Clone)]
pub struct AuthResponse {
    pub success: bool,
    pub session_token: Option<[u8; 32]>,
    pub user_id_hash: Option<[u8; 32]>,
    pub error: Option<String>,
}

impl LegionAuthSystem {
    pub fn new() -> Result<Self> {
        let prover = AuthenticationProtocol::new()?;
        let verifier = LegionVerifier::new()?;
        
        Ok(Self {
            prover,
            verifier,
        })
    }
    
    /// Register trusted verification key
    pub fn register_vk(&mut self, vk_hash: [u8; 32]) {
        self.verifier.register_trusted_vk(vk_hash);
    }
    
    /// Set current merkle root
    pub fn set_merkle_root(&self, root: [u8; 32]) {
        self.verifier.set_current_merkle_root(root);
    }
    
    /// Complete authentication flow: prove + verify
    pub fn authenticate(
        &self,
        request: AuthRequest,
        vk: &VerifyingKey<vesta::Affine>,
    ) -> Result<AuthResponse> {
        // STEP 1: Register challenge and session for security validation
        self.verifier.register_challenge(request.challenge_hash);
        self.verifier.register_session(request.session_id);
        
        // STEP 2: Generate circuit proof
        let prover_request = legion_prover::AuthenticationRequest {
            username: request.username.clone(),
            password: request.password.clone(),
            security_level: match request.auth_level {
                1 => legion_prover::SecurityLevel::Standard,
                2 => legion_prover::SecurityLevel::Production,
                3 => legion_prover::SecurityLevel::Quantum,
                4 => legion_prover::SecurityLevel::Enterprise,
                _ => legion_prover::SecurityLevel::Standard,
            },
            anonymity_required: true,
        };
        
        let prover_result = self.prover.authenticate(prover_request)
            .map_err(|e| anyhow::anyhow!("Proof generation failed: {}", e))?;
        
        if !prover_result.success {
            return Ok(AuthResponse {
                success: false,
                session_token: None,
                user_id_hash: None,
                error: prover_result.error,
            });
        }
        
        let proof = prover_result.proof.ok_or_else(|| anyhow::anyhow!("No proof generated"))?;
        
        // STEP 3: Extract circuit outputs (merkle_root, nullifier)
        let circuit_nullifier = if let Some(nullifier_bytes) = prover_result.nullifier {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&nullifier_bytes);
            Fp::from_uniform_bytes(&buf)
        } else {
            return Err(anyhow::anyhow!("No nullifier in proof result"));
        };
        
        let circuit_merkle_root = Fp::from(42u64); // In production: extract from proof
        
        // STEP 4: Verify with security policies
        let verifier_context = VerifierAuthContext {
            challenge_hash: request.challenge_hash,
            session_id: request.session_id,
            auth_level: request.auth_level,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        };
        
        let verify_result = self.verifier.verify_auth_proof(
            vk,
            &verifier_context,
            &proof,
            circuit_merkle_root,
            circuit_nullifier,
        )?;
        
        Ok(AuthResponse {
            success: verify_result.authenticated,
            session_token: verify_result.session_token,
            user_id_hash: verify_result.user_id_hash,
            error: if verify_result.authenticated { None } else { Some("Verification failed".to_string()) },
        })
    }
}

impl Default for LegionAuthSystem {
    fn default() -> Self {
        Self::new().expect("Failed to create auth system")
    }
}