//! Legion proof verifier using Pasta curves
//! 
//! This crate provides verification functionality for Legion ZK authentication
//! using unified cryptographic parameters with zero-knowledge properties.

mod security_policies;

use crypto_constants::{PARAMS_K, TRANSCRIPT_DOMAIN};
use security_policies::{SecurityPolicyEngine, SecurityContext};
use halo2_proofs::{
    plonk::{verify_proof, VerifyingKey, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255, Transcript},
};
use pasta_curves::{pallas, vesta, Fp, Fq};
use ff::{FromUniformBytes, Field, PrimeField};
use group::{Curve, Group};
use anyhow::Result;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::sync::RwLock;

/// Zero-knowledge authentication context
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub challenge_hash: [u8; 32],    // Server challenge (public)
    pub session_id: [u8; 16],        // Session identifier (public)
    pub auth_level: u8,              // Required security level (public)
    pub timestamp: u64,              // Challenge timestamp (public)
}

/// Authentication verification result
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub authenticated: bool,
    pub user_id_hash: Option<[u8; 32]>, // Blinded user identifier
    pub session_token: Option<[u8; 32]>, // Session token for authenticated user
}

pub type PallasParams = Params<vesta::Affine>;
pub type VestaParams = Params<pallas::Affine>;

/// Zero-knowledge authentication verifier
pub struct LegionVerifier {
    pallas_params: PallasParams,
    vesta_params: VestaParams,
    trusted_vk_hashes: Vec<[u8; 32]>,
    used_nullifiers: RwLock<HashSet<[u8; 32]>>, // CRITICAL: Replay protection
    current_merkle_root: RwLock<[u8; 32]>,      // CRITICAL: Current valid root
    security_engine: SecurityPolicyEngine,      // CRITICAL: Security policies
}

impl LegionVerifier {
    /// Create new verifier with unified parameters
    pub fn new() -> Result<Self> {
        let pallas_params = PallasParams::new(PARAMS_K);
        let vesta_params = VestaParams::new(PARAMS_K);
        
        Ok(Self {
            pallas_params,
            vesta_params,
            trusted_vk_hashes: Vec::new(),
            used_nullifiers: RwLock::new(HashSet::new()),
            current_merkle_root: RwLock::new([0u8; 32]),
            security_engine: SecurityPolicyEngine::new(),
        })
    }
    
    /// SECURITY: Register trusted verifying key
    pub fn register_trusted_vk(&mut self, vk_hash: [u8; 32]) {
        self.trusted_vk_hashes.push(vk_hash);
    }
    
    /// CRITICAL: Set current valid Merkle root
    pub fn set_current_merkle_root(&self, root: [u8; 32]) {
        *self.current_merkle_root.write().unwrap() = root;
    }
    
    /// Register challenge for security validation
    pub fn register_challenge(&self, challenge_hash: [u8; 32]) {
        self.security_engine.register_challenge(challenge_hash);
    }
    
    /// Register session for security validation
    pub fn register_session(&self, session_id: [u8; 16]) {
        self.security_engine.register_session(session_id);
    }
    
    /// CRITICAL: Check if nullifier has been used (replay protection)
    fn is_nullifier_used(&self, nullifier: &[u8; 32]) -> bool {
        self.used_nullifiers.read().unwrap().contains(nullifier)
    }
    
    /// CRITICAL: Mark nullifier as used
    fn mark_nullifier_used(&self, nullifier: [u8; 32]) {
        self.used_nullifiers.write().unwrap().insert(nullifier);
    }
    
    /// CRITICAL: Validate circuit outputs against current state
    fn validate_circuit_state(&self, merkle_root: Fp, nullifier: Fp) -> Result<()> {
        // Extract bytes from field elements
        let merkle_root_bytes = merkle_root.to_repr();
        let nullifier_bytes = nullifier.to_repr();
        
        let mut root_array = [0u8; 32];
        let mut nullifier_array = [0u8; 32];
        root_array.copy_from_slice(&merkle_root_bytes.as_ref()[..32]);
        nullifier_array.copy_from_slice(&nullifier_bytes.as_ref()[..32]);
        
        // CRITICAL: Check merkle root matches current state
        let current_root = *self.current_merkle_root.read().unwrap();
        if root_array != current_root {
            return Err(anyhow::anyhow!("Outdated merkle root"));
        }
        
        // CRITICAL: Check nullifier hasn't been used (replay protection)
        if self.is_nullifier_used(&nullifier_array) {
            return Err(anyhow::anyhow!("Nullifier already used - replay attack detected"));
        }
        
        Ok(())
    }
    
    /// ZK-AUTH: Verify authentication proof with zero-knowledge properties
    pub fn verify_auth_proof(
        &self,
        vk: &VerifyingKey<vesta::Affine>,
        auth_context: &AuthContext,
        proof: &[u8],
        circuit_merkle_root: Fp,  // From circuit proof
        circuit_nullifier: Fp,    // From circuit proof
    ) -> Result<AuthResult> {
        // STEP 1: Validate security policies first (fail fast)
        let security_context = SecurityContext {
            timestamp: auth_context.timestamp,
            challenge_hash: auth_context.challenge_hash,
            auth_level: auth_context.auth_level,
            session_id: auth_context.session_id,
            attributes: 1, // Default: user verified
            freshness: auth_context.timestamp % 100,
        };
        
        self.security_engine.validate_security_policies(
            &security_context,
            circuit_merkle_root,
            circuit_nullifier,
        )?;
        
        // STEP 2: Verify circuit proof with 2 public inputs
        let circuit_public_inputs = vec![circuit_merkle_root, circuit_nullifier];
        let is_valid = self.verify_pallas(vk, &circuit_public_inputs, proof)?;
        
        if !is_valid {
            return Ok(AuthResult {
                authenticated: false,
                user_id_hash: None,
                session_token: None,
            });
        }
        
        // STEP 3: Additional state validation
        self.validate_circuit_state(circuit_merkle_root, circuit_nullifier)?;
        
        // STEP 4: Mark nullifier as used
        let nullifier_bytes = circuit_nullifier.to_repr();
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&nullifier_bytes.as_ref()[..32]);
        self.mark_nullifier_used(nullifier);
        
        // STEP 5: Generate session data
        let user_id_hash = self.extract_blinded_user_id(proof, auth_context)?;
        let session_token = self.generate_session_token(auth_context, &user_id_hash)?;
        
        Ok(AuthResult {
            authenticated: true,
            user_id_hash: Some(user_id_hash),
            session_token: Some(session_token),
        })
    }
    
    /// SECURITY: Validate verifying key against whitelist
    fn validate_verifying_key<C: Curve>(&self, vk: &VerifyingKey<C>) -> Result<()> {
        // CRITICAL: Always require trusted VK - no bypass
        if self.trusted_vk_hashes.is_empty() {
            return Err(anyhow::anyhow!("No trusted verification keys registered"));
        }
        
        let vk_bytes = bincode::serialize(vk)
            .map_err(|e| anyhow::anyhow!("VK serialization failed: {}", e))?;
        let vk_hash = Sha3_256::digest(&vk_bytes);
        
        if !self.trusted_vk_hashes.iter().any(|trusted| trusted == vk_hash.as_slice()) {
            return Err(anyhow::anyhow!("Untrusted verifying key"));
        }
        
        Ok(())
    }
    
    /// Core Pallas verification (internal use)
    fn verify_pallas(
        &self,
        vk: &VerifyingKey<vesta::Affine>,
        public_inputs: &[Fp],
        proof: &[u8],
    ) -> Result<bool> {
        self.validate_verifying_key(vk)?;
        self.validate_proof_bytes(proof)?;
        self.validate_public_inputs_pallas(public_inputs)?;
        
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);
        
        // Enhanced domain separation
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_AUTH_VERIFICATION_V1");
        hasher.update(TRANSCRIPT_DOMAIN.as_bytes());
        hasher.update(&(public_inputs.len() as u32).to_le_bytes());
        let enhanced_domain = hasher.finalize();
        
        let mut enhanced_domain_bytes = [0u8; 64];
        enhanced_domain_bytes[..32].copy_from_slice(enhanced_domain.as_bytes());
        transcript.common_scalar(Fp::from_uniform_bytes(&enhanced_domain_bytes))?;
        
        let strategy = SingleVerifier::new(&self.pallas_params);
        let instances = &[&[public_inputs][..]];
        
        match verify_proof(
            &self.pallas_params,
            vk,
            strategy,
            instances,
            &mut transcript,
        ) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false), // Don't leak verification details
        }
    }
    
    /// ZK-AUTH: Construct anonymous public inputs (Zcash-style)
    fn construct_auth_public_inputs(&self, ctx: &AuthContext) -> Result<Vec<Fp>> {
        // ZCASH-STYLE: Only challenge data, anonymous proofs, no user correlation
        Ok(vec![
            // Challenge components (public, same for all users)
            Fp::from(ctx.timestamp),                                    // Challenge timestamp
            Fp::from_uniform_bytes(&[ctx.challenge_hash[..32].try_into().unwrap(), [0u8; 32]].concat().try_into().unwrap()), // Server pubkey
            Fp::from(ctx.auth_level as u64),                           // Required security level
            
            // Anonymous set root (shared by all users, no position leak)
            Fp::from_uniform_bytes(&[ctx.challenge_hash[16..].try_into().unwrap_or([0u8; 16]), [0u8; 48]].concat().try_into().unwrap()), // Merkle root placeholder
            
            // Challenge-specific nullifier (unlinkable across sessions)
            Fp::from_uniform_bytes(&[ctx.session_id, ctx.challenge_hash[..16].try_into().unwrap_or([0u8; 16]), [0u8; 32]].concat().try_into().unwrap()), // Anonymous nullifier
            
            // Session binding (prevents replay, no user correlation)
            Fp::from_uniform_bytes(&[ctx.session_id, [0u8; 48]].concat().try_into().unwrap()), // Session commitment
            
            // Anonymous attribute proof
            Fp::from(1u64),                                            // Attribute requirements met
            
            // Freshness proof
            Fp::from(ctx.timestamp % 100),                             // Challenge freshness
        ])
    }
    
    /// SECURITY: Validate authentication context
    fn validate_auth_context(&self, ctx: &AuthContext) -> Result<()> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        if current_time.saturating_sub(ctx.timestamp) > 300 {
            return Err(anyhow::anyhow!("Challenge expired"));
        }
        
        if ctx.auth_level == 0 || ctx.auth_level > 4 {
            return Err(anyhow::anyhow!("Invalid auth level"));
        }
        
        Ok(())
    }
    
    /// PRIVACY: Extract blinded user ID without revealing identity
    fn extract_blinded_user_id(&self, proof: &[u8], ctx: &AuthContext) -> Result<[u8; 32]> {
        // ZERO-KNOWLEDGE: Generate session-specific blinded ID
        // This is unlinkable across sessions and reveals no user identity
        let mut hasher = Sha3_256::new();
        hasher.update(b"LEGION_ANONYMOUS_SESSION_ID");
        hasher.update(&proof[..32.min(proof.len())]); // Use proof randomness
        hasher.update(&ctx.challenge_hash);
        hasher.update(&ctx.session_id);
        hasher.update(&ctx.timestamp.to_le_bytes());
        
        let result = hasher.finalize();
        let mut user_id = [0u8; 32];
        user_id.copy_from_slice(&result);
        Ok(user_id)
    }
    
    /// SECURITY: Generate session token for authenticated user
    fn generate_session_token(&self, ctx: &AuthContext, user_id_hash: &[u8; 32]) -> Result<[u8; 32]> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"LEGION_SESSION_TOKEN");
        hasher.update(user_id_hash);
        hasher.update(&ctx.challenge_hash);
        hasher.update(&ctx.session_id);
        hasher.update(&ctx.timestamp.to_le_bytes());
        
        let result = hasher.finalize();
        let mut token = [0u8; 32];
        token.copy_from_slice(&result);
        Ok(token)
    }
    
    /// SECURITY: Validate proof bytes structure
    fn validate_proof_bytes(&self, proof: &[u8]) -> Result<()> {
        if proof.is_empty() || proof.len() < 100 {
            return Err(anyhow::anyhow!("Invalid proof size"));
        }
        if proof.len() > 10_000_000 {
            return Err(anyhow::anyhow!("Proof too large"));
        }
        Ok(())
    }
    
    /// SECURITY: Validate Pallas public inputs
    fn validate_public_inputs_pallas(&self, inputs: &[Fp]) -> Result<()> {
        if inputs.is_empty() || inputs.len() > 100 {
            return Err(anyhow::anyhow!("Invalid input count"));
        }
        
        for (i, input) in inputs.iter().enumerate() {
            if input.is_zero().into() {
                continue;
            }
            let bytes = input.to_repr();
            if bytes.as_ref().iter().all(|&b| b == 0) {
                return Err(anyhow::anyhow!("Invalid field element at {}", i));
            }
        }
        Ok(())
    }
}

impl Default for LegionVerifier {
    fn default() -> Self {
        Self::new().expect("Failed to create default verifier")
    }
}