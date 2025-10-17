use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::{
    application_service::ApplicationService,
};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

// BLIND REGISTRATION: Client sends only leaf hash
#[derive(Deserialize)]
pub struct BlindRegisterRequest {
    pub user_leaf: String,  // Hex-encoded Fp element
}

// REMOVED: LoginRequest - use AnonymousProofRequest for zero-knowledge auth

// ZCASH MODEL: Anonymous proof submission (no username)
#[derive(Deserialize)]
pub struct AnonymousProofRequest {
    pub proof: Vec<u8>,
    pub merkle_root: String,
    pub nullifier: String,
}

// ZCASH MODEL: Public anonymity set response
#[derive(Serialize)]
pub struct AnonymitySetResponse {
    pub merkle_root: String,
    pub leaves: Vec<String>,
    pub paths: Vec<Vec<String>>,  // Pre-computed Merkle paths
    pub tree_size: usize,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub success: bool,
    pub session_id: Option<String>,
    pub message: Option<String>,
    pub proof_size: Option<usize>,
}

pub struct WebServer {
    app_service: Arc<ApplicationService>,
}

impl WebServer {
    pub fn new() -> Result<Self> {
        let app_service = Arc::new(ApplicationService::new()?);
        
        Ok(Self {
            app_service,
        })
    }


    
    /// BLIND REGISTRATION: Server receives only leaf hash (never sees raw credentials)
    pub fn handle_blind_register(&self, req: BlindRegisterRequest) -> Result<AuthResponse> {
        use pasta_curves::Fp;
        use ff::PrimeField;
        
        // Decode leaf hash from hex
        let leaf_bytes = hex::decode(&req.user_leaf)
            .map_err(|_| anyhow::anyhow!("Invalid leaf hex"))?;
        if leaf_bytes.len() != 32 {
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some("Invalid leaf length".to_string()),
                proof_size: None,
            });
        }
        
        let mut leaf_repr = [0u8; 32];
        leaf_repr.copy_from_slice(&leaf_bytes);
        let user_leaf = Fp::from_repr(leaf_repr).into_option()
            .ok_or_else(|| anyhow::anyhow!("Invalid leaf field element"))?;
        
        // Register with pre-computed leaf (server never sees username/password)
        let protocol = self.app_service.get_protocol();
        match protocol.register_user_with_leaf(user_leaf) {
            Ok(_) => Ok(AuthResponse {
                success: true,
                session_id: None,
                message: Some("Blind registration successful - server never saw credentials".to_string()),
                proof_size: None,
            }),
            Err(e) => Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some(format!("Registration failed: {}", e)),
                proof_size: None,
            }),
        }
    }

    // REMOVED: Server-side proving endpoint
    // Use verify_anonymous_proof() for true zero-knowledge authentication
    
    /// Get anonymity set for client-side proving
    pub fn get_anonymity_set(&self) -> Result<AnonymitySetResponse> {
        let protocol = self.app_service.get_protocol();
        let dto = protocol.get_anonymity_set_dto()?;
        
        Ok(AnonymitySetResponse {
            merkle_root: dto.merkle_root,
            leaves: dto.leaves,
            paths: dto.paths,
            tree_size: dto.tree_size,
        })
    }
    
    /// Serve static proving files (params and proving keys)
    pub fn serve_static_file(&self, filename: &str) -> Result<Vec<u8>> {
        let allowed_files = ["k16.params", "auth_circuit.pk"];
        if !allowed_files.contains(&filename) {
            return Err(anyhow::anyhow!("File not allowed: {}", filename));
        }
        let path = format!("./static/{}", filename);
        std::fs::read(&path).map_err(|e| anyhow::anyhow!("File not found: {}", e))
    }

    // WebAuthn endpoints
    #[cfg(feature = "webauthn")]
    pub fn handle_webauthn_register_start(&self, user_id: String) -> Result<serde_json::Value> {
        let ccr = self.app_service.webauthn_start_registration(&user_id)?;
        Ok(serde_json::to_value(ccr)?)
    }

    #[cfg(feature = "webauthn")]
    pub fn handle_webauthn_register_finish(&self, user_id: String, reg: webauthn_rs::prelude::RegisterPublicKeyCredential) -> Result<AuthResponse> {
        match self.app_service.webauthn_finish_registration(&user_id, &reg) {
            Ok(credential_id) => Ok(AuthResponse {
                success: true,
                session_id: Some(credential_id),
                message: Some("WebAuthn credential registered".to_string()),
                proof_size: None,
            }),
            Err(e) => Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some(format!("Registration failed: {}", e)),
                proof_size: None,
            }),
        }
    }

    #[cfg(feature = "webauthn")]
    pub fn handle_webauthn_auth_start(&self, user_id: String) -> Result<serde_json::Value> {
        let rcr = self.app_service.webauthn_start_authentication(&user_id)?;
        Ok(serde_json::to_value(rcr)?)
    }

    #[cfg(feature = "webauthn")]
    pub fn handle_webauthn_auth_finish(&self, user_id: String, auth: webauthn_rs::prelude::PublicKeyCredential) -> Result<AuthResponse> {
        match self.app_service.webauthn_finish_authentication(&user_id, &auth) {
            Ok(verified_user) => Ok(AuthResponse {
                success: true,
                session_id: None,
                message: Some(format!("Authenticated as: {}", verified_user)),
                proof_size: None,
            }),
            Err(e) => Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some(format!("Authentication failed: {}", e)),
                proof_size: None,
            }),
        }
    }

    // ZCASH MODEL: Verify anonymous proof (server knows nothing about user identity)
    pub fn verify_anonymous_proof(&self, req: AnonymousProofRequest) -> Result<AuthResponse> {
        use pasta_curves::Fp;
        use ff::PrimeField;
        
        let protocol = self.app_service.get_protocol();
        
        // Decode merkle root
        let root_bytes = hex::decode(&req.merkle_root)
            .map_err(|_| anyhow::anyhow!("Invalid merkle root hex"))?;
        if root_bytes.len() != 32 {
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some("Invalid merkle root length".to_string()),
                proof_size: None,
            });
        }
        let mut root_repr = [0u8; 32];
        root_repr.copy_from_slice(&root_bytes);
        let merkle_root = Fp::from_repr(root_repr).into_option()
            .ok_or_else(|| anyhow::anyhow!("Invalid merkle root field element"))?;
        
        // Decode nullifier
        let nullifier_bytes = hex::decode(&req.nullifier)
            .map_err(|_| anyhow::anyhow!("Invalid nullifier hex"))?;
        if nullifier_bytes.len() != 32 {
            return Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some("Invalid nullifier length".to_string()),
                proof_size: None,
            });
        }
        let mut nullifier_repr = [0u8; 32];
        nullifier_repr.copy_from_slice(&nullifier_bytes);
        let nullifier = Fp::from_repr(nullifier_repr).into_option()
            .ok_or_else(|| anyhow::anyhow!("Invalid nullifier field element"))?;
        
        // Verify proof blindly (server doesn't know which user)
        let public_inputs = vec![merkle_root, nullifier];
        let auth_context = crate::AuthContext {
            challenge_hash: [0u8; 32],
            session_id: [0u8; 16],
            auth_level: 1,
            timestamp: crate::get_timestamp(),
        };
        
        match protocol.verify_proof(&req.proof, &public_inputs, &auth_context) {
            Ok(true) => {
                let nullifier_hash = *blake3::hash(&nullifier_repr).as_bytes();
                let session_token = nullifier_hash;
                
                Ok(AuthResponse {
                    success: true,
                    session_id: Some(hex::encode(session_token)),
                    message: Some("Anonymous authentication successful".to_string()),
                    proof_size: Some(req.proof.len()),
                })
            },
            Ok(false) => Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some("Invalid proof or replay detected".to_string()),
                proof_size: None,
            }),
            Err(e) => Ok(AuthResponse {
                success: false,
                session_id: None,
                message: Some(format!("Verification error: {}", e)),
                proof_size: None,
            }),
        }
    }
}
