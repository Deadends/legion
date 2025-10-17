use ed25519_dalek::VerifyingKey;
use pasetors::keys::{AsymmetricPublicKey, AsymmetricSecretKey};
use pasetors::token::UntrustedToken;
use pasetors::{Public, version4::V4, claims::{Claims, ClaimsValidationRules}};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use anyhow::Result;

// Import from main.rs modules
use crate::security::{SecurityManager, crypto::CryptoRateLimiter};

#[derive(Error, Debug)]
pub enum SessionError {
    #[error("Security error: {0}")]
    Security(#[from] anyhow::Error),
    #[error("PASETO error: {0}")]
    Paseto(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Time error: {0}")]
    Time(#[from] std::time::SystemTimeError),
    #[error("Token expired")]
    Expired,
    #[error("Proof hash mismatch")]
    ProofHashMismatch,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub aud: String,
    pub exp: u64,
    pub nbf: u64,
    pub proof_hash: String,
    pub key_epoch: u64,
    pub client_id: String,
    pub alg: String,
}

pub async fn issue_token(
    security_manager: Arc<SecurityManager>,
    proof_hash: [u8; 32],
    client_id: &str,
    aud: &str,
    expiry_seconds: u64,
) -> Result<String, SessionError> {
    // Rate limiting check
    let rate_limiter = CryptoRateLimiter::new(100); // 100 ops/min
    if !rate_limiter.check_rate_limit(client_id)? {
        return Err(SessionError::RateLimitExceeded);
    }
    
    let signing_key = security_manager.key_manager().get_signing_key().await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    
    let claims = TokenClaims {
        aud: aud.to_string(),
        exp: now + expiry_seconds,
        nbf: now,
        proof_hash: hex::encode(proof_hash),
        key_epoch: now / 3600,
        client_id: client_id.to_string(),
        alg: "Ed25519".to_string(),
    };
    
    // Create pasetors Claims
    let mut paseto_claims = Claims::new()
        .map_err(|e| SessionError::Paseto(format!("Claims creation failed: {:?}", e)))?;
    
    // Add custom claims
    paseto_claims.add_additional("aud", serde_json::Value::String(claims.aud))
        .map_err(|e| SessionError::Paseto(format!("Failed to add aud: {:?}", e)))?;
    paseto_claims.add_additional("exp", serde_json::Value::Number(claims.exp.into()))
        .map_err(|e| SessionError::Paseto(format!("Failed to add exp: {:?}", e)))?;
    paseto_claims.add_additional("nbf", serde_json::Value::Number(claims.nbf.into()))
        .map_err(|e| SessionError::Paseto(format!("Failed to add nbf: {:?}", e)))?;
    paseto_claims.add_additional("proof_hash", serde_json::Value::String(claims.proof_hash))
        .map_err(|e| SessionError::Paseto(format!("Failed to add proof_hash: {:?}", e)))?;
    paseto_claims.add_additional("key_epoch", serde_json::Value::Number(claims.key_epoch.into()))
        .map_err(|e| SessionError::Paseto(format!("Failed to add key_epoch: {:?}", e)))?;
    paseto_claims.add_additional("client_id", serde_json::Value::String(claims.client_id))
        .map_err(|e| SessionError::Paseto(format!("Failed to add client_id: {:?}", e)))?;
    paseto_claims.add_additional("alg", serde_json::Value::String(claims.alg))
        .map_err(|e| SessionError::Paseto(format!("Failed to add alg: {:?}", e)))?;
    
    // Convert ed25519_dalek key to pasetors key
    let secret_key = AsymmetricSecretKey::<V4>::from(&signing_key.to_bytes())
        .map_err(|e| SessionError::Paseto(format!("Key conversion failed: {:?}", e)))?;
    
    let token = pasetors::public::sign(&secret_key, &paseto_claims, None, None)
        .map_err(|e| SessionError::Paseto(format!("Signing failed: {:?}", e)))?;
    
    // Token issued successfully (audit would be handled by caller)
    
    Ok(token)
}

pub fn verify_token(
    public_keys: &[VerifyingKey],
    token: &str,
    expected_proof_hash: &str,
) -> Result<TokenClaims, SessionError> {
    let untrusted_token = UntrustedToken::<Public, V4>::try_from(token)
        .map_err(|e| SessionError::Paseto(format!("Invalid token format: {:?}", e)))?;
    
    for public_key in public_keys {
        let public_key_bytes = public_key.to_bytes();
        let paseto_public_key = AsymmetricPublicKey::<V4>::from(&public_key_bytes)
            .map_err(|e| SessionError::Paseto(format!("Key conversion failed: {:?}", e)))?;
        
        let validation_rules = ClaimsValidationRules::new();
        
        match pasetors::public::verify(&paseto_public_key, &untrusted_token, &validation_rules, None, None) {
            Ok(trusted_token) => {
                let payload = trusted_token.payload();
                let claims: TokenClaims = serde_json::from_str(payload)?;
                
                // Verify expiry
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if now >= claims.exp {
                    return Err(SessionError::Expired);
                }
                
                // Verify proof hash
                if claims.proof_hash != expected_proof_hash {
                    return Err(SessionError::ProofHashMismatch);
                }
                
                return Ok(claims);
            }
            Err(_) => continue,
        }
    }
    
    Err(SessionError::Paseto("No valid signature found".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{SecurityManager, SecurityConfig, KeyProviderType, SecurityLevel, initialize_security};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_secure_paseto_tokens() {
        let security_config = SecurityConfig {
            key_provider_type: KeyProviderType::File,
            audit_enabled: false,
            security_level: SecurityLevel::Development,
        };
        let security_manager = initialize_security(security_config).await.unwrap();
        let proof_hash = [0xAB; 32];
        
        let token = issue_token(
            security_manager.clone(),
            proof_hash,
            "test_client",
            "legion-service",
            3600,
        ).await.unwrap();
        
        // Verify it's a proper PASETO v4.public token
        assert!(token.starts_with("v4.public."));
        
        let signing_key = security_manager.key_manager().get_signing_key().await.unwrap();
        let verifying_key = signing_key.verifying_key();
        
        let claims = verify_token(
            &[verifying_key],
            &token,
            &hex::encode(proof_hash),
        ).unwrap();
        
        assert_eq!(claims.client_id, "test_client");
        assert_eq!(claims.proof_hash, hex::encode(proof_hash));
        assert_eq!(claims.alg, "Ed25519");
    }
}