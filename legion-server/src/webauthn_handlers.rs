use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::Json as ResponseJson,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[cfg(feature = "webauthn")]
use webauthn_rs::prelude::*;

use super::AppState;

// Request to start WebAuthn registration (after ZK auth succeeds)
#[derive(Debug, Deserialize)]
pub struct StartWebAuthnRegRequest {
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct StartWebAuthnRegResponse {
    pub success: bool,
    pub challenge: Option<serde_json::Value>,
    pub error: Option<String>,
}

// Request to finish WebAuthn registration
#[derive(Debug, Deserialize)]
pub struct FinishWebAuthnRegRequest {
    pub session_token: String,
    pub credential: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct FinishWebAuthnRegResponse {
    pub success: bool,
    pub credential_id: Option<String>,
    pub error: Option<String>,
}

// Request to start WebAuthn authentication (for subsequent requests)
#[derive(Debug, Deserialize)]
pub struct StartWebAuthnAuthRequest {
    pub session_token: String,
}

#[derive(Debug, Serialize)]
pub struct StartWebAuthnAuthResponse {
    pub success: bool,
    pub challenge: Option<serde_json::Value>,
    pub error: Option<String>,
}

// Request to finish WebAuthn authentication
#[derive(Debug, Deserialize)]
pub struct FinishWebAuthnAuthRequest {
    pub session_token: String,
    pub assertion: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct FinishWebAuthnAuthResponse {
    pub success: bool,
    pub verified: bool,
    pub error: Option<String>,
}

#[cfg(feature = "webauthn")]
pub async fn start_webauthn_registration(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StartWebAuthnRegRequest>,
) -> Result<ResponseJson<StartWebAuthnRegResponse>, StatusCode> {
    tracing::info!("Starting WebAuthn registration for session: {}", &request.session_token[..16]);
    
    match state.webauthn_service.start_registration(&request.session_token) {
        Ok((challenge, reg_state)) => {
            // Store registration state in Redis
            state.webauthn_service.store_reg_state(&request.session_token, reg_state);
            
            let challenge_json = serde_json::to_value(&challenge)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            tracing::info!("WebAuthn registration challenge generated");
            Ok(ResponseJson(StartWebAuthnRegResponse {
                success: true,
                challenge: Some(challenge_json),
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!("WebAuthn registration start failed: {}", e);
            Ok(ResponseJson(StartWebAuthnRegResponse {
                success: false,
                challenge: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

#[cfg(feature = "webauthn")]
pub async fn finish_webauthn_registration(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishWebAuthnRegRequest>,
) -> Result<ResponseJson<FinishWebAuthnRegResponse>, StatusCode> {
    tracing::info!("Finishing WebAuthn registration for session: {}", &request.session_token[..16]);
    
    // Get stored registration state
    let reg_state = match state.webauthn_service.get_reg_state(&request.session_token) {
        Ok(state) => state,
        Err(e) => {
            tracing::error!("Failed to retrieve registration state: {}", e);
            return Ok(ResponseJson(FinishWebAuthnRegResponse {
                success: false,
                credential_id: None,
                error: Some("Registration state expired or not found".to_string()),
            }));
        }
    };
    
    // Parse credential from client
    let credential: RegisterPublicKeyCredential = serde_json::from_value(request.credential)
        .map_err(|e| {
            tracing::error!("Failed to parse credential: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    
    match state.webauthn_service.finish_registration(&credential, reg_state) {
        Ok(credential_id) => {
            // Bind credential to session
            if let Err(e) = state.webauthn_service.bind_credential_to_session(&credential_id, &request.session_token) {
                tracing::error!("Failed to bind credential to session: {}", e);
                return Ok(ResponseJson(FinishWebAuthnRegResponse {
                    success: false,
                    credential_id: None,
                    error: Some("Failed to bind credential".to_string()),
                }));
            }
            
            tracing::info!("✅ WebAuthn credential registered and bound to session");
            Ok(ResponseJson(FinishWebAuthnRegResponse {
                success: true,
                credential_id: Some(credential_id),
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!("WebAuthn registration finish failed: {}", e);
            Ok(ResponseJson(FinishWebAuthnRegResponse {
                success: false,
                credential_id: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

#[cfg(feature = "webauthn")]
pub async fn start_webauthn_authentication(
    State(state): State<Arc<AppState>>,
    Json(request): Json<StartWebAuthnAuthRequest>,
) -> Result<ResponseJson<StartWebAuthnAuthResponse>, StatusCode> {
    tracing::info!("Starting WebAuthn authentication for session: {}", &request.session_token[..16]);
    
    match state.webauthn_service.start_authentication(&request.session_token) {
        Ok((challenge, auth_state)) => {
            // Store authentication state in Redis
            state.webauthn_service.store_auth_state(&request.session_token, auth_state);
            
            let challenge_json = serde_json::to_value(&challenge)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            
            tracing::info!("WebAuthn authentication challenge generated");
            Ok(ResponseJson(StartWebAuthnAuthResponse {
                success: true,
                challenge: Some(challenge_json),
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!("WebAuthn authentication start failed: {}", e);
            Ok(ResponseJson(StartWebAuthnAuthResponse {
                success: false,
                challenge: None,
                error: Some(e.to_string()),
            }))
        }
    }
}

#[cfg(feature = "webauthn")]
pub async fn finish_webauthn_authentication(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FinishWebAuthnAuthRequest>,
) -> Result<ResponseJson<FinishWebAuthnAuthResponse>, StatusCode> {
    tracing::info!("Finishing WebAuthn authentication for session: {}", &request.session_token[..16]);
    
    // Get stored authentication state
    let auth_state = match state.webauthn_service.get_auth_state(&request.session_token) {
        Ok(state) => state,
        Err(e) => {
            tracing::error!("Failed to retrieve authentication state: {}", e);
            return Ok(ResponseJson(FinishWebAuthnAuthResponse {
                success: false,
                verified: false,
                error: Some("Authentication state expired or not found".to_string()),
            }));
        }
    };
    
    // Parse assertion from client
    let assertion: PublicKeyCredential = serde_json::from_value(request.assertion)
        .map_err(|e| {
            tracing::error!("Failed to parse assertion: {}", e);
            StatusCode::BAD_REQUEST
        })?;
    
    match state.webauthn_service.finish_authentication(&assertion, auth_state) {
        Ok(_user_id) => {
            tracing::info!("✅ WebAuthn authentication successful");
            Ok(ResponseJson(FinishWebAuthnAuthResponse {
                success: true,
                verified: true,
                error: None,
            }))
        }
        Err(e) => {
            tracing::error!("WebAuthn authentication finish failed: {}", e);
            Ok(ResponseJson(FinishWebAuthnAuthResponse {
                success: false,
                verified: false,
                error: Some(e.to_string()),
            }))
        }
    }
}

// Stubs for when webauthn feature is disabled
#[cfg(not(feature = "webauthn"))]
pub async fn start_webauthn_registration(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<StartWebAuthnRegRequest>,
) -> Result<ResponseJson<StartWebAuthnRegResponse>, StatusCode> {
    Ok(ResponseJson(StartWebAuthnRegResponse {
        success: false,
        challenge: None,
        error: Some("WebAuthn feature not enabled".to_string()),
    }))
}

#[cfg(not(feature = "webauthn"))]
pub async fn finish_webauthn_registration(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<FinishWebAuthnRegRequest>,
) -> Result<ResponseJson<FinishWebAuthnRegResponse>, StatusCode> {
    Ok(ResponseJson(FinishWebAuthnRegResponse {
        success: false,
        credential_id: None,
        error: Some("WebAuthn feature not enabled".to_string()),
    }))
}

#[cfg(not(feature = "webauthn"))]
pub async fn start_webauthn_authentication(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<StartWebAuthnAuthRequest>,
) -> Result<ResponseJson<StartWebAuthnAuthResponse>, StatusCode> {
    Ok(ResponseJson(StartWebAuthnAuthResponse {
        success: false,
        challenge: None,
        error: Some("WebAuthn feature not enabled".to_string()),
    }))
}

#[cfg(not(feature = "webauthn"))]
pub async fn finish_webauthn_authentication(
    State(_state): State<Arc<AppState>>,
    Json(_request): Json<FinishWebAuthnAuthRequest>,
) -> Result<ResponseJson<FinishWebAuthnAuthResponse>, StatusCode> {
    Ok(ResponseJson(FinishWebAuthnAuthResponse {
        success: false,
        verified: false,
        error: Some("WebAuthn feature not enabled".to_string()),
    }))
}
