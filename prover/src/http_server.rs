use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::application_service::ApplicationService;

#[cfg(feature = "webauthn")]
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

// Request/Response types
// BLIND REGISTRATION: Client sends only leaf hash
#[derive(Deserialize)]
struct BlindRegisterRequest {
    user_leaf: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    success: bool,
    user_leaf: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct WebAuthnStartRequest {
    user_id_hash: String, // Client sends Argon2(username) - never plaintext
}

#[derive(Deserialize)]
struct WebAuthnFinishRegisterRequest {
    user_id_hash: String, // Client sends Argon2(username) - never plaintext
    #[serde(flatten)]
    credential: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
struct WebAuthnFinishAuthRequest {
    user_id_hash: String, // Client sends Argon2(username) - never plaintext
    #[serde(flatten)]
    credential: PublicKeyCredential,
}

#[derive(Serialize)]
struct JsonResponse<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

// Route handlers - ZERO-KNOWLEDGE ONLY with Discord-style discriminators

#[cfg(feature = "webauthn")]
async fn webauthn_register_start(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<WebAuthnStartRequest>,
) -> impl Responder {
    match service.webauthn_start_registration(&req.user_id_hash) {
        Ok(challenge) => HttpResponse::Ok().json(challenge),
        Err(e) => HttpResponse::BadRequest().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(e.to_string()),
        }),
    }
}

#[cfg(feature = "webauthn")]
async fn webauthn_register_finish(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<WebAuthnFinishRegisterRequest>,
) -> impl Responder {
    match service.webauthn_finish_registration(&req.user_id_hash, &req.credential) {
        Ok(_) => HttpResponse::Ok().json(JsonResponse {
            success: true,
            data: Some("WebAuthn credential registered"),
            error: None,
        }),
        Err(e) => HttpResponse::BadRequest().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(e.to_string()),
        }),
    }
}

#[cfg(feature = "webauthn")]
async fn webauthn_auth_start(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<WebAuthnStartRequest>,
) -> impl Responder {
    match service.webauthn_start_authentication(&req.user_id_hash) {
        Ok(challenge) => HttpResponse::Ok().json(challenge),
        Err(e) => HttpResponse::BadRequest().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(e.to_string()),
        }),
    }
}

#[cfg(feature = "webauthn")]
async fn webauthn_auth_finish(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<WebAuthnFinishAuthRequest>,
) -> impl Responder {
    match service.webauthn_finish_authentication(&req.user_id_hash, &req.credential) {
        Ok(user_id_hash) => HttpResponse::Ok().json(JsonResponse {
            success: true,
            data: Some(serde_json::json!({ "user_id": user_id_hash, "verified": true })),
            error: None,
        }),
        Err(e) => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(e.to_string()),
        }),
    }
}

#[cfg(feature = "webauthn")]
#[derive(Deserialize)]
struct ProtectedChallengeRequest {
    session_id: String,
}

#[cfg(feature = "webauthn")]
#[derive(Deserialize)]
struct ProtectedRequest {
    session_id: String,
    #[serde(flatten)]
    credential: PublicKeyCredential,
}

#[cfg(feature = "webauthn")]
async fn protected_resource(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<ProtectedRequest>,
) -> impl Responder {
    // 🔒 ENFORCEMENT: Use the REAL validation that requires hardware proof
    match service.validate_session_with_hardware_proof(&req.session_id, &req.credential) {
        Ok(Some(session)) => HttpResponse::Ok().json(JsonResponse {
            success: true,
            data: Some(serde_json::json!({
                "message": "Access granted - hardware signature verified",
                "permissions": session.permissions,
                "user_id": session.user_id
            })),
            error: None,
        }),
        Ok(None) => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some("Invalid or expired session".to_string()),
        }),
        Err(e) => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(format!("Hardware verification failed: {}", e)),
        }),
    }
}

#[cfg(feature = "webauthn")]
async fn protected_challenge(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<ProtectedChallengeRequest>,
) -> impl Responder {
    match service.webauthn_start_authentication(&req.session_id) {
        Ok(challenge) => HttpResponse::Ok().json(challenge),
        Err(e) => HttpResponse::BadRequest().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(e.to_string()),
        }),
    }
}

// Get Merkle path for specific user leaf
#[derive(Deserialize)]
struct MerklePathRequest {
    user_leaf: String,
}

#[derive(Serialize)]
struct MerklePathResponse {
    merkle_path: Vec<String>,
    merkle_root: String,
    challenge: String,
    position: usize,
}

async fn get_merkle_path(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<MerklePathRequest>,
) -> impl Responder {
    use ff::PrimeField;
    use pasta_curves::Fp;

    let leaf_bytes = match hex::decode(&req.user_leaf) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid leaf hex".to_string()),
            })
        }
    };

    let mut leaf_repr = [0u8; 32];
    leaf_repr.copy_from_slice(&leaf_bytes[..32]);
    let user_leaf = match Fp::from_repr(leaf_repr).into_option() {
        Some(l) => l,
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid leaf".to_string()),
            })
        }
    };

    let protocol = service.get_protocol();

    // Use safe public API instead of direct tree access
    let (path, position) = match protocol.get_merkle_proof(user_leaf) {
        Ok(p) => p,
        Err(e) => {
            return HttpResponse::NotFound().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some(e.to_string()),
            })
        }
    };

    let merkle_path: Vec<String> = path.iter().map(|p| hex::encode(p.to_repr())).collect();
    let merkle_root = hex::encode(protocol.get_merkle_root().to_repr());

    // Generate challenge as valid Fp field element
    use ff::FromUniformBytes;
    use rand::RngCore;
    let mut challenge_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge_fp = Fp::from_uniform_bytes(&challenge_bytes);
    let challenge = hex::encode(challenge_fp.to_repr());

    // Store challenge with timestamp for expiry check
    let challenge_data = serde_json::json!({
        "challenge": challenge.clone(),
        "created_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "user_leaf": req.user_leaf.clone(),
    });

    let challenges_path = "./legion_data/challenges.json";
    let mut challenges: Vec<serde_json::Value> = std::fs::read_to_string(challenges_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    challenges.push(challenge_data);
    let _ = std::fs::write(
        challenges_path,
        serde_json::to_string_pretty(&challenges).unwrap(),
    );

    HttpResponse::Ok().json(MerklePathResponse {
        merkle_path,
        merkle_root,
        challenge,
        position,
    })
}

// WASM client support - anonymous proof verification
#[derive(Deserialize)]
struct AnonymousProofRequest {
    proof: String,
    merkle_root: String,
    nullifier: String,
    challenge: String,
    client_pubkey: String,
}

async fn verify_anonymous_proof(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<AnonymousProofRequest>,
) -> impl Responder {
    use ff::PrimeField;
    use pasta_curves::Fp;

    // Decode proof
    let proof = match hex::decode(&req.proof) {
        Ok(p) => p,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid proof hex".to_string()),
            })
        }
    };

    // Decode merkle root
    let root_bytes = match hex::decode(&req.merkle_root) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid merkle root hex".to_string()),
            })
        }
    };
    let mut root_repr = [0u8; 32];
    root_repr.copy_from_slice(&root_bytes[..32]);
    let merkle_root = match Fp::from_repr(root_repr).into_option() {
        Some(r) => r,
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid merkle root".to_string()),
            })
        }
    };

    // Decode nullifier
    let nullifier_bytes = match hex::decode(&req.nullifier) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid nullifier hex".to_string()),
            })
        }
    };
    let mut nullifier_repr = [0u8; 32];
    nullifier_repr.copy_from_slice(&nullifier_bytes[..32]);
    let nullifier = match Fp::from_repr(nullifier_repr).into_option() {
        Some(n) => n,
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid nullifier".to_string()),
            })
        }
    };

    // Verify challenge is fresh (60 second window)
    let challenges_path = "./legion_data/challenges.json";
    let mut challenges: Vec<serde_json::Value> = std::fs::read_to_string(challenges_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let challenge_valid = challenges.iter().any(|c| {
        c["challenge"].as_str() == Some(&req.challenge)
            && now - c["created_at"].as_u64().unwrap_or(0) < 60 // 60 second expiry
    });

    if !challenge_valid {
        return HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some("Challenge expired or invalid".to_string()),
        });
    }

    // Remove used challenge (single-use)
    challenges.retain(|c| c["challenge"].as_str() != Some(&req.challenge));
    let _ = std::fs::write(
        challenges_path,
        serde_json::to_string_pretty(&challenges).unwrap(),
    );

    // Decode challenge
    let challenge_bytes = match hex::decode(&req.challenge) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid challenge hex".to_string()),
            })
        }
    };
    let mut challenge_repr = [0u8; 32];
    challenge_repr.copy_from_slice(&challenge_bytes[..32]);
    let challenge = match Fp::from_repr(challenge_repr).into_option() {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid challenge".to_string()),
            })
        }
    };

    // Decode client pubkey
    let pubkey_bytes = match hex::decode(&req.client_pubkey) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid pubkey hex".to_string()),
            })
        }
    };
    let mut pubkey_repr = [0u8; 32];
    pubkey_repr.copy_from_slice(&pubkey_bytes[..32]);
    let client_pubkey = match Fp::from_repr(pubkey_repr).into_option() {
        Some(p) => p,
        None => {
            return HttpResponse::BadRequest().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("Invalid pubkey".to_string()),
            })
        }
    };

    // Compute expected bindings using Poseidon
    use halo2_gadgets::poseidon::primitives as poseidon;

    let expected_challenge_binding =
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, challenge]);

    let expected_pubkey_binding =
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, client_pubkey]);

    // Verify proof with 6 public inputs
    let protocol = service.get_protocol();
    let public_inputs = vec![
        merkle_root,
        nullifier,
        challenge,
        client_pubkey,
        expected_challenge_binding,
        expected_pubkey_binding,
    ];
    let auth_context = crate::AuthContext {
        challenge_hash: [0u8; 32],
        session_id: [0u8; 16],
        auth_level: 1,
        timestamp: crate::get_timestamp(),
    };

    match protocol.verify_proof(&proof, &public_inputs, &auth_context) {
        Ok(true) => {
            let nullifier_hash = *blake3::hash(&nullifier_repr).as_bytes();
            let nullifier_hex = hex::encode(nullifier_hash);

            // Session token now comes from proof (computed in circuit)
            let session_id = hex::encode(nullifier_hash);

            // Bind session to WebAuthn credential (if available)
            #[cfg(feature = "webauthn")]
            let webauthn_challenge = {
                use crate::webauthn_service::WebAuthnService;

                match WebAuthnService::new("legion.local", "https://localhost:8080") {
                    Ok(webauthn) => {
                        // Bind credential to session for anonymous lookup
                        let _ = webauthn.bind_credential_to_session(&nullifier_hex, &session_id);

                        // Start WebAuthn authentication
                        match webauthn.start_authentication(&session_id) {
                            Ok((challenge, auth_state)) => {
                                webauthn.store_auth_state(&session_id, auth_state);
                                Some(challenge)
                            }
                            Err(_) => None,
                        }
                    }
                    Err(_) => None,
                }
            };

            #[cfg(not(feature = "webauthn"))]
            let webauthn_challenge: Option<()> = None;

            // Store session binding
            let session_binding = serde_json::json!({
                "session_id": session_id.clone(),
                "client_pubkey": hex::encode(pubkey_repr),
                "nullifier": nullifier_hex,
                "created_at": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                "webauthn_bound": webauthn_challenge.is_some(),
            });

            let sessions_path = "./legion_data/sessions.json";
            let mut sessions: Vec<serde_json::Value> = std::fs::read_to_string(sessions_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            sessions.push(session_binding);
            let _ = std::fs::write(
                sessions_path,
                serde_json::to_string_pretty(&sessions).unwrap(),
            );

            let mut response = serde_json::json!({
                "success": true,
                "session_id": session_id,
                "message": "ZK proof verified",
                "proof_size": proof.len()
            });

            #[cfg(feature = "webauthn")]
            if let Some(challenge) = webauthn_challenge {
                response["webauthn_challenge"] = serde_json::to_value(challenge).unwrap();
                response["message"] =
                    serde_json::Value::String("Complete with WebAuthn".to_string());
            }

            HttpResponse::Ok().json(response)
        }
        Ok(false) => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some("Invalid proof or replay detected".to_string()),
        }),
        Err(e) => HttpResponse::InternalServerError().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(format!("Verification error: {}", e)),
        }),
    }
}

// BLIND REGISTRATION: Server receives only leaf hash
async fn register_blind(
    service: web::Data<Arc<ApplicationService>>,
    req: web::Json<BlindRegisterRequest>,
) -> impl Responder {
    use ff::PrimeField;
    use pasta_curves::Fp;

    // Decode leaf hash from hex
    let leaf_bytes = match hex::decode(&req.user_leaf) {
        Ok(b) => b,
        Err(_) => {
            return HttpResponse::BadRequest().json(RegisterResponse {
                success: false,
                user_leaf: None,
                error: Some("Invalid leaf hex".to_string()),
            })
        }
    };

    if leaf_bytes.len() != 32 {
        return HttpResponse::BadRequest().json(RegisterResponse {
            success: false,
            user_leaf: None,
            error: Some("Invalid leaf length".to_string()),
        });
    }

    let mut leaf_repr = [0u8; 32];
    leaf_repr.copy_from_slice(&leaf_bytes);
    let user_leaf = match Fp::from_repr(leaf_repr).into_option() {
        Some(l) => l,
        None => {
            return HttpResponse::BadRequest().json(RegisterResponse {
                success: false,
                user_leaf: None,
                error: Some("Invalid leaf field element".to_string()),
            })
        }
    };

    // Register with pre-computed leaf (server never sees username/password)
    let protocol = service.get_protocol();
    match protocol.register_user_with_leaf(user_leaf) {
        Ok(_) => HttpResponse::Ok().json(RegisterResponse {
            success: true,
            user_leaf: Some(req.user_leaf.clone()),
            error: None,
        }),
        Err(e) => HttpResponse::BadRequest().json(RegisterResponse {
            success: false,
            user_leaf: None,
            error: Some(e.to_string()),
        }),
    }
}

// Complete authentication with WebAuthn
#[cfg(feature = "webauthn")]
#[derive(Deserialize)]
struct CompleteAuthRequest {
    session_id: String,
    #[serde(flatten)]
    webauthn_assertion: PublicKeyCredential,
}

#[cfg(feature = "webauthn")]
async fn complete_auth(req: web::Json<CompleteAuthRequest>) -> impl Responder {
    use crate::webauthn_service::WebAuthnService;

    let webauthn = match WebAuthnService::new("legion.local", "https://localhost:8080") {
        Ok(w) => w,
        Err(e) => {
            return HttpResponse::InternalServerError().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some(e.to_string()),
            })
        }
    };

    // Get stored auth state
    let auth_state = match webauthn.get_auth_state(&req.session_id) {
        Ok(state) => state,
        Err(e) => {
            return HttpResponse::Unauthorized().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some(format!("No auth state: {}", e)),
            })
        }
    };

    // Verify WebAuthn signature
    match webauthn.finish_authentication(&req.webauthn_assertion, auth_state) {
        Ok(_user_id) => {
            // Update session to mark as fully authenticated
            let sessions_path = "./legion_data/sessions.json";
            let mut sessions: Vec<serde_json::Value> = std::fs::read_to_string(sessions_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();

            for session in sessions.iter_mut() {
                if session["session_id"].as_str() == Some(&req.session_id) {
                    session["webauthn_verified"] = serde_json::Value::Bool(true);
                    session["verified_at"] = serde_json::Value::Number(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            .into(),
                    );
                    break;
                }
            }

            let _ = std::fs::write(
                sessions_path,
                serde_json::to_string_pretty(&sessions).unwrap(),
            );

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "session_id": req.session_id,
                "message": "Session bound to hardware key",
                "webauthn_verified": true
            }))
        }
        Err(e) => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some(format!("Hardware key verification failed: {}", e)),
        }),
    }
}

// Verify session with device binding
#[derive(Deserialize)]
struct VerifySessionRequest {
    session_id: String,
    client_pubkey: String,
}

async fn verify_session(req: web::Json<VerifySessionRequest>) -> impl Responder {
    let sessions_path = "./legion_data/sessions.json";
    let sessions: Vec<serde_json::Value> = match std::fs::read_to_string(sessions_path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => {
            return HttpResponse::Unauthorized().json(JsonResponse {
                success: false,
                data: None::<String>,
                error: Some("No sessions found".to_string()),
            })
        }
    };

    // Find session
    let session = sessions
        .iter()
        .find(|s| s["session_id"].as_str() == Some(&req.session_id));

    match session {
        Some(s) => {
            let stored_pubkey = s["client_pubkey"].as_str().unwrap_or("");

            // Verify pubkey matches (device binding)
            if stored_pubkey == req.client_pubkey {
                HttpResponse::Ok().json(JsonResponse {
                    success: true,
                    data: Some("Session valid for this device"),
                    error: None,
                })
            } else {
                HttpResponse::Unauthorized().json(JsonResponse {
                    success: false,
                    data: None::<String>,
                    error: Some("Session stolen - pubkey mismatch".to_string()),
                })
            }
        }
        None => HttpResponse::Unauthorized().json(JsonResponse {
            success: false,
            data: None::<String>,
            error: Some("Invalid session".to_string()),
        }),
    }
}

// Route configuration - ZK + WebAuthn
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/register-blind", web::post().to(register_blind))
            .route("/get-merkle-path", web::post().to(get_merkle_path))
            .route(
                "/verify-anonymous-proof",
                web::post().to(verify_anonymous_proof),
            )
            .route("/verify-session", web::post().to(verify_session)),
    );

    #[cfg(feature = "webauthn")]
    cfg.service(web::scope("/api").route("/complete-auth", web::post().to(complete_auth)));

    #[cfg(feature = "webauthn")]
    cfg.service(
        web::scope("/api/webauthn")
            .route("/register/start", web::post().to(webauthn_register_start))
            .route("/register/finish", web::post().to(webauthn_register_finish))
            .route("/auth/start", web::post().to(webauthn_auth_start))
            .route("/auth/finish", web::post().to(webauthn_auth_finish)),
    );

    #[cfg(feature = "webauthn")]
    cfg.service(
        web::scope("/api/protected")
            .route("/challenge", web::post().to(protected_challenge))
            .route("/access", web::post().to(protected_resource)),
    );
}
