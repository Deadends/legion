// LEGION: Clean Layered Zero-Knowledge Authentication

#![allow(unexpected_cfgs)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(deprecated)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_abs_diff)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::new_without_default)]
#![allow(clippy::unwrap_or_default)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::needless_return)]

// LAYERED ARCHITECTURE
#[cfg(not(target_arch = "wasm32"))]
pub mod application_service;
pub mod auth_circuit; // Layer 1: Pure Circuit (Math Only)
#[cfg(not(target_arch = "wasm32"))]
pub mod authentication_protocol; // Layer 2: Protocol Logic // Layer 3: Business Logic

// POST-QUANTUM CRYPTOGRAPHY (Optional - requires 'post-quantum' feature)
#[cfg(feature = "post-quantum")]
pub mod pq_auth_wrapper;
#[cfg(feature = "post-quantum")]
pub mod pq_forward_secrecy; // Hybrid ML-KEM + X25519 Forward Secrecy
#[cfg(feature = "post-quantum")]
pub mod pq_signatures; // ML-DSA (FIPS 204) Signatures // Practical PQ Auth (Native, not in circuits)

// SPECIALIZED MODULES (Some require additional features)
#[cfg(not(target_arch = "wasm32"))]
pub mod enterprise_key_manager; // Key Management
#[cfg(feature = "nova")]
pub mod nova_accumulator; // Recursive Proofs (requires nova feature)
#[cfg(not(target_arch = "wasm32"))]
pub mod oracle_verification; // Off-circuit Verification
#[cfg(not(target_arch = "wasm32"))]
pub mod standardized_auth_system; // Certificate Management

// SUPPORTING MODULES
pub mod constraint_verifier;
pub mod crypto_constants;
pub mod crypto_helpers; // Shared helpers (server + WASM)
pub mod device_tree;
pub mod merkle_tree;
pub mod params_cache;
pub mod ring_signature; // Device ring signatures
pub mod rocksdb_merkle;
#[cfg(feature = "nova")]
pub mod test_nova;

// SECURITY MODULES
pub mod audit_log;
pub mod input_validator;
pub mod key_rotation;

// REDIS OPTIMIZATION LAYER (requires redis feature)
#[cfg(feature = "redis")]
pub mod background_nova;
pub mod background_worker;
#[cfg(feature = "redis")]
pub mod bloom_filter;
#[cfg(feature = "redis")]
pub mod key_pool;
#[cfg(feature = "redis")]
pub mod redis_cache;

// REAL PROOF GENERATION
pub mod proof_generator;

// WEB SERVER (for WASM client)
#[cfg(not(target_arch = "wasm32"))]
pub mod web_server;

// SESSION BINDING (cryptographic session management)
pub mod session_verifier;

// HTTP SERVER (for WebAuthn endpoints)
#[cfg(feature = "http-server")]
pub mod http_server;

// WEBAUTHN (hardware-bound authentication)
pub mod webauthn_service;

// Re-export main types
#[cfg(not(target_arch = "wasm32"))]
pub use application_service::{ApplicationService, UserSession}; // Layer 3: Application
pub use auth_circuit::{AuthCircuit, AuthConfig, AuthContext}; // Layer 1: Pure Circuit
#[cfg(not(target_arch = "wasm32"))]
pub use authentication_protocol::{
    cleanup_expired_nullifiers, AuthenticationProtocol, AuthenticationRequest,
    AuthenticationResult, NullifierEntry, SecurityLevel,
}; // Layer 2: Protocol
#[cfg(not(target_arch = "wasm32"))]
pub use enterprise_key_manager::*; // Key Management
#[cfg(feature = "nova")]
pub use nova_accumulator::*; // Nova Integration (optional)
#[cfg(not(target_arch = "wasm32"))]
pub use oracle_verification::*; // Oracle Verification
pub use proof_generator::ProofGenerator; // Proof generation (for WASM)
pub use session_verifier::SessionVerifier; // Session binding
#[cfg(not(target_arch = "wasm32"))]
pub use standardized_auth_system::*;
pub use webauthn_service::WebAuthnService; // WebAuthn // Certificates

// Supporting exports
pub use constraint_verifier::*;
pub use crypto_helpers::*;
pub use device_tree::*; // Device ring signatures
pub use key_rotation::*;
pub use merkle_tree::*; // Export shared helpers

// Helper functions
pub fn get_timestamp() -> u64 {
    use web_time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn fill_random_bytes(buf: &mut [u8]) -> anyhow::Result<()> {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
    Ok(())
}

// Re-export Fp for convenience
pub use pasta_curves::Fp;
