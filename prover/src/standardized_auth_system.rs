use crate::{fill_random_bytes, get_timestamp};
use anyhow::{anyhow, Result};
use blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};

// STANDARD: Pure Ed25519 keys - no hybrid structures
type StandardPublicKey = [u8; 32];
type StandardSecretKey = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardCertificate {
    pub subject: String,
    pub issuer: String,
    pub public_key: StandardPublicKey,
    pub signature: Vec<u8>, // Standard Ed25519 signature (64 bytes)
    pub valid_from: u64,
    pub valid_until: u64,
    pub revoked: bool,
}

impl StandardCertificate {
    pub fn verify_signature(&self) -> Result<bool> {
        let verifying_key = VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| anyhow!("Invalid Ed25519 public key"))?;

        let signature = Signature::try_from(self.signature.as_slice())
            .map_err(|_| anyhow!("Invalid Ed25519 signature"))?;

        let mut cert_data = Vec::new();
        cert_data.extend_from_slice(self.subject.as_bytes());
        cert_data.extend_from_slice(&self.public_key);
        cert_data.extend_from_slice(&self.valid_from.to_le_bytes());
        cert_data.extend_from_slice(&self.valid_until.to_le_bytes());

        match verifying_key.verify(&cert_data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn is_valid(&self) -> bool {
        let now = get_timestamp();
        !self.revoked && now >= self.valid_from && now <= self.valid_until
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub event_type: String,
    pub user_id: String,
    pub success: bool,
    pub hash_chain: [u8; 32],
}

static CERTIFICATE_STORE: Lazy<RwLock<HashMap<String, StandardCertificate>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static AUDIT_BUFFER: Lazy<Mutex<Vec<AuditEvent>>> = Lazy::new(|| Mutex::new(Vec::new()));
static AUTHORITY_KEYS: Lazy<RwLock<Option<(StandardPublicKey, StandardSecretKey)>>> =
    Lazy::new(|| RwLock::new(None));
static HASH_CHAIN_STATE: Lazy<Mutex<[u8; 32]>> = Lazy::new(|| Mutex::new([0u8; 32]));

pub struct StandardizedAuthSystem;

impl StandardizedAuthSystem {
    pub fn initialize() -> Result<()> {
        // Initialize authority keys using STANDARD Ed25519
        {
            let keys = AUTHORITY_KEYS.read().unwrap();
            if keys.is_none() {
                drop(keys);
                let (pk, sk) = Self::generate_standard_keypair()?;
                let mut keys_write = AUTHORITY_KEYS.write().unwrap();
                *keys_write = Some((pk, sk));
            }
        }

        // Initialize hash chain
        {
            let mut chain_state = HASH_CHAIN_STATE.lock().unwrap();
            if *chain_state == [0u8; 32] {
                fill_random_bytes(&mut *chain_state)?;
            }
        }

        Ok(())
    }

    fn generate_standard_keypair() -> Result<(StandardPublicKey, StandardSecretKey)> {
        // STANDARD: Pure Ed25519 keypair generation
        let mut seed = [0u8; 32];
        fill_random_bytes(&mut seed)?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok((verifying_key.to_bytes(), signing_key.to_bytes()))
    }

    pub fn issue_certificate(subject: &str, validity_seconds: u64) -> Result<StandardCertificate> {
        let keys = AUTHORITY_KEYS.read().unwrap();
        let (_ca_pk, ca_sk) = keys
            .as_ref()
            .ok_or_else(|| anyhow!("Authority keys not initialized"))?;

        // Generate certificate keypair
        let (cert_pk, _cert_sk) = Self::generate_standard_keypair()?;

        let now = get_timestamp();
        let valid_from = now;
        let valid_until = now + validity_seconds;

        // Create certificate data
        let mut cert_data = Vec::new();
        cert_data.extend_from_slice(subject.as_bytes());
        cert_data.extend_from_slice(&cert_pk);
        cert_data.extend_from_slice(&valid_from.to_le_bytes());
        cert_data.extend_from_slice(&valid_until.to_le_bytes());

        // Sign with CA key
        let signing_key = SigningKey::from_bytes(ca_sk);
        let signature = signing_key.sign(&cert_data);

        let certificate = StandardCertificate {
            subject: subject.to_string(),
            issuer: "Legion CA".to_string(),
            public_key: cert_pk,
            signature: signature.to_bytes().to_vec(),
            valid_from,
            valid_until,
            revoked: false,
        };

        // Store certificate
        {
            let mut store = CERTIFICATE_STORE.write().unwrap();
            store.insert(subject.to_string(), certificate.clone());
        }

        Self::audit_event("CERT_ISSUED", subject, true)?;
        Ok(certificate)
    }

    pub fn revoke_certificate(subject: &str) -> Result<()> {
        let mut store = CERTIFICATE_STORE.write().unwrap();
        if let Some(cert) = store.get_mut(subject) {
            cert.revoked = true;
            Self::audit_event("CERT_REVOKED", subject, true)?;
            Ok(())
        } else {
            Err(anyhow!("Certificate not found: {}", subject))
        }
    }

    pub fn get_certificate(subject: &str) -> Option<StandardCertificate> {
        let store = CERTIFICATE_STORE.read().unwrap();
        store.get(subject).cloned()
    }

    fn audit_event(event_type: &str, user_id: &str, success: bool) -> Result<()> {
        // Update hash chain
        let hash_chain = {
            let mut chain_state = HASH_CHAIN_STATE.lock().unwrap();
            let mut hasher = blake3::Hasher::new();
            hasher.update(&*chain_state);
            hasher.update(event_type.as_bytes());
            hasher.update(user_id.as_bytes());
            hasher.update(&get_timestamp().to_le_bytes());
            let new_hash = hasher.finalize();
            *chain_state = *new_hash.as_bytes();
            *new_hash.as_bytes()
        };

        let event = AuditEvent {
            timestamp: get_timestamp(),
            event_type: event_type.to_string(),
            user_id: user_id.to_string(),
            success,
            hash_chain,
        };

        {
            let mut buffer = AUDIT_BUFFER.lock().unwrap();
            buffer.push(event);

            if buffer.len() >= 100 {
                Self::flush_audit_buffer(&mut buffer)?;
            }
        }

        Ok(())
    }

    fn flush_audit_buffer(buffer: &mut Vec<AuditEvent>) -> Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::fs;
            let timestamp = get_timestamp();
            let filename = format!("./audit_logs/audit_{}.json", timestamp);
            let data = serde_json::to_string_pretty(buffer)?;
            fs::write(filename, data)?;
        }

        buffer.clear();
        Ok(())
    }

    pub fn publish_merkle_root(root: [u8; 32]) -> Result<[u8; 64]> {
        let keys = AUTHORITY_KEYS.read().unwrap();
        let (_ca_pk, ca_sk) = keys
            .as_ref()
            .ok_or_else(|| anyhow!("Authority keys not initialized"))?;

        // Sign merkle root with standard Ed25519
        let signing_key = SigningKey::from_bytes(ca_sk);
        let signature = signing_key.sign(&root);

        Self::audit_event("MERKLE_ROOT_PUBLISHED", &hex::encode(root), true)?;
        Ok(signature.to_bytes())
    }

    pub fn verify_merkle_root_signature(root: [u8; 32], signature: [u8; 64]) -> Result<bool> {
        let keys = AUTHORITY_KEYS.read().unwrap();
        let (ca_pk, _ca_sk) = keys
            .as_ref()
            .ok_or_else(|| anyhow!("Authority keys not initialized"))?;

        let verifying_key =
            VerifyingKey::from_bytes(ca_pk).map_err(|_| anyhow!("Invalid CA public key"))?;

        let sig = Signature::try_from(signature.as_slice())
            .map_err(|_| anyhow!("Invalid signature format"))?;

        match verifying_key.verify(&root, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
