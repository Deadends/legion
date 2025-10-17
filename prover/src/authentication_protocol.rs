use anyhow::{Result, anyhow};
use pasta_curves::Fp;
use ff::PrimeField;
use std::collections::HashMap;
use std::sync::{RwLock, Arc};
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};

use crate::{
    auth_circuit::{AuthCircuit, AuthContext},
    oracle_verification::OracleVerifier,
    merkle_tree::AnonymityMerkleTree,
    device_tree::DeviceTreeManager,
    get_timestamp, fill_random_bytes,
};

// DTO for safe public API
#[derive(Serialize, Deserialize)]
pub struct AnonymitySetData {
    pub merkle_root: String,
    pub leaves: Vec<String>,
    pub paths: Vec<Vec<String>>,
    pub tree_size: usize,
}



#[cfg(feature = "redis")]
use redis;

// Protocol-level types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
    pub security_level: SecurityLevel,
    pub anonymity_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResult {
    pub success: bool,
    pub proof: Option<Vec<u8>>,
    pub proof_size: Option<usize>,
    pub session_token: Option<[u8; 32]>,
    pub nullifier: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Standard,   // k=16
    Production, // k=18
    Quantum,    // k=20
    Enterprise, // k=22
}

impl Default for SecurityLevel {
    fn default() -> Self {
        Self::Standard
    }
}

// Nullifier storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierEntry {
    pub hash: [u8; 32],
    pub timestamp: u64,
    pub user_context: String,
    pub security_level: SecurityLevel,
}

static NULLIFIER_STORE: Lazy<Arc<RwLock<HashMap<[u8; 32], NullifierEntry>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Main authentication protocol orchestrator (VERIFIER ONLY)
#[allow(dead_code)]
pub struct AuthenticationProtocol {
    oracle_verifier: Option<OracleVerifier>,
    anonymity_tree: Arc<RwLock<AnonymityMerkleTree>>,
    device_tree_manager: Arc<DeviceTreeManager>,
    #[cfg(feature = "redis")]
    redis_cache: Arc<RwLock<crate::redis_cache::RedisCache>>,
    #[cfg(feature = "redis")]
    bloom_filter: Arc<RwLock<crate::bloom_filter::BloomFilter>>,
}

// Global singleton with persistent storage
static GLOBAL_PROTOCOL: Lazy<Arc<RwLock<Option<Arc<AuthenticationProtocol>>>>> = 
    Lazy::new(|| Arc::new(RwLock::new(None)));

impl AuthenticationProtocol {
    pub fn new() -> Result<Self> {
        let oracle_verifier = Self::init_oracle_verifier().ok();
        
        let data_dir = std::env::var("LEGION_DATA_PATH")
            .unwrap_or_else(|_| "./legion_data".to_string());
        std::fs::create_dir_all(&data_dir)?;
        
        // Always use RocksDB for production-grade storage
        let rocksdb_path = format!("{}/rocksdb_merkle", data_dir);
        println!("💾 Loading anonymity set from RocksDB: {}", rocksdb_path);
        let anonymity_tree = Arc::new(RwLock::new(
            AnonymityMerkleTree::new_with_rocksdb(&rocksdb_path)?
        ));
        
        println!("✅ Server initialized in VERIFIER-ONLY mode");
        println!("   → Server will NOT generate proofs (zero-knowledge!)");
        println!("   → Clients generate proofs, server only verifies");
        
        let device_tree_manager = Arc::new(DeviceTreeManager::new());
        
        #[cfg(feature = "redis")]
        {
            let redis_cache = Arc::new(RwLock::new(crate::redis_cache::RedisCache::new()?));
            let bloom_filter = Arc::new(RwLock::new(crate::bloom_filter::BloomFilter::new()?));
            
            Ok(Self {
                oracle_verifier,
                anonymity_tree,
                device_tree_manager,
                redis_cache,
                bloom_filter,
            })
        }
        
        #[cfg(not(feature = "redis"))]
        Ok(Self {
            oracle_verifier,
            anonymity_tree,
            device_tree_manager,
        })
    }
    
    /// Get or create global singleton instance
    pub fn get_global() -> Result<Arc<Self>> {
        let mut global = GLOBAL_PROTOCOL.write().unwrap();
        if global.is_none() {
            *global = Some(Arc::new(Self::new()?));
        }
        Ok(global.as_ref().unwrap().clone())
    }
    
    /// Get anonymity set size (safe public method)
    pub fn get_anonymity_set_size(&self) -> usize {
        self.anonymity_tree.read().unwrap().get_anonymity_set_size()
    }
    
    /// Get Merkle proof for a specific leaf (safe public API)
    pub fn get_merkle_proof(&self, user_leaf: Fp) -> Result<(Vec<Fp>, usize)> {
        let tree = self.anonymity_tree.read().unwrap();
        
        let position = tree.get_leaf_index(&user_leaf)
            .ok_or_else(|| anyhow!("User not found in tree"))?;
        
        let (path, _) = tree.get_proof(position)?;
        Ok((path.to_vec(), position))
    }
    
    /// Get current Merkle root (safe public API)
    pub fn get_merkle_root(&self) -> Fp {
        self.anonymity_tree.read().unwrap().get_root()
    }
    
    /// Public API: Get anonymity set data for client-side proving (old method)
    pub fn get_anonymity_set_data(&self) -> Result<(Fp, Vec<Fp>)> {
        let tree = self.anonymity_tree.read().unwrap();
        let root = tree.get_root();
        let leaves = tree.get_leaves();
        Ok((root, leaves))
    }
    
    /// Safe public API: Get anonymity set as DTO (proper pattern)
    pub fn get_anonymity_set_dto(&self) -> Result<AnonymitySetData> {
        let tree = self.anonymity_tree.read().unwrap();
        let tree_size = tree.get_anonymity_set_size();
        
        // Get leaves as hex strings
        let leaves_hex: Vec<String> = tree.get_leaves()
            .iter()
            .map(|leaf| hex::encode(leaf.to_repr()))
            .collect();
        
        // Compute Merkle paths for each leaf
        let mut paths_hex = Vec::new();
        for i in 0..tree_size {
            match tree.get_proof(i) {
                Ok((path, _)) => {
                    let path_hex: Vec<String> = path.iter()
                        .map(|node| hex::encode(node.to_repr()))
                        .collect();
                    paths_hex.push(path_hex);
                }
                Err(_) => {
                    paths_hex.push(vec![]);
                }
            }
        }
        
        Ok(AnonymitySetData {
            merkle_root: hex::encode(tree.get_root().to_repr()),
            leaves: leaves_hex,
            paths: paths_hex,
            tree_size,
        })
    }
    
    /// Register user with pre-computed leaf (for HTTP API)
    pub fn register_user_with_leaf(&self, user_leaf: Fp) -> Result<()> {
        let mut tree = self.anonymity_tree.write().unwrap();
        
        // NO duplicate check - linkability tags make users unique
        // Multiple users can share same credentials but have different devices
        
        tree.add_leaf(user_leaf)?;
        println!("➕ User registered. Anonymity set size: {}", tree.get_anonymity_set_size());
        
        #[cfg(feature = "redis")]
        {
            let cache = self.redis_cache.write().unwrap();
            cache.set_merkle_root(tree.get_root())?;
        }
        
        Ok(())
    }
    
    /// Register blind leaf (client-side hashing)
    pub fn register_blind_leaf(&self, user_leaf_hex: &str) -> Result<()> {
        let leaf_bytes = hex::decode(user_leaf_hex)
            .map_err(|_| anyhow!("Invalid hex string"))?;
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&leaf_bytes);
        let user_leaf = Option::from(Fp::from_repr(repr))
            .ok_or_else(|| anyhow!("Invalid field element"))?;
        
        self.register_user_with_leaf(user_leaf)
    }
    
    /// Get Merkle path for a leaf (for ZK proof generation)
    pub fn get_merkle_path_for_leaf(&self, user_leaf_hex: &str) -> Result<(Vec<String>, String, usize)> {
        let leaf_bytes = hex::decode(user_leaf_hex)
            .map_err(|_| anyhow!("Invalid hex string"))?;
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&leaf_bytes);
        let user_leaf = Option::from(Fp::from_repr(repr))
            .ok_or_else(|| anyhow!("Invalid field element"))?;
        
        let tree = self.anonymity_tree.read().unwrap();
        let position = tree.get_leaf_index(&user_leaf)
            .ok_or_else(|| anyhow!("User not found in Merkle tree"))?;
        
        let (path, _) = tree.get_proof(position)?;
        let path_hex: Vec<String> = path.iter()
            .map(|node| hex::encode(node.to_repr()))
            .collect();
        
        let root_hex = hex::encode(tree.get_root().to_repr());
        
        Ok((path_hex, root_hex, position))
    }
    
    /// Generate challenge for ZK proof
    pub fn generate_challenge(&self) -> [u8; 32] {
        use ff::FromUniformBytes;
        let mut random_bytes = [0u8; 64];
        fill_random_bytes(&mut random_bytes).unwrap();
        let challenge_fp = Fp::from_uniform_bytes(&random_bytes);
        let repr = challenge_fp.to_repr();
        let mut result = [0u8; 32];
        result.copy_from_slice(repr.as_ref());
        result
    }
    
    /// Register device for user (device ring signature)
    pub fn register_device(&self, nullifier_hash: &str, device_commitment_hex: &str) -> Result<(usize, String)> {
        let device_commitment = Self::hex_to_fp(device_commitment_hex)?;
        let (position, root) = self.device_tree_manager.register_device(nullifier_hash, device_commitment)?;
        Ok((position, hex::encode(root.to_repr())))
    }
    
    /// Get device proof for user
    pub fn get_device_proof(&self, nullifier_hash: &str, position: usize) -> Result<(Vec<String>, String)> {
        let (path, root) = self.device_tree_manager.get_device_proof(nullifier_hash, position)?;
        let path_hex: Vec<String> = path.iter().map(|p| hex::encode(p.to_repr())).collect();
        Ok((path_hex, hex::encode(root.to_repr())))
    }
    
    /// Verify anonymous ZK proof with device ring signature
    pub fn verify_anonymous_proof(
        &self,
        proof_hex: &str,
        merkle_root_hex: &str,
        nullifier_hex: &str,
        challenge_hex: &str,
        client_pubkey_hex: &str,
        timestamp_hex: &str,
        device_merkle_root_hex: &str,
        session_token_hex: &str,
        expiration_time_hex: &str,
        linkability_tag_hex: &str,  // CHANGED from device_commitment_hex
    ) -> Result<String> {
        // Decode proof
        let proof = hex::decode(proof_hex)
            .map_err(|_| anyhow!("Invalid proof hex"))?;
        
        // Decode public inputs (10 total)
        let merkle_root = Self::hex_to_fp(merkle_root_hex)?;
        let nullifier = Self::hex_to_fp(nullifier_hex)?;
        let challenge = Self::hex_to_fp(challenge_hex)?;
        let client_pubkey = Self::hex_to_fp(client_pubkey_hex)?;
        let timestamp = Self::hex_to_fp(timestamp_hex)?;
        let device_merkle_root = Self::hex_to_fp(device_merkle_root_hex)?;
        let session_token = Self::hex_to_fp(session_token_hex)?;
        let expiration_time = Self::hex_to_fp(expiration_time_hex)?;
        let linkability_tag = Self::hex_to_fp(linkability_tag_hex)?;  // CHANGED
        
        // CRITICAL: Validate timestamp (prevent future/past attacks)
        // Allow longer window for k=16 (4 min proof) and k=18 (15 min proof)
        let timestamp_bytes = timestamp.to_repr();
        let timestamp_u64 = u64::from_le_bytes(timestamp_bytes[..8].try_into().unwrap_or([0u8; 8]));
        let current_time = get_timestamp();
        let time_diff = if timestamp_u64 > current_time {
            timestamp_u64 - current_time
        } else {
            current_time - timestamp_u64
        };
        // Allow 10 minutes for k=16/18 (proof generation takes 4-15 minutes)
        if time_diff > 600 {
            return Err(anyhow!("Timestamp too far from current time (max 10 minutes)"));
        }
        
        // Compute bindings
        use halo2_gadgets::poseidon::primitives as poseidon;
        let challenge_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, challenge]);
        let pubkey_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, client_pubkey]);
        
        // Verify session token computation (now uses linkability_tag)
        let expected_session_token = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<3>, 3, 2>::init()
            .hash([nullifier, timestamp, linkability_tag]);  // CHANGED
        if session_token != expected_session_token {
            return Err(anyhow!("Session token mismatch"));
        }
        
        // Verify expiration time
        let expected_expiration = timestamp + Fp::from(3600u64);
        if expiration_time != expected_expiration {
            return Err(anyhow!("Expiration time mismatch"));
        }
        
        let public_inputs = vec![
            merkle_root, nullifier, challenge, client_pubkey,
            challenge_binding, pubkey_binding,
            timestamp, device_merkle_root, session_token, expiration_time,
        ];
        
        // Verify proof using static method
        let valid = Self::verify_proof_static(&proof, &public_inputs)?;
        
        if !valid {
            return Err(anyhow!("Proof verification failed"));
        }
        
        // Check nullifier
        let nullifier_bytes: [u8; 32] = *blake3::hash(&nullifier.to_repr()).as_bytes();
        if self.check_nullifier_exists(nullifier_bytes)? {
            return Err(anyhow!("Nullifier already used"));
        }
        
        // Store nullifier
        let request = AuthenticationRequest {
            username: vec![],
            password: vec![],
            security_level: SecurityLevel::Standard,
            anonymity_required: true,
        };
        self.store_nullifier(nullifier_bytes, &request)?;
        
        // Extract expiration as u64
        let expiration_bytes = expiration_time.to_repr();
        let expiration_u64 = u64::from_le_bytes(expiration_bytes[..8].try_into().unwrap_or([0u8; 8]));
        
        // Session token is already computed in circuit, just convert to hex
        let session_token_hex = hex::encode(session_token.to_repr());
        
        // Store session in Redis with TTL
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                use redis::Commands;
                let key = format!("legion:session:{}", session_token_hex);
                
                let ttl = expiration_u64.saturating_sub(timestamp_u64) as i64;
                
                // Store session with linkability tag (zero-knowledge)
                // linkability_tag = Blake3(device_private_key || "LINKABILITY")
                
                let _: () = conn.hset_multiple(&key, &[
                    ("linkability_tag", linkability_tag_hex),
                    ("device_merkle_root", device_merkle_root_hex),
                    ("nullifier_hash", nullifier_hex),
                    ("created_at", &timestamp_u64.to_string()),
                    ("expires_at", &expiration_u64.to_string()),
                ]).unwrap_or(());
                
                // Set TTL from proof
                let _: () = conn.expire(&key, ttl).unwrap_or(());
                
                println!("✅ Session created with device-bound commitment (zero-knowledge)");
                println!("   → Session token computed in circuit");
                println!("   → Expiration enforced: {} seconds", ttl);
            }
        }
        
        Ok(session_token_hex)
    }
    
    fn hex_to_fp(hex: &str) -> Result<Fp> {
        let bytes = hex::decode(hex)
            .map_err(|_| anyhow!("Invalid hex string"))?;
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&bytes);
        Option::from(Fp::from_repr(repr))
            .ok_or_else(|| anyhow!("Invalid field element"))
    }
    

    
    pub fn is_user_registered(&self, user_leaf: Fp) -> bool {
        let tree = self.anonymity_tree.read().unwrap();
        tree.get_leaf_index(&user_leaf).is_some()
    }
    
    /// Register user in persistent anonymity set
    pub fn register_user(&self, username: &[u8], password: &[u8]) -> Result<()> {
        // Step 1: Hash username with Blake3
        let username_hash = AuthCircuit::hash_credential(username, b"USERNAME")?;
        
        // Step 2: Hash password with Argon2 (slow, secure)
        let argon2_password = AuthCircuit::argon2_hash_password(password, username)?;
        
        // Step 3: Hash the Argon2 output with Blake3 (for circuit compatibility)
        let password_hash = AuthCircuit::hash_credential(&argon2_password, b"PASSWORD")?;
        
        // Step 4: Compute leaf from BOTH username and password
        // This is what the circuit expects: Poseidon(username_hash, password_hash)
        let user_leaf = self.compute_user_leaf(username_hash, password_hash)?;
        
        let mut tree = self.anonymity_tree.write().unwrap();
        
        // NO duplicate check - linkability tags make users unique
        // Multiple users can share same credentials but have different devices
        
        tree.add_leaf(user_leaf)?;
        println!("➕ User registered. Anonymity set size: {}", tree.get_anonymity_set_size());
        
        #[cfg(feature = "redis")]
        {
            let cache = self.redis_cache.write().unwrap();
            cache.set_merkle_root(tree.get_root())?;
        }
        
        Ok(())
    }
    
    #[cfg(not(feature = "redis"))]
    pub fn authenticate_fast(&self, _request: AuthenticationRequest) -> Result<AuthenticationResult> {
        // Server should NOT generate proofs - client-side only
        Ok(AuthenticationResult {
            success: false,
            proof: None,
            proof_size: None,
            session_token: None,
            nullifier: None,
            error: Some("Server-side proving disabled. Use /api/verify-anonymous-proof".to_string()),
        })
    }
    
    #[cfg(feature = "redis")]
    pub fn authenticate_fast(&self, _request: AuthenticationRequest) -> Result<AuthenticationResult> {
        // Server should NOT generate proofs - client-side only
        Ok(AuthenticationResult {
            success: false,
            proof: None,
            proof_size: None,
            session_token: None,
            nullifier: None,
            error: Some("Server-side proving disabled. Use /api/verify-anonymous-proof".to_string()),
        })
    }
    

    
    /// Static proof verification (no state needed)
    fn verify_proof_static(proof: &[u8], public_inputs: &[Fp]) -> Result<bool> {
        use halo2_proofs::{
            plonk::{verify_proof, keygen_vk, SingleVerifier},
            poly::commitment::Params,
            transcript::{Blake2bRead, Challenge255},
        };
        use pasta_curves::vesta;
        
        // Try different k values (client can use k=12, 14, 16, 18)
        for k in [12, 14, 16, 18] {
            let params = Params::<vesta::Affine>::new(k);
            let dummy_circuit = AuthCircuit::default();
            if let Ok(vk) = keygen_vk(&params, &dummy_circuit) {
                let strategy = SingleVerifier::new(&params);
                let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
                
                if verify_proof(&params, &vk, strategy, &[&[public_inputs]], &mut transcript).is_ok() {
                    println!("✅ Proof verified with k={}", k);
                    return Ok(true);
                }
            }
        }
        
        println!("❌ Proof verification failed for all k values (12, 14, 16, 18)");
        Ok(false)
    }
    
    /// Verify proof with contextual checks
    pub fn verify_proof(&self, proof: &[u8], public_inputs: &[Fp], _auth_context: &AuthContext) -> Result<bool> {
        if public_inputs.len() != 10 {
            return Err(anyhow!("Invalid public inputs length: expected 10, got {}", public_inputs.len()));
        }
        
        let merkle_root = public_inputs[0];
        let nullifier = public_inputs[1];
        let challenge = public_inputs[2];
        let client_pubkey = public_inputs[3];
        let challenge_binding = public_inputs[4];
        let pubkey_binding = public_inputs[5];
        let timestamp = public_inputs[6];
        let device_merkle_root = public_inputs[7];
        let session_token = public_inputs[8];
        let expiration_time = public_inputs[9];
        
        // Verify bindings are correct (Poseidon hash)
        use halo2_gadgets::poseidon::primitives as poseidon;
        
        let expected_challenge_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, challenge]);
        
        let expected_pubkey_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([nullifier, client_pubkey]);
        
        if challenge_binding != expected_challenge_binding {
            println!("❌ Challenge binding mismatch");
            return Ok(false);
        }
        
        if pubkey_binding != expected_pubkey_binding {
            println!("❌ Pubkey binding mismatch");
            return Ok(false);
        }
        
        // Note: Cannot verify session token here without device_commitment
        // Session token verification happens in verify_anonymous_proof
        
        // Verify expiration time
        let expected_expiration = timestamp + Fp::from(3600u64);
        if expiration_time != expected_expiration {
            println!("❌ Expiration time mismatch");
            return Ok(false);
        }
        
        // Check merkle root matches current tree state
        let current_root = self.anonymity_tree.read().unwrap().get_root();
        if merkle_root != current_root {
            return Ok(false);
        }
        
        // Check nullifier hasn't been used
        let nullifier_bytes: [u8; 32] = *blake3::hash(&nullifier.to_repr()).as_bytes();
        if self.check_nullifier_exists(nullifier_bytes)? {
            return Ok(false);
        }
        
        // Verify cryptographic proof
        Self::verify_proof_static(proof, public_inputs)
    }
    
    fn init_oracle_verifier() -> Result<OracleVerifier> {
        if let Ok(pubkey_hex) = std::env::var("ORACLE_PUBLIC_KEY") {
            if pubkey_hex.len() == 64 {
                let mut pubkey = [0u8; 32];
                hex::decode_to_slice(&pubkey_hex, &mut pubkey)?;
                return OracleVerifier::new(&pubkey);
            }
        }
        
        let mut pubkey = [0u8; 32];
        fill_random_bytes(&mut pubkey)?;
        OracleVerifier::new(&pubkey)
    }
    
    fn validate_request(&self, request: &AuthenticationRequest) -> Result<()> {
        if request.username.is_empty() {
            return Err(anyhow!("Username cannot be empty"));
        }
        if request.password.is_empty() {
            return Err(anyhow!("Password cannot be empty"));
        }
        if request.username.len() > 256 || request.password.len() > 256 {
            return Err(anyhow!("Credentials too long"));
        }
        Ok(())
    }
    
    fn compute_nullifier_hash(&self, username: &[u8], password: &[u8]) -> Result<[u8; 32]> {
        // Use same hashing as authentication for consistency
        let username_hash = AuthCircuit::hash_credential(username, b"USERNAME")?;
        let argon2_password = AuthCircuit::argon2_hash_password(password, username)?;
        let password_hash = AuthCircuit::hash_credential(&argon2_password, b"PASSWORD")?;
        
        // ✅ FIXED: Deterministic nullifier (no timestamp)
        // Same username+password always produces same nullifier
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NULLIFIER_V3_ARGON2");
        hasher.update(&username_hash.to_repr());
        hasher.update(&password_hash.to_repr());
        // NO TIMESTAMP - prevents multiple logins with same credentials
        
        Ok(*hasher.finalize().as_bytes())
    }
    
    fn check_nullifier_exists(&self, nullifier_hash: [u8; 32]) -> Result<bool> {
        {
            let store = NULLIFIER_STORE.read().unwrap();
            if store.contains_key(&nullifier_hash) {
                return Ok(true);
            }
        }
        
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                let exists: bool = redis::cmd("SISMEMBER")
                    .arg("legion:nullifiers")
                    .arg(hex::encode(nullifier_hash))
                    .query(&mut conn)?;
                return Ok(exists);
            }
        }
        
        Ok(false)
    }
    
    fn store_nullifier(&self, nullifier_hash: [u8; 32], request: &AuthenticationRequest) -> Result<()> {
        let entry = NullifierEntry {
            hash: nullifier_hash,
            timestamp: get_timestamp(),
            user_context: "auth".to_string(),
            security_level: request.security_level,
        };
        
        {
            let mut store = NULLIFIER_STORE.write().unwrap();
            store.insert(nullifier_hash, entry.clone());
        }
        
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                let key = format!("legion:nullifier:{}", hex::encode(nullifier_hash));
                let data = serde_json::to_string(&entry)?;
                
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(&data)
                    .arg("EX")
                    .arg(3600)
                    .query(&mut conn)?;
                
                let _: () = redis::cmd("SADD")
                    .arg("legion:nullifiers")
                    .arg(hex::encode(nullifier_hash))
                    .query(&mut conn)?;
            }
        }
        
        Ok(())
    }
    

    
    fn compute_user_leaf(&self, username_hash: Fp, password_hash: Fp) -> Result<Fp> {
        use halo2_gadgets::poseidon::primitives as poseidon;
        
        Ok(poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([username_hash, password_hash]))
    }
    

    

    
    #[cfg(feature = "redis")]
    fn get_redis_connection(&self) -> Result<redis::Connection> {
        let redis_url = std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        
        let client = redis::Client::open(redis_url)?;
        Ok(client.get_connection()?)
    }
    
    /// ✅ FIXED: Audit logging for security monitoring
    fn log_authentication_attempt(
        &self,
        request: &AuthenticationRequest,
        success: bool,
        proof_size: Option<usize>,
        duration: std::time::Duration,
    ) -> Result<()> {
        let username_hash = AuthCircuit::hash_credential(&request.username, b"USERNAME")?;
        let log_entry = serde_json::json!({
            "timestamp": get_timestamp(),
            "event": "authentication_attempt",
            "username_hash": hex::encode(username_hash.to_repr()),
            "success": success,
            "proof_size": proof_size,
            "duration_ms": duration.as_millis(),
            "security_level": format!("{:?}", request.security_level),
        });
        
        println!("📝 Audit: {}", log_entry);
        
        #[cfg(feature = "redis")]
        {
            if let Ok(mut conn) = self.get_redis_connection() {
                let log_key = format!("legion:audit:{}", get_timestamp());
                let _: () = redis::cmd("SETEX")
                    .arg(log_key)
                    .arg(2592000) // 30 days
                    .arg(log_entry.to_string())
                    .query(&mut conn)
                    .unwrap_or(());
            }
        }
        
        Ok(())
    }
}



impl Default for AuthenticationProtocol {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            let tree = AnonymityMerkleTree::new_with_rocksdb("./legion_data/rocksdb_merkle")
                .expect("Failed to create default RocksDB tree");
            
            let device_tree_manager = Arc::new(DeviceTreeManager::new());
            
            #[cfg(feature = "redis")]
            {
                Self {
                    oracle_verifier: None,
                    anonymity_tree: Arc::new(RwLock::new(tree)),
                    device_tree_manager,
                    redis_cache: Arc::new(RwLock::new(crate::redis_cache::RedisCache::new().unwrap())),
                    bloom_filter: Arc::new(RwLock::new(crate::bloom_filter::BloomFilter::new().unwrap())),
                }
            }
            
            #[cfg(not(feature = "redis"))]
            {
                Self {
                    oracle_verifier: None,
                    anonymity_tree: Arc::new(RwLock::new(tree)),
                    device_tree_manager,
                }
            }
        })
    }
}

pub fn cleanup_expired_nullifiers() -> Result<usize> {
    let now = get_timestamp();
    let cutoff = now - 86400;
    let mut expired_count = 0;
    
    {
        let mut store = NULLIFIER_STORE.write().unwrap();
        let expired_keys: Vec<[u8; 32]> = store
            .iter()
            .filter(|(_, entry)| entry.timestamp < cutoff)
            .map(|(key, _)| *key)
            .collect();
        
        for key in expired_keys {
            store.remove(&key);
            expired_count += 1;
        }
    }
    
    #[cfg(feature = "redis")]
    {
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            if let Ok(client) = redis::Client::open(redis_url) {
                if let Ok(mut conn) = client.get_connection() {
                    let expired: Vec<String> = redis::cmd("ZRANGEBYSCORE")
                        .arg("legion:nullifiers:by_time")
                        .arg(0)
                        .arg(cutoff)
                        .query(&mut conn)
                        .unwrap_or_default();
                    
                    for nullifier_hex in expired {
                        let _: () = redis::cmd("SREM")
                            .arg("legion:nullifiers")
                            .arg(&nullifier_hex)
                            .query(&mut conn)
                            .unwrap_or(());
                    }
                }
            }
        }
    }
    
    Ok(expired_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[cfg(feature = "redis")]
    fn test_real_multi_user_system() -> Result<()> {
        let protocol = AuthenticationProtocol::new()?;
        
        // Register alice and bob in shared anonymity tree
        protocol.register_user(b"alice", b"password123")?;
        let root_after_alice = protocol.anonymity_tree.read().unwrap().get_root();
        
        protocol.register_user(b"bob", b"secret456")?;
        let root_after_bob = protocol.anonymity_tree.read().unwrap().get_root();
        
        // Merkle root should change after each registration
        assert_ne!(root_after_alice, root_after_bob);
        
        // Authenticate alice
        let alice_request = AuthenticationRequest {
            username: b"alice".to_vec(),
            password: b"password123".to_vec(),
            security_level: SecurityLevel::Standard,
            anonymity_required: true,
        };
        let alice_result = protocol.authenticate_fast(alice_request)?;
        assert!(alice_result.success);
        assert!(alice_result.proof.is_some());
        
        // Authenticate bob
        let bob_request = AuthenticationRequest {
            username: b"bob".to_vec(),
            password: b"secret456".to_vec(),
            security_level: SecurityLevel::Standard,
            anonymity_required: true,
        };
        let bob_result = protocol.authenticate_fast(bob_request)?;
        assert!(bob_result.success);
        assert!(bob_result.proof.is_some());
        
        // Both should have different nullifiers
        assert_ne!(alice_result.nullifier, bob_result.nullifier);
        
        Ok(())
    }
}
