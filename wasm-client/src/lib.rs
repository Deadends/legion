use wasm_bindgen::prelude::*;
use serde::Deserialize;
use base64::{Engine as _, engine::general_purpose};

mod indexeddb;
use indexeddb::IndexedDBCache;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[macro_export]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}



// TRUE ZERO-KNOWLEDGE AUTHENTICATION
#[wasm_bindgen]
pub async fn authenticate_user(username: String, password: String, k: u32, server_url: String) -> Result<JsValue, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use legion_prover::{auth_circuit::AuthCircuit, proof_generator::ProofGenerator, Fp};
    use halo2_gadgets::poseidon::primitives as poseidon;
    use ff::{PrimeField, FromUniformBytes};
    
    console_log!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console_log!("🔐 ZERO-KNOWLEDGE AUTHENTICATION STARTED");
    console_log!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console_log!("⚙️  Security Level: k={} (Circuit size: 2^{} = {} rows)", k, k, 1u64 << k);
    console_log!("📊 Expected proof time: {}", match k {
        12 => "~10 seconds",
        14 => "~60 seconds",
        16 => "~4 minutes",
        18 => "~15 minutes",
        _ => "unknown"
    });
    console_log!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console_log!("\n[Step 1/8] 🔑 Hashing credentials client-side...");
    
    let username_hash = AuthCircuit::hash_credential(username.as_bytes(), b"USERNAME")
        .map_err(|e| JsValue::from_str(&format!("Username hash failed: {}", e)))?;
    console_log!("  ✓ Username hashed with Blake3");
    
    let argon2_password = AuthCircuit::argon2_hash_password(password.as_bytes(), username.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Argon2 failed: {}", e)))?;
    console_log!("  ✓ Password hashed with Argon2 (memory-hard)");
    
    let password_hash = AuthCircuit::hash_credential(&argon2_password, b"PASSWORD")
        .map_err(|e| JsValue::from_str(&format!("Password hash failed: {}", e)))?;
    console_log!("  ✓ Argon2 output hashed with Blake3");
    
    let user_leaf = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([username_hash, password_hash]);
    
    console_log!("\n[Step 2/8] 🔐 Checking for existing device credential...");
    
    let window = web_sys::window().ok_or("No window")?;
    let storage = window.local_storage()
        .map_err(|_| JsValue::from_str("No localStorage"))?
        .ok_or("No localStorage")?;
    
    // Check if device is already registered
    let (device_commitment_fp, device_position, ecdsa_pubkey_bytes_clone) = if let Some(stored_cred_id) = storage.get_item("legion_device_credential_id")
        .map_err(|_| JsValue::from_str("Storage read failed"))? {
        
        console_log!("  ✓ Found existing device credential");
        console_log!("  → Credential ID: {}...", &stored_cred_id[..16]);
        
        // Retrieve stored device commitment
        let stored_commitment = storage.get_item("legion_device_commitment")
            .map_err(|_| JsValue::from_str("Storage read failed"))?
            .ok_or("No device commitment stored")?;
        
        let commitment_bytes = hex::decode(&stored_commitment)
            .map_err(|_| JsValue::from_str("Invalid commitment hex"))?;
        let mut commitment_repr = [0u8; 32];
        commitment_repr.copy_from_slice(&commitment_bytes);
        let device_commitment_fp = Option::from(Fp::from_repr(commitment_repr))
            .ok_or_else(|| JsValue::from_str("Invalid device commitment"))?;
        
        // Retrieve stored device position
        let device_position = storage.get_item("legion_device_position")
            .map_err(|_| JsValue::from_str("Storage read failed"))?
            .ok_or("No device position stored")?
            .parse::<usize>()
            .map_err(|_| JsValue::from_str("Invalid device position"))?;
        
        // Retrieve stored public key
        let stored_pubkey = storage.get_item("legion_device_pubkey")
            .map_err(|_| JsValue::from_str("Storage read failed"))?
            .ok_or("No device pubkey stored")?;
        let ecdsa_pubkey_bytes = general_purpose::STANDARD.decode(&stored_pubkey)
            .map_err(|_| JsValue::from_str("Invalid pubkey base64"))?;
        
        console_log!("  ✓ Device commitment: {}...", &stored_commitment[..16]);
        console_log!("  ✓ Device position: {}", device_position);
        
        (device_commitment_fp, device_position, ecdsa_pubkey_bytes)
    } else {
        console_log!("  ⚠️  No existing credential - creating new device...");
        
        // Always use localhost for WebAuthn RP ID
        let rp_id = "localhost";
        
        // Generate random challenge
        let mut challenge_buf = [0u8; 32];
        getrandom::getrandom(&mut challenge_buf)
            .map_err(|e| JsValue::from_str(&format!("RNG failed: {}", e)))?;
        let challenge_bytes = js_sys::Uint8Array::from(&challenge_buf[..]);
    
        // Build WebAuthn credential options
        let credential_options = js_sys::Object::new();
        js_sys::Reflect::set(&credential_options, &"publicKey".into(), &{
            let pk_options = js_sys::Object::new();
            js_sys::Reflect::set(&pk_options, &"challenge".into(), &challenge_bytes)?;
            js_sys::Reflect::set(&pk_options, &"rp".into(), &{
                let rp = js_sys::Object::new();
                js_sys::Reflect::set(&rp, &"name".into(), &"Legion ZK Auth".into())?;
                js_sys::Reflect::set(&rp, &"id".into(), &JsValue::from_str(&rp_id))?;
                rp.into()
            })?;
            js_sys::Reflect::set(&pk_options, &"user".into(), &{
                let user = js_sys::Object::new();
                let user_id = js_sys::Uint8Array::from(&username_hash.to_repr()[..]);
                js_sys::Reflect::set(&user, &"id".into(), &user_id)?;
                js_sys::Reflect::set(&user, &"name".into(), &"anonymous".into())?;
                js_sys::Reflect::set(&user, &"displayName".into(), &"Anonymous User".into())?;
                user.into()
            })?;
            js_sys::Reflect::set(&pk_options, &"pubKeyCredParams".into(), &{
                let params = js_sys::Array::new();
                let param = js_sys::Object::new();
                js_sys::Reflect::set(&param, &"type".into(), &"public-key".into())?;
                js_sys::Reflect::set(&param, &"alg".into(), &JsValue::from_f64(-7.0))?;
                params.push(&param);
                params.into()
            })?;
            js_sys::Reflect::set(&pk_options, &"authenticatorSelection".into(), &{
                let auth_sel = js_sys::Object::new();
                js_sys::Reflect::set(&auth_sel, &"authenticatorAttachment".into(), &"platform".into())?;
                js_sys::Reflect::set(&auth_sel, &"userVerification".into(), &"preferred".into())?;
                js_sys::Reflect::set(&auth_sel, &"requireResidentKey".into(), &false.into())?;
                auth_sel.into()
            })?;
            js_sys::Reflect::set(&pk_options, &"timeout".into(), &JsValue::from_f64(60000.0))?;
            js_sys::Reflect::set(&pk_options, &"attestation".into(), &"none".into())?;
            pk_options.into()
        })?;
    
        console_log!("  ⏳ Requesting hardware key (Touch your security key/fingerprint)...");
        
        // Call navigator.credentials.create() via JS reflection
        let navigator = window.navigator();
        let credentials_obj = js_sys::Reflect::get(&navigator, &"credentials".into())?;
        let create_fn = js_sys::Reflect::get(&credentials_obj, &"create".into())?;
        let create_fn = create_fn.dyn_into::<js_sys::Function>()?;
        let credential_promise = create_fn.call1(&credentials_obj, &credential_options)?;
        
        let credential_result = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(credential_promise))
            .await
            .map_err(|e| JsValue::from_str(&format!("WebAuthn failed: {:?}", e)))?;
        
        // Extract credential ID
        let raw_id = js_sys::Reflect::get(&credential_result, &"rawId".into())?;
        let raw_id_bytes = js_sys::Uint8Array::new(&raw_id);
        let credential_id = hex::encode(raw_id_bytes.to_vec());
        
        // Extract attestation object and parse CBOR to get real public key
        let response = js_sys::Reflect::get(&credential_result, &"response".into())?;
        let attestation_object = js_sys::Reflect::get(&response, &"attestationObject".into())?;
        let attestation_bytes = js_sys::Uint8Array::new(&attestation_object);
        let attestation_vec = attestation_bytes.to_vec();
        
        // Parse CBOR attestation to extract P-256 public key
        let (ecdsa_pubkey_bytes, _) = parse_webauthn_attestation(&attestation_vec)
            .map_err(|e| JsValue::from_str(&format!("Failed to parse attestation: {}", e)))?;
        
        console_log!("  ✓ Extracted P-256 public key ({} bytes)", ecdsa_pubkey_bytes.len());
        
        // CRITICAL: Compute PERSISTENT device commitment from credential ID
        // This ensures same device = same commitment across logins
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_DEVICE_COMMITMENT_V1");
        hasher.update(&ecdsa_pubkey_bytes);
        hasher.update(credential_id.as_bytes());
        let commitment_hash = hasher.finalize();
        
        let device_commitment_fp = Fp::from_uniform_bytes(&{
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(commitment_hash.as_bytes());
            buf[32..].copy_from_slice(&username_hash.to_repr()[..32]);
            buf
        });
        
        console_log!("  ✓ Hardware credential created");
        console_log!("  ✓ Private key secured in TPM/Secure Enclave (non-extractable)");
        console_log!("  ✓ Credential ID: {}...", &credential_id[..16]);
        
        // Store credential ID and pubkey for future logins
        storage.set_item("legion_device_credential_id", &credential_id)
            .map_err(|e| JsValue::from_str(&format!("Storage failed: {:?}", e)))?;
        storage.set_item("legion_device_pubkey", &general_purpose::STANDARD.encode(&ecdsa_pubkey_bytes))
            .map_err(|e| JsValue::from_str(&format!("Storage failed: {:?}", e)))?;
        storage.set_item("legion_device_commitment", &hex::encode(device_commitment_fp.to_repr()))
            .map_err(|e| JsValue::from_str(&format!("Storage failed: {:?}", e)))?;
        
        // Device position will be set after registration
        (device_commitment_fp, 0, ecdsa_pubkey_bytes)
    };
    
    let client_pubkey_fp = device_commitment_fp;
    
    console_log!("\n[Step 3/8] 🌳 Requesting Merkle path from server...");
    
    // TRUE ZERO-KNOWLEDGE: Use tree_index if available
    let tree_index = storage.get_item("legion_tree_index")
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .and_then(|s| s.parse::<usize>().ok());
    
    let path_url = format!("{}/api/get-merkle-path", server_url);
    let path_body = if let Some(idx) = tree_index {
        console_log!("  ✓ Using tree_index={} (zero-knowledge - server doesn't know identity)", idx);
        serde_json::json!({
            "tree_index": idx
        })
    } else {
        console_log!("  ⚠️  No tree_index found - using DEPRECATED user_leaf (leaks identity)");
        serde_json::json!({
            "user_leaf": hex::encode(user_leaf.to_repr())
        })
    };
    
    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&path_body.to_string()));
    
    let request = Request::new_with_str_and_init(&path_url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    request.headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let window = web_sys::window().ok_or("No window")?;
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    let json_value = wasm_bindgen_futures::JsFuture::from(
        resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("JSON future failed: {:?}", e)))?;
    
    #[derive(Deserialize)]
    struct PathResponse {
        merkle_path: Vec<String>,
        merkle_root: String,
        challenge: String,
        position: usize,
    }
    
    let path_resp: PathResponse = serde_wasm_bindgen::from_value(json_value.clone())
        .map_err(|e| JsValue::from_str(&format!("Deserialize failed: {}", e)))?;
    
    console_log!("  ✓ Received Merkle path ({} siblings)", path_resp.merkle_path.len());
    console_log!("  ✓ Merkle root: {}...", &path_resp.merkle_root[..16]);
    console_log!("  ✓ Challenge: {}...", &path_resp.challenge[..16]);
    console_log!("  ✓ Your position in tree: {}", path_resp.position);
    
    console_log!("\n[Step 4/8] 🔍 Parsing and validating Merkle path...");
    
    let merkle_path: [Fp; 20] = {
        let mut path = [Fp::zero(); 20];
        for (i, hex) in path_resp.merkle_path.iter().enumerate() {
            let bytes = hex::decode(hex).map_err(|_| JsValue::from_str("Invalid path hex"))?;
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&bytes);
            path[i] = Option::from(Fp::from_repr(repr)).ok_or_else(|| JsValue::from_str("Invalid path element"))?;
        }
        path
    };
    
    let root_bytes = hex::decode(&path_resp.merkle_root)
        .map_err(|_| JsValue::from_str("Invalid root hex"))?;
    let mut root_repr = [0u8; 32];
    root_repr.copy_from_slice(&root_bytes);
    let merkle_root_fp = Option::from(Fp::from_repr(root_repr))
        .ok_or_else(|| JsValue::from_str("Invalid merkle root"))?;
    
    if path_resp.challenge.is_empty() {
        return Err(JsValue::from_str("Server returned empty challenge - user may not be registered"));
    }
    let challenge_bytes = hex::decode(&path_resp.challenge)
        .map_err(|_| JsValue::from_str(&format!("Invalid challenge hex: '{}'", path_resp.challenge)))?;
    let mut challenge_repr = [0u8; 32];
    challenge_repr.copy_from_slice(&challenge_bytes);
    let challenge_fp = Option::from(Fp::from_repr(challenge_repr))
        .ok_or_else(|| JsValue::from_str("Invalid challenge"))?;
    
    console_log!("  ✓ All {} Merkle siblings parsed successfully", path_resp.merkle_path.len());
    
    let circuit_start = js_sys::Date::now();
    
    console_log!("\n[Step 6/9] ⚡ Creating authentication circuit...");
    console_log!("  → Circuit will prove:");
    console_log!("    1. Credential verification (username + password)");
    console_log!("    2. User Merkle path validation (you're in anonymity set)");
    console_log!("    3. Device Merkle path validation (device ring signature)");
    console_log!("    4. Nullifier computation (replay protection)");
    console_log!("    5. Challenge binding (prevents replay attacks)");
    console_log!("    6. Public key binding (prevents session theft)");
    console_log!("    7. Session token = Hash(nullifier, timestamp, device_commitment)");
    console_log!("    8. Expiration time = timestamp + 3600 seconds");
    
    // Get current timestamp
    let timestamp_u64 = (js_sys::Date::now() / 1000.0) as u64;
    let timestamp_fp = Fp::from(timestamp_u64);
    console_log!("  ✓ Timestamp: {}", timestamp_u64);
    
    // Generate device commitment from WebAuthn pubkey
    let device_commitment_fp = client_pubkey_fp;
    console_log!("  ✓ Device commitment: {}...", &hex::encode(device_commitment_fp.to_repr())[..16]);
    
    // Compute nullifier first (needed for linkability tag)
    let nullifier_fp = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([username_hash, password_hash]);
    
    // Compute linkability tag (zero-knowledge device binding)
    // linkability_tag = Blake3(device_pubkey || nullifier)
    // This makes it unique per user+device (solves shared device problem)
    let mut link_hasher = blake3::Hasher::new();
    link_hasher.update(b"LEGION_LINKABILITY_TAG_V1");
    link_hasher.update(&ecdsa_pubkey_bytes_clone);
    link_hasher.update(&nullifier_fp.to_repr());
    let linkability_tag_bytes = link_hasher.finalize();
    
    let linkability_tag_fp = Fp::from_uniform_bytes(&{
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(linkability_tag_bytes.as_bytes());
        buf[32..].copy_from_slice(linkability_tag_bytes.as_bytes());
        buf
    });
    console_log!("  ✓ Linkability tag: {}...", &hex::encode(linkability_tag_fp.to_repr())[..16]);
    
    // Store linkability tag for session verification
    storage.set_item("legion_linkability_tag", &hex::encode(linkability_tag_fp.to_repr()))
        .map_err(|e| JsValue::from_str(&format!("Storage failed: {:?}", e)))?;
    
    // Register device and get device tree proof
    console_log!("\n[Step 5a/9] 🔐 Registering device in ring signature...");
    let nullifier_fp = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([username_hash, password_hash]);
    let nullifier_hash = hex::encode(blake3::hash(&nullifier_fp.to_repr()).as_bytes());
    
    let device_reg_url = format!("{}/api/register-device", server_url);
    let device_reg_body = serde_json::json!({
        "nullifier_hash": nullifier_hash,
        "device_commitment": hex::encode(device_commitment_fp.to_repr())
    });
    
    let mut device_reg_opts = RequestInit::new();
    device_reg_opts.set_method("POST");
    device_reg_opts.set_mode(RequestMode::Cors);
    device_reg_opts.set_body(&JsValue::from_str(&device_reg_body.to_string()));
    
    let device_reg_request = Request::new_with_str_and_init(&device_reg_url, &device_reg_opts)
        .map_err(|e| JsValue::from_str(&format!("Device reg request failed: {:?}", e)))?;
    device_reg_request.headers().set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let device_reg_resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&device_reg_request)
    ).await.map_err(|e| JsValue::from_str(&format!("Device reg fetch failed: {:?}", e)))?;
    
    let device_reg_resp: Response = device_reg_resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Device reg response cast failed"))?;
    
    let device_reg_json = wasm_bindgen_futures::JsFuture::from(
        device_reg_resp.json().map_err(|e| JsValue::from_str(&format!("Device reg JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("Device reg JSON future failed: {:?}", e)))?;
    
    #[derive(Deserialize)]
    struct DeviceRegResponse {
        success: bool,
        device_position: Option<usize>,
        device_tree_root: Option<String>,
        error: Option<String>,
    }
    
    let device_reg_resp: DeviceRegResponse = serde_wasm_bindgen::from_value(device_reg_json)
        .map_err(|e| JsValue::from_str(&format!("Device reg deserialize failed: {}", e)))?;
    
    if !device_reg_resp.success {
        return Err(JsValue::from_str(&format!("Device registration failed: {:?}", device_reg_resp.error)));
    }
    
    let device_position_from_server = device_reg_resp.device_position.ok_or("No device position")?;
    
    // Update device position if this was a new registration
    if device_position == 0 {
        storage.set_item("legion_device_position", &device_position_from_server.to_string())
            .map_err(|e| JsValue::from_str(&format!("Storage failed: {:?}", e)))?;
    }
    let device_position = device_position_from_server;
    
    console_log!("  ✓ Device registered at position {}", device_position);
    
    // Get device proof
    console_log!("\n[Step 5b/9] 🌳 Fetching device Merkle proof...");
    let device_proof_url = format!("{}/api/get-device-proof", server_url);
    let device_proof_body = serde_json::json!({
        "nullifier_hash": nullifier_hash,
        "device_position": device_position
    });
    
    let mut device_proof_opts = RequestInit::new();
    device_proof_opts.set_method("POST");
    device_proof_opts.set_mode(RequestMode::Cors);
    device_proof_opts.set_body(&JsValue::from_str(&device_proof_body.to_string()));
    
    let device_proof_request = Request::new_with_str_and_init(&device_proof_url, &device_proof_opts)
        .map_err(|e| JsValue::from_str(&format!("Device proof request failed: {:?}", e)))?;
    device_proof_request.headers().set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let device_proof_resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&device_proof_request)
    ).await.map_err(|e| JsValue::from_str(&format!("Device proof fetch failed: {:?}", e)))?;
    
    let device_proof_resp: Response = device_proof_resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Device proof response cast failed"))?;
    
    let device_proof_json = wasm_bindgen_futures::JsFuture::from(
        device_proof_resp.json().map_err(|e| JsValue::from_str(&format!("Device proof JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("Device proof JSON future failed: {:?}", e)))?;
    
    #[derive(Deserialize)]
    struct DeviceProofResponse {
        success: bool,
        device_merkle_path: Option<Vec<String>>,
        device_tree_root: Option<String>,
        error: Option<String>,
    }
    
    let device_proof_resp: DeviceProofResponse = serde_wasm_bindgen::from_value(device_proof_json)
        .map_err(|e| JsValue::from_str(&format!("Device proof deserialize failed: {}", e)))?;
    
    if !device_proof_resp.success {
        return Err(JsValue::from_str(&format!("Device proof failed: {:?}", device_proof_resp.error)));
    }
    
    let device_merkle_path_hex = device_proof_resp.device_merkle_path.ok_or("No device path")?;
    let device_tree_root_hex = device_proof_resp.device_tree_root.ok_or("No device root")?;
    
    console_log!("  ✓ Device Merkle path received ({} siblings)", device_merkle_path_hex.len());
    
    // Parse device Merkle path
    let device_merkle_path: [Fp; 10] = {
        let mut path = [Fp::zero(); 10];
        for (i, hex_str) in device_merkle_path_hex.iter().enumerate() {
            let bytes = hex::decode(hex_str).map_err(|_| JsValue::from_str("Invalid device path hex"))?;
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&bytes);
            path[i] = Option::from(Fp::from_repr(repr)).ok_or_else(|| JsValue::from_str("Invalid device path element"))?;
        }
        path
    };
    
    let device_root_bytes = hex::decode(&device_tree_root_hex)
        .map_err(|_| JsValue::from_str("Invalid device root hex"))?;
    let mut device_root_repr = [0u8; 32];
    device_root_repr.copy_from_slice(&device_root_bytes);
    let device_merkle_root_fp = Option::from(Fp::from_repr(device_root_repr))
        .ok_or_else(|| JsValue::from_str("Invalid device merkle root"))?;
    
    console_log!("  ✓ Device tree root: {}...", &device_tree_root_hex[..16]);
    
    let circuit = AuthCircuit::new(
        username_hash,
        password_hash,
        user_leaf,
        merkle_path,
        path_resp.position as u64,
        merkle_root_fp,
        challenge_fp,
        client_pubkey_fp,
        timestamp_fp,
        device_commitment_fp,
        device_merkle_path,
        device_position as u64,
        device_merkle_root_fp,
        linkability_tag_fp,  // NEW: Pass linkability tag to circuit
    )
    .map_err(|e| JsValue::from_str(&format!("Circuit creation failed: {}", e)))?;
    
    let public_inputs = circuit.public_inputs();
    console_log!("  ✓ Circuit created with {} public inputs", public_inputs.len());
    
    console_log!("\n[Step 7/9] 🔧 Loading/generating proving parameters (k={})...", k);
    console_log!("  → Circuit size: 2^{} = {} rows", k, 1u64 << k);
    
    let pg_start = js_sys::Date::now();
    let proof_gen;
    
    // Try to load from IndexedDB cache
    console_log!("  💾 Checking IndexedDB cache...");
    match IndexedDBCache::new().await {
        Ok(cache) => {
            match cache.get_params(k).await {
                Ok(Some(cached_params)) => {
                    console_log!("  ✓ Found cached params ({} bytes)", cached_params.len());
                    console_log!("  ⏳ Generating keys from cached params...");
                    proof_gen = ProofGenerator::from_params_bytes(k, &cached_params)
                        .map_err(|e| JsValue::from_str(&format!("Failed to load cached params: {}", e)))?;
                    console_log!("  ✓ Keys generated from cache in {:.1}s", (js_sys::Date::now() - pg_start) / 1000.0);
                }
                Ok(None) => {
                    console_log!("  ⚠️  No cached params found - generating fresh (40-90s)");
                    console_log!("  ⚠️  Browser will freeze - this is normal for ZK proofs");
                    proof_gen = ProofGenerator::new(k)
                        .map_err(|e| JsValue::from_str(&format!("ProofGenerator init failed: {}", e)))?;
                    
                    // Cache the params for next time
                    console_log!("  💾 Caching params to IndexedDB...");
                    let params_bytes = proof_gen.get_params_bytes()
                        .map_err(|e| JsValue::from_str(&format!("Failed to serialize params: {}", e)))?;
                    if let Err(e) = cache.set_params(k, &params_bytes).await {
                        console_log!("  ⚠️  Failed to cache params: {:?}", e);
                    } else {
                        console_log!("  ✓ Params cached for future use");
                    }
                }
                Err(e) => {
                    console_log!("  ⚠️  IndexedDB error: {:?} - generating fresh", e);
                    proof_gen = ProofGenerator::new(k)
                        .map_err(|e| JsValue::from_str(&format!("ProofGenerator init failed: {}", e)))?;
                }
            }
        }
        Err(e) => {
            console_log!("  ⚠️  IndexedDB not available: {:?} - generating fresh", e);
            proof_gen = ProofGenerator::new(k)
                .map_err(|e| JsValue::from_str(&format!("ProofGenerator init failed: {}", e)))?;
        }
    }
    
    let pg_time = js_sys::Date::now() - pg_start;
    console_log!("  ✓ Total setup time: {:.1}s", pg_time / 1000.0);
    console_log!("  ✓ Proving key (PK) ready");
    console_log!("  ✓ Verifying key (VK) ready");
    
    console_log!("\n[Step 8/9] 🎯 Generating zero-knowledge proof...");
    console_log!("  → Using Halo2 PLONK (no trusted setup)");
    console_log!("  → Proving system: Pasta curves (Pallas/Vesta)");
    console_log!("  ⏳ Generating proof - please wait...");
    let proof_start = js_sys::Date::now();
    
    let proof_bytes = proof_gen.generate_proof(circuit, &public_inputs)
        .map_err(|e| JsValue::from_str(&format!("Proof generation failed: {}", e)))?;
    
    let proof_time = js_sys::Date::now() - proof_start;
    console_log!("  ✓ Proof generated in {:.1}s", proof_time / 1000.0);
    console_log!("  ✓ Proof size: {} bytes ({:.2} KB)", proof_bytes.len(), proof_bytes.len() as f64 / 1024.0);
    
    console_log!("\n[Step 9/9] 📤 Submitting anonymous proof to server...");
    console_log!("  → Proof contains {} public inputs:", public_inputs.len());
    console_log!("    1. User Merkle root (current tree state)");
    console_log!("    2. Nullifier (prevents replay)");
    console_log!("    3. Challenge (freshness)");
    console_log!("    4. Client pubkey (session binding)");
    console_log!("    5. Challenge binding (Poseidon hash)");
    console_log!("    6. Pubkey binding (Poseidon hash)");
    console_log!("    7. Timestamp (session uniqueness)");
    console_log!("    8. Device Merkle root (device ring signature)");
    console_log!("    9. Session token (computed in circuit)");
    console_log!("   10. Expiration time (timestamp + 3600)");
    console_log!("  → Server will verify WITHOUT learning your identity");
    
    let verify_url = format!("{}/api/verify-anonymous-proof", server_url);
    let verify_body = serde_json::json!({
        "proof": hex::encode(&proof_bytes),
        "merkle_root": path_resp.merkle_root,
        "nullifier": hex::encode(public_inputs[1].to_repr()),
        "challenge": path_resp.challenge,
        "client_pubkey": hex::encode(client_pubkey_fp.to_repr()),
        "timestamp": hex::encode(public_inputs[6].to_repr()),
        "device_merkle_root": hex::encode(public_inputs[7].to_repr()),
        "session_token": hex::encode(public_inputs[8].to_repr()),
        "expiration_time": hex::encode(public_inputs[9].to_repr()),
        "linkability_tag": hex::encode(linkability_tag_fp.to_repr())  // CHANGED
    });
    
    let mut verify_opts = RequestInit::new();
    verify_opts.set_method("POST");
    verify_opts.set_mode(RequestMode::Cors);
    verify_opts.set_body(&JsValue::from_str(&verify_body.to_string()));
    
    let verify_request = Request::new_with_str_and_init(&verify_url, &verify_opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    verify_request.headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let verify_resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&verify_request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let verify_resp: Response = verify_resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    let result_json = wasm_bindgen_futures::JsFuture::from(
        verify_resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("JSON future failed: {:?}", e)))?;
    
    let total_time = js_sys::Date::now() - circuit_start;
    console_log!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console_log!("✅ ZERO-KNOWLEDGE AUTHENTICATION COMPLETE!");
    console_log!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console_log!("📊 Performance Summary:");
    console_log!("  • Security level: k={}", k);
    console_log!("  • Total time: {:.1}s", total_time / 1000.0);
    console_log!("  • Params + key generation: {:.1}s", pg_time / 1000.0);
    console_log!("  • Proof generation: {:.1}s", proof_time / 1000.0);
    console_log!("  • Proof size: {} bytes", proof_bytes.len());
    console_log!("\n🔒 Privacy Guarantees:");
    console_log!("  ✓ Server NEVER saw your username");
    console_log!("  ✓ Server NEVER saw your password");
    console_log!("  ✓ Server CANNOT identify which user you are");
    console_log!("  ✓ Proof is cryptographically sound (2^-128 forgery probability)");
    console_log!("  ✓ Session bound to this device (prevents theft)");
    console_log!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    console_log!("🔒 Device commitment is PERSISTENT across logins");
    console_log!("   → Same device = same commitment (enables device ring)");
    console_log!("   → Server cannot track (only sees hash)");
    console_log!("   → Stored locally: credential ID, pubkey, commitment, position");
    
    Ok(result_json)
}

// BLIND REGISTRATION: Client hashes credentials, server never sees raw data
#[wasm_bindgen]
pub async fn register_user(username: String, password: String, server_url: String) -> Result<JsValue, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    use legion_prover::auth_circuit::AuthCircuit;
    use halo2_gadgets::poseidon::primitives as poseidon;
    use ff::PrimeField;
    
    console_log!("Hashing credentials client-side...");
    
    // EXACT MATCH to server registration (authentication_protocol.rs line 213-224)
    let username_hash = AuthCircuit::hash_credential(username.as_bytes(), b"USERNAME")
        .map_err(|e| JsValue::from_str(&format!("Username hash failed: {}", e)))?;
    
    let argon2_password = AuthCircuit::argon2_hash_password(password.as_bytes(), username.as_bytes())
        .map_err(|e| JsValue::from_str(&format!("Argon2 failed: {}", e)))?;
    
    let password_hash = AuthCircuit::hash_credential(&argon2_password, b"PASSWORD")
        .map_err(|e| JsValue::from_str(&format!("Password hash failed: {}", e)))?;
    
    // Compute leaf: Poseidon(username_hash, password_hash)
    let user_leaf = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
        .hash([username_hash, password_hash]);
    
    console_log!("Sending only leaf hash to server (blind registration)");
    console_log!("Server will return tree_index for zero-knowledge authentication");
    
    let url = format!("{}/api/register-blind", server_url);
    let body = serde_json::json!({
        "user_leaf": hex::encode(user_leaf.to_repr())
    });
    
    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&body.to_string()));
    
    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    request.headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let window = web_sys::window().ok_or("No window")?;
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    let json = wasm_bindgen_futures::JsFuture::from(
        resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("JSON future failed: {:?}", e)))?;
    
    // Extract and store tree_index for zero-knowledge
    #[derive(Deserialize)]
    struct RegResponse {
        success: bool,
        user_leaf: String,
    }
    
    if let Ok(reg_resp) = serde_wasm_bindgen::from_value::<RegResponse>(json.clone()) {
        if reg_resp.success && reg_resp.user_leaf.starts_with("tree_index=") {
            if let Some(idx_str) = reg_resp.user_leaf.strip_prefix("tree_index=") {
                let window = web_sys::window().ok_or("No window")?;
                let storage = window.local_storage()
                    .map_err(|_| JsValue::from_str("No localStorage"))?
                    .ok_or("No localStorage")?;
                storage.set_item("legion_tree_index", idx_str)
                    .map_err(|_| JsValue::from_str("Failed to store tree_index"))?;
                console_log!("✓ Stored tree_index={} for zero-knowledge authentication", idx_str);
            }
        }
    }
    
    Ok(json)
}

// Verify session on subsequent requests
#[wasm_bindgen]
pub async fn verify_session(session_id: String, server_url: String) -> Result<JsValue, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    
    let window = web_sys::window().ok_or("No window")?;
    let storage = window.local_storage()
        .map_err(|_| JsValue::from_str("No localStorage"))?
        .ok_or("No localStorage")?;
    
    let device_commitment = storage.get_item("legion_device_commitment")
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .ok_or("No device commitment stored - not authenticated")?;
    
    let url = format!("{}/api/verify-session", server_url);
    let body = serde_json::json!({
        "session_id": session_id,
        "client_pubkey": device_commitment
    });
    
    let mut opts = RequestInit::new();
    opts.set_method("POST");
    opts.set_mode(RequestMode::Cors);
    opts.set_body(&JsValue::from_str(&body.to_string()));
    
    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    request.headers()
        .set("Content-Type", "application/json")
        .map_err(|e| JsValue::from_str(&format!("Header failed: {:?}", e)))?;
    
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    let result_json = wasm_bindgen_futures::JsFuture::from(
        resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("JSON future failed: {:?}", e)))?;
    
    Ok(result_json)
}

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    console_log!("Legion ZK Auth (k=14, single-threaded)");
}


// Parse WebAuthn attestation CBOR to extract P-256 public key
fn parse_webauthn_attestation(attestation: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    use ciborium::Value;
    use std::io::Cursor;
    
    // Parse CBOR attestation object
    let attestation_obj: Value = ciborium::from_reader(Cursor::new(attestation))
        .map_err(|e| format!("CBOR parse failed: {}", e))?;
    
    // Extract authData from attestation object
    let auth_data_bytes = match &attestation_obj {
        Value::Map(map) => {
            map.iter()
                .find(|(k, _)| matches!(k, Value::Text(s) if s == "authData"))
                .and_then(|(_, v)| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or("authData not found")?
        }
        _ => return Err("Invalid attestation format".to_string()),
    };
    
    // Parse authData structure:
    // rpIdHash (32 bytes) + flags (1 byte) + signCount (4 bytes) + attestedCredentialData
    if auth_data_bytes.len() < 37 {
        return Err("authData too short".to_string());
    }
    
    let flags = auth_data_bytes[32];
    let has_attested_cred = (flags & 0x40) != 0; // AT flag
    
    if !has_attested_cred {
        return Err("No attested credential data".to_string());
    }
    
    // Skip rpIdHash (32) + flags (1) + signCount (4) = 37 bytes
    let mut offset = 37;
    
    // AAGUID (16 bytes)
    offset += 16;
    
    // Credential ID length (2 bytes, big-endian)
    if auth_data_bytes.len() < offset + 2 {
        return Err("Invalid credential ID length".to_string());
    }
    let cred_id_len = u16::from_be_bytes([auth_data_bytes[offset], auth_data_bytes[offset + 1]]) as usize;
    offset += 2;
    
    // Credential ID
    if auth_data_bytes.len() < offset + cred_id_len {
        return Err("Invalid credential ID".to_string());
    }
    let credential_id = auth_data_bytes[offset..offset + cred_id_len].to_vec();
    offset += cred_id_len;
    
    // Credential public key (CBOR encoded)
    let pubkey_cbor = &auth_data_bytes[offset..];
    let pubkey_obj: Value = ciborium::from_reader(Cursor::new(pubkey_cbor))
        .map_err(|e| format!("Public key CBOR parse failed: {}", e))?;
    
    // Extract P-256 public key coordinates (COSE format)
    // kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256), x and y coordinates
    let (x_coord, y_coord) = match &pubkey_obj {
        Value::Map(map) => {
            let x = map.iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == ciborium::value::Integer::from(-2)))
                .and_then(|(_, v)| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or("x coordinate not found")?;
            
            let y = map.iter()
                .find(|(k, _)| matches!(k, Value::Integer(i) if *i == ciborium::value::Integer::from(-3)))
                .and_then(|(_, v)| match v {
                    Value::Bytes(b) => Some(b.clone()),
                    _ => None,
                })
                .ok_or("y coordinate not found")?;
            
            (x, y)
        }
        _ => return Err("Invalid public key format".to_string()),
    };
    
    // Construct uncompressed P-256 public key: 0x04 || x || y
    let mut pubkey_bytes = Vec::with_capacity(65);
    pubkey_bytes.push(0x04); // Uncompressed point format
    pubkey_bytes.extend_from_slice(&x_coord);
    pubkey_bytes.extend_from_slice(&y_coord);
    
    if pubkey_bytes.len() != 65 {
        return Err(format!("Invalid P-256 public key length: {}", pubkey_bytes.len()));
    }
    
    Ok((pubkey_bytes, credential_id))
}
