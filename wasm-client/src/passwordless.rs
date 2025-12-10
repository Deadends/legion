// BIP-39 Passwordless Authentication
use wasm_bindgen::prelude::*;
use bip39::Mnemonic;
use legion_prover::Fp;
use ff::{FromUniformBytes, PrimeField};

// Generate 24-word recovery phrase
#[wasm_bindgen]
pub fn generate_recovery_phrase() -> Result<String, JsValue> {
    let mnemonic = Mnemonic::generate(24)
        .map_err(|e| JsValue::from_str(&format!("Mnemonic generation failed: {}", e)))?;
    Ok(mnemonic.to_string())
}

// Derive account_id from phrase (deterministic)
#[wasm_bindgen]
pub fn derive_account_id(phrase: &str) -> Result<String, JsValue> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| JsValue::from_str(&format!("Invalid phrase: {}", e)))?;
    
    let seed = mnemonic.to_seed("");  // No passphrase
    let master_key = &seed[..32];
    
    // Derive account_id using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LEGION_ACCOUNT_V2");
    hasher.update(master_key);
    let account_hash = hasher.finalize();
    
    let account_id_fp = Fp::from_uniform_bytes(&{
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(account_hash.as_bytes());
        buf[32..].copy_from_slice(account_hash.as_bytes());
        buf
    });
    
    Ok(hex::encode(account_id_fp.to_repr()))
}

// Internal version that returns Fp
pub(crate) fn derive_account_id_fp(phrase: &str) -> Result<Fp, JsValue> {
    let mnemonic = Mnemonic::parse(phrase)
        .map_err(|e| JsValue::from_str(&format!("Invalid phrase: {}", e)))?;
    
    let seed = mnemonic.to_seed("");  // No passphrase
    let master_key = &seed[..32];
    
    // Derive account_id using Blake3
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"LEGION_ACCOUNT_V2");
    hasher.update(master_key);
    let account_hash = hasher.finalize();
    
    Ok(Fp::from_uniform_bytes(&{
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(account_hash.as_bytes());
        buf[32..].copy_from_slice(account_hash.as_bytes());
        buf
    }))
}

// Validate recovery phrase
#[wasm_bindgen]
pub fn validate_recovery_phrase(phrase: String) -> bool {
    Mnemonic::parse(&phrase).is_ok()
}
