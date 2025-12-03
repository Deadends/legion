// Local Merkle Tree Storage Module
// Replaces PIR with local tree download for TRUE zero-knowledge

use wasm_bindgen::prelude::*;
use serde::Deserialize;
use legion_prover::Fp;
use ff::PrimeField;
use legion_prover::halo2_gadgets::poseidon::primitives as poseidon;
use crate::{console_log, log};

#[derive(Debug, Deserialize)]
pub struct DownloadTreeResponse {
    pub merkle_root: String,
    pub tree_data: Vec<String>,
    pub tree_size: usize,
    pub version: u64,
}

/// Download full Merkle tree from server and cache in IndexedDB
pub async fn download_and_cache_tree(
    window: &web_sys::Window,
    server_url: &str,
) -> Result<DownloadTreeResponse, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode, Response};
    
    console_log!("📥 Downloading full Merkle tree for local storage...");
    
    let url = format!("{}/api/download-tree", server_url);
    let opts = RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(RequestMode::Cors);
    
    let request = Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let resp: Response = resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    if !resp.ok() {
        return Err(JsValue::from_str(&format!("Server error: {}", resp.status())));
    }
    
    let json = wasm_bindgen_futures::JsFuture::from(
        resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await.map_err(|e| JsValue::from_str(&format!("JSON future failed: {:?}", e)))?;
    
    let tree_data: DownloadTreeResponse = serde_wasm_bindgen::from_value(json)
        .map_err(|e| JsValue::from_str(&format!("Deserialize failed: {}", e)))?;
    
    console_log!("✅ Downloaded {} leaves ({} MB)", 
        tree_data.tree_data.len(), 
        tree_data.tree_size / 1_000_000
    );
    
    // Cache in IndexedDB
    cache_tree_data(&tree_data).await?;
    
    Ok(tree_data)
}

/// Cache tree data in IndexedDB
async fn cache_tree_data(tree_data: &DownloadTreeResponse) -> Result<(), JsValue> {
    use crate::indexeddb::IndexedDBCache;
    
    console_log!("💾 Caching tree in IndexedDB...");
    
    let cache = IndexedDBCache::new().await?;
    
    // Store tree data as JSON string
    let tree_json = serde_json::to_string(&tree_data.tree_data)
        .map_err(|e| JsValue::from_str(&format!("JSON serialize failed: {}", e)))?;
    
    cache.set_item("merkle_tree_leaves", &tree_json).await?;
    cache.set_item("merkle_tree_root", &tree_data.merkle_root).await?;
    cache.set_item("merkle_tree_version", &tree_data.version.to_string()).await?;
    
    console_log!("✅ Tree cached successfully");
    
    Ok(())
}

/// Load cached tree from IndexedDB
pub async fn load_cached_tree() -> Result<Vec<String>, JsValue> {
    use crate::indexeddb::IndexedDBCache;
    
    let cache = IndexedDBCache::new().await?;
    
    let tree_json = cache.get_item("merkle_tree_leaves").await?
        .ok_or_else(|| JsValue::from_str("No cached tree found"))?;
    
    let leaves: Vec<String> = serde_json::from_str(&tree_json)
        .map_err(|e| JsValue::from_str(&format!("JSON parse failed: {}", e)))?;
    
    Ok(leaves)
}

/// Compute Merkle path locally from cached tree (Zcash/Semaphore standard)
/// SYNCHRONOUS version - tree data must be pre-loaded to avoid RefCell conflicts
pub fn compute_merkle_path_sync(
    tree_index: usize,
    leaves: &[String],
) -> Result<([Fp; 20], Fp), JsValue> {
    console_log!("🔍 Computing Merkle path locally for index {}", tree_index);
    
    if tree_index >= leaves.len() {
        return Err(JsValue::from_str(&format!(
            "Invalid tree_index: {} >= {}", tree_index, leaves.len()
        )));
    }
    
    let mut tree: Vec<Fp> = leaves.iter()
        .map(|hex| {
            let bytes = hex::decode(hex).map_err(|_| JsValue::from_str("Invalid hex"))?;
            let mut repr = [0u8; 32];
            repr.copy_from_slice(&bytes);
            Option::from(Fp::from_repr(repr))
                .ok_or_else(|| JsValue::from_str("Invalid field element"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    
    let mut path = [Fp::zero(); 20];
    let mut current_index = tree_index;
    
    for level in 0..20 {
        let sibling_index = current_index ^ 1;
        if sibling_index < tree.len() {
            path[level] = tree[sibling_index];
        } else {
            path[level] = Fp::zero();
        }
        
        let mut next_level = Vec::new();
        for i in (0..tree.len()).step_by(2) {
            let left = tree[i];
            let right = if i + 1 < tree.len() { tree[i + 1] } else { Fp::zero() };
            let parent = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
                .hash([left, right]);
            next_level.push(parent);
        }
        
        tree = next_level;
        current_index /= 2;
        
        if tree.len() == 1 {
            break;
        }
    }
    
    let root = tree[0];
    console_log!("✅ Merkle path computed locally (no server query)");
    
    Ok((path, root))
}

/// Check if tree needs update
pub async fn check_tree_version(
    window: &web_sys::Window,
    server_url: &str,
) -> Result<bool, JsValue> {
    use crate::indexeddb::IndexedDBCache;
    
    let cache = IndexedDBCache::new().await?;
    
    let local_version: u64 = cache.get_item("merkle_tree_version").await
        .ok()
        .flatten()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    // Quick check: download just metadata
    let url = format!("{}/api/download-tree", server_url);
    let opts = web_sys::RequestInit::new();
    opts.set_method("GET");
    opts.set_mode(web_sys::RequestMode::Cors);
    
    let request = web_sys::Request::new_with_str_and_init(&url, &opts)
        .map_err(|e| JsValue::from_str(&format!("Request failed: {:?}", e)))?;
    
    let resp_value = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_request(&request)
    ).await.map_err(|e| JsValue::from_str(&format!("Fetch failed: {:?}", e)))?;
    
    let resp: web_sys::Response = resp_value.dyn_into()
        .map_err(|_| JsValue::from_str("Response cast failed"))?;
    
    let json = wasm_bindgen_futures::JsFuture::from(
        resp.json().map_err(|e| JsValue::from_str(&format!("JSON failed: {:?}", e)))?
    ).await?;
    
    let tree_data: DownloadTreeResponse = serde_wasm_bindgen::from_value(json)
        .map_err(|e| JsValue::from_str(&format!("Deserialize failed: {}", e)))?;
    
    if tree_data.version > local_version {
        console_log!("🔄 Tree updated (v{} -> v{}), re-downloading...", 
            local_version, tree_data.version);
        Ok(true)
    } else {
        console_log!("✅ Tree up-to-date (v{})", local_version);
        Ok(false)
    }
}

// console_log macro already defined in lib.rs
