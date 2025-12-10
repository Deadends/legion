// Device Manager - 2 devices per user with zero-knowledge
use wasm_bindgen::prelude::*;
use web_sys::Storage;

// Helper: Count devices for user (max 2)
pub fn count_user_devices(storage: &Storage, user_key: &str) -> Result<usize, JsValue> {
    let mut count = 0;
    
    // Check device_1
    if storage.get_item(&format!("legion_device_{}_1_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_some() {
        count += 1;
    }
    
    // Check device_2
    if storage.get_item(&format!("legion_device_{}_2_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_some() {
        count += 1;
    }
    
    Ok(count)
}

// Helper: Get next available device slot (1 or 2)
pub fn get_next_device_slot(storage: &Storage, user_key: &str) -> Result<u8, JsValue> {
    // Check device_1
    if storage.get_item(&format!("legion_device_{}_1_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_none() {
        return Ok(1);
    }
    
    // Check device_2
    if storage.get_item(&format!("legion_device_{}_2_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_none() {
        return Ok(2);
    }
    
    Err(JsValue::from_str("No available device slots (max 2 devices)"))
}

// Helper: Detect current device (returns key like "legion_device_xxx_1_credential_id")
pub fn detect_current_device(storage: &Storage, user_key: &str) -> Result<String, JsValue> {
    // Try device_1
    let device_1_key = format!("legion_device_{}_1_credential_id", &user_key[..16]);
    if storage.get_item(&device_1_key)
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_some() {
        return Ok(device_1_key);
    }
    
    // Try device_2
    let device_2_key = format!("legion_device_{}_2_credential_id", &user_key[..16]);
    if storage.get_item(&device_2_key)
        .map_err(|_| JsValue::from_str("Storage read failed"))?
        .is_some() {
        return Ok(device_2_key);
    }
    
    // No device found - will create new one
    Err(JsValue::from_str("No device found"))
}

// Helper: Revoke device (zero-knowledge - only removes local data)
#[wasm_bindgen]
pub fn revoke_device_local(user_key: String, device_slot: u8) -> Result<(), JsValue> {
    let window = web_sys::window().ok_or("No window")?;
    let storage = window.local_storage()
        .map_err(|_| JsValue::from_str("No localStorage"))?
        .ok_or("No localStorage")?;
    
    if device_slot != 1 && device_slot != 2 {
        return Err(JsValue::from_str("Invalid device slot (must be 1 or 2)"));
    }
    
    // Remove all device data
    storage.remove_item(&format!("legion_device_{}_{}_{}", &user_key[..16], device_slot, "credential_id"))
        .map_err(|_| JsValue::from_str("Failed to remove credential_id"))?;
    storage.remove_item(&format!("legion_device_{}_{}_{}", &user_key[..16], device_slot, "pubkey"))
        .map_err(|_| JsValue::from_str("Failed to remove pubkey"))?;
    storage.remove_item(&format!("legion_device_{}_{}_{}", &user_key[..16], device_slot, "commitment"))
        .map_err(|_| JsValue::from_str("Failed to remove commitment"))?;
    storage.remove_item(&format!("legion_device_{}_{}_{}", &user_key[..16], device_slot, "position"))
        .map_err(|_| JsValue::from_str("Failed to remove position"))?;
    
    Ok(())
}

// Helper: List user devices (zero-knowledge - only shows local data)
#[wasm_bindgen]
pub fn list_user_devices(user_key: String) -> Result<JsValue, JsValue> {
    use serde::Serialize;
    
    #[derive(Serialize)]
    struct DeviceInfo {
        slot: u8,
        credential_id: String,
        exists: bool,
    }
    
    let window = web_sys::window().ok_or("No window")?;
    let storage = window.local_storage()
        .map_err(|_| JsValue::from_str("No localStorage"))?
        .ok_or("No localStorage")?;
    
    let mut devices = Vec::new();
    
    // Check device_1
    if let Some(cred_id) = storage.get_item(&format!("legion_device_{}_1_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))? {
        devices.push(DeviceInfo {
            slot: 1,
            credential_id: cred_id[..16].to_string(),
            exists: true,
        });
    }
    
    // Check device_2
    if let Some(cred_id) = storage.get_item(&format!("legion_device_{}_2_credential_id", &user_key[..16]))
        .map_err(|_| JsValue::from_str("Storage read failed"))? {
        devices.push(DeviceInfo {
            slot: 2,
            credential_id: cred_id[..16].to_string(),
            exists: true,
        });
    }
    
    serde_wasm_bindgen::to_value(&devices)
        .map_err(|e| JsValue::from_str(&format!("Serialize failed: {}", e)))
}
