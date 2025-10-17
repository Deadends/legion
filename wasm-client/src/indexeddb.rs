use idb::{Database, DatabaseEvent, Factory, ObjectStoreParams, TransactionMode};
use wasm_bindgen::prelude::*;

const DB_NAME: &str = "LegionParamsDB";
const PARAMS_STORE_NAME: &str = "proving_parameters";

pub struct IndexedDBCache {
    db: Database,
}

impl IndexedDBCache {
    pub async fn new() -> Result<Self, JsValue> {
        let map_err = |e: idb::Error| JsValue::from_str(&e.to_string());

        let factory = Factory::new().map_err(map_err)?;
        let mut open_request = factory.open(DB_NAME, Some(1)).map_err(map_err)?;
        
        open_request.on_upgrade_needed(|event| {
            let db = event.database().unwrap();
            let params = ObjectStoreParams::new();
            let _ = db.create_object_store(PARAMS_STORE_NAME, params);
        });

        let db = open_request.await.map_err(map_err)?;
        Ok(Self { db })
    }

    pub async fn get_params(&self, k: u32) -> Result<Option<Vec<u8>>, JsValue> {
        let map_err = |e: idb::Error| JsValue::from_str(&e.to_string());

        let tx = self.db.transaction(&[PARAMS_STORE_NAME], TransactionMode::ReadOnly).map_err(map_err)?;
        let store = tx.object_store(PARAMS_STORE_NAME).map_err(map_err)?;
        
        let key = JsValue::from_str(&format!("legion_params_k{}", k));
        let value = store.get(key).map_err(map_err)?.await.map_err(map_err)?;
        
        if let Some(val) = value {
            let array = js_sys::Uint8Array::new(&val);
            Ok(Some(array.to_vec()))
        } else {
            Ok(None)
        }
    }

    pub async fn set_params(&self, k: u32, params: &[u8]) -> Result<(), JsValue> {
        let map_err = |e: idb::Error| JsValue::from_str(&e.to_string());

        let tx = self.db.transaction(&[PARAMS_STORE_NAME], TransactionMode::ReadWrite).map_err(map_err)?;
        let store = tx.object_store(PARAMS_STORE_NAME).map_err(map_err)?;
        
        let key = JsValue::from_str(&format!("legion_params_k{}", k));
        let val = js_sys::Uint8Array::from(params);

        store.put(&val, Some(&key)).map_err(map_err)?.await.map_err(map_err)?;
        Ok(())
    }

    pub async fn clear_cache(&self) -> Result<(), JsValue> {
        let map_err = |e: idb::Error| JsValue::from_str(&e.to_string());

        let tx = self.db.transaction(&[PARAMS_STORE_NAME], TransactionMode::ReadWrite).map_err(map_err)?;
        let store = tx.object_store(PARAMS_STORE_NAME).map_err(map_err)?;

        store.clear().map_err(map_err)?.await.map_err(map_err)?;
        Ok(())
    }
}
