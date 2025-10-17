#[cfg(feature = "webauthn")]
use anyhow::Result;
#[cfg(feature = "webauthn")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
#[cfg(all(feature = "webauthn", feature = "redis"))]
use redis::Commands;
#[cfg(all(feature = "webauthn", feature = "rocksdb-storage"))]
use rocksdb::DB;
#[cfg(feature = "webauthn")]
use std::sync::Arc;
#[cfg(feature = "webauthn")]
use url::Url;
#[cfg(feature = "webauthn")]
use webauthn_rs::prelude::*;

#[cfg(feature = "webauthn")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebAuthnCredential {
    pub user_id: String,
    pub passkey: Passkey,
}

#[cfg(feature = "webauthn")]
pub struct WebAuthnService {
    webauthn: Arc<Webauthn>,
    #[cfg(feature = "rocksdb-storage")]
    db: Arc<DB>,
}

#[cfg(feature = "webauthn")]
impl WebAuthnService {
    pub fn new(rp_id: &str, rp_origin: &str) -> Result<Self> {
        let rp_origin = Url::parse(rp_origin)?;
        let builder = WebauthnBuilder::new(rp_id, &rp_origin)?;
        let webauthn = Arc::new(builder.build()?);

        #[cfg(feature = "rocksdb-storage")]
        let db = {
            let path = "./legion_data/webauthn_credentials";
            std::fs::create_dir_all(path)?;
            Arc::new(DB::open_default(path)?)
        };

        Ok(Self {
            webauthn,
            #[cfg(feature = "rocksdb-storage")]
            db,
        })
    }

    /// Start registration - generates challenge and returns state to store
    pub fn start_registration(
        &self,
        user_id: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_unique_id = Uuid::new_v4();

        let (ccr, passkey_reg_state) =
            self.webauthn
                .start_passkey_registration(user_unique_id, user_id, user_id, None)?;

        // Return both: challenge for client AND state for server to store
        Ok((ccr, passkey_reg_state))
    }

    /// Store registration state in Redis (5 min expiration)
    #[cfg(feature = "redis")]
    pub fn store_reg_state(&self, user_id: &str, state: PasskeyRegistration) {
        if let Ok(mut conn) = self.get_redis_connection() {
            let key = format!("legion:webauthn:reg:{}", user_id);
            let value = serde_json::to_string(&state).unwrap();
            let _: Result<(), redis::RedisError> = conn.set_ex(&key, value, 300);
            // 5 min
        }
    }

    /// Get stored registration state from Redis
    #[cfg(feature = "redis")]
    pub fn get_reg_state(&self, user_id: &str) -> Result<PasskeyRegistration> {
        let mut conn = self.get_redis_connection()?;
        let key = format!("legion:webauthn:reg:{}", user_id);
        let value: String = conn.get_del(&key)?; // Get and delete atomically
        Ok(serde_json::from_str(&value)?)
    }

    #[cfg(not(feature = "redis"))]
    pub fn store_reg_state(&self, _user_id: &str, _state: PasskeyRegistration) {}

    #[cfg(not(feature = "redis"))]
    pub fn get_reg_state(&self, _user_id: &str) -> Result<PasskeyRegistration> {
        Err(anyhow::anyhow!("Redis required for WebAuthn state"))
    }

    /// Finish registration - verifies attestation and stores credential
    pub fn finish_registration(
        &self,
        reg_request: &RegisterPublicKeyCredential,
        passkey_reg_state: PasskeyRegistration,
    ) -> Result<String> {
        // ✅ REAL CRYPTO: Verifies attestation, challenge, signature
        let passkey = self
            .webauthn
            .finish_passkey_registration(reg_request, &passkey_reg_state)?;

        let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id());
        // Store with a generated user_id (we'll track this separately)
        let user_id = credential_id.clone();

        // Store credential in RocksDB
        #[cfg(feature = "rocksdb-storage")]
        {
            let cred = WebAuthnCredential {
                user_id: user_id.clone(),
                passkey,
            };
            let key = format!("cred:{}", user_id);
            let value = serde_json::to_vec(&cred)?;
            self.db.put(key.as_bytes(), value)?;
        }

        Ok(credential_id)
    }

    /// Start authentication - generates challenge and returns state to store
    pub fn start_authentication(
        &self,
        session_id: &str,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        // Load credential from RocksDB using session ID (preserves anonymity)
        #[cfg(feature = "rocksdb-storage")]
        let cred: WebAuthnCredential = {
            let key = format!("session_cred:{}", session_id);
            let value = self
                .db
                .get(key.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("No credential bound to this session"))?;
            serde_json::from_slice(&value)?
        };

        #[cfg(not(feature = "rocksdb-storage"))]
        return Err(anyhow::anyhow!("RocksDB required for WebAuthn"));

        let user_passkeys = vec![cred.passkey.clone()];
        let (rcr, passkey_auth_state) =
            self.webauthn.start_passkey_authentication(&user_passkeys)?;

        Ok((rcr, passkey_auth_state))
    }

    /// Store authentication state in Redis (5 min expiration)
    #[cfg(feature = "redis")]
    pub fn store_auth_state(&self, user_id: &str, state: PasskeyAuthentication) {
        if let Ok(mut conn) = self.get_redis_connection() {
            let key = format!("legion:webauthn:auth:{}", user_id);
            let value = serde_json::to_string(&state).unwrap();
            let _: Result<(), redis::RedisError> = conn.set_ex(&key, value, 300);
            // 5 min
        }
    }

    /// Get stored authentication state from Redis
    #[cfg(feature = "redis")]
    pub fn get_auth_state(&self, user_id: &str) -> Result<PasskeyAuthentication> {
        let mut conn = self.get_redis_connection()?;
        let key = format!("legion:webauthn:auth:{}", user_id);
        let value: String = conn.get_del(&key)?; // Get and delete atomically
        Ok(serde_json::from_str(&value)?)
    }

    #[cfg(not(feature = "redis"))]
    pub fn store_auth_state(&self, _user_id: &str, _state: PasskeyAuthentication) {}

    #[cfg(not(feature = "redis"))]
    pub fn get_auth_state(&self, _user_id: &str) -> Result<PasskeyAuthentication> {
        Err(anyhow::anyhow!("Redis required for WebAuthn state"))
    }

    /// Finish authentication - verifies signature and updates counter
    pub fn finish_authentication(
        &self,
        auth_request: &PublicKeyCredential,
        passkey_auth_state: PasskeyAuthentication,
    ) -> Result<String> {
        // ✅ REAL CRYPTO: Verifies challenge, RP ID, signature, counter
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth_request, &passkey_auth_state)?;

        #[cfg(feature = "rocksdb-storage")]
        {
            // Get credential ID from auth result
            let cred_id_bytes = auth_result.cred_id();
            let cred_id_str = URL_SAFE_NO_PAD.encode(cred_id_bytes);

            // Direct lookup using credential ID (no full scan)
            let key = format!("cred:{}", cred_id_str);
            let value = self
                .db
                .get(key.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("Credential not found"))?;

            let mut cred = serde_json::from_slice::<WebAuthnCredential>(&value)?;

            // 🚨 CRITICAL: Update signature counter to prevent replay attacks
            cred.passkey.update_credential(&auth_result);

            // 🚨 CRITICAL: Persist updated counter back to database
            let updated_value = serde_json::to_vec(&cred)?;
            self.db.put(key.as_bytes(), updated_value)?;

            println!("✅ Authentication successful. Counter updated.");

            return Ok(cred.user_id);
        }

        #[cfg(not(feature = "rocksdb-storage"))]
        return Err(anyhow::anyhow!("RocksDB required for WebAuthn"));
    }

    /// Bind credential to session (called after login)
    pub fn bind_credential_to_session(&self, user_id: &str, session_id: &str) -> Result<()> {
        #[cfg(feature = "rocksdb-storage")]
        {
            let user_key = format!("cred:{}", user_id);
            let value = self
                .db
                .get(user_key.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("No credential found for user"))?;

            // Store credential under session ID (anonymous lookup)
            let session_key = format!("session_cred:{}", session_id);
            self.db.put(session_key.as_bytes(), value)?;
            Ok(())
        }

        #[cfg(not(feature = "rocksdb-storage"))]
        Err(anyhow::anyhow!("RocksDB required for WebAuthn"))
    }

    /// Get credential ID for user (for initial binding)
    pub fn get_credential_id(&self, user_id: &str) -> Option<String> {
        #[cfg(feature = "rocksdb-storage")]
        {
            let key = format!("cred:{}", user_id);
            if let Ok(Some(value)) = self.db.get(key.as_bytes()) {
                if let Ok(cred) = serde_json::from_slice::<WebAuthnCredential>(&value) {
                    return Some(URL_SAFE_NO_PAD.encode(cred.passkey.cred_id()));
                }
            }
        }
        #[cfg(not(feature = "rocksdb-storage"))]
        return None;

        None
    }

    #[cfg(feature = "redis")]
    fn get_redis_connection(&self) -> Result<redis::Connection> {
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
        let client = redis::Client::open(redis_url)?;
        Ok(client.get_connection()?)
    }
}

// Stub for when webauthn feature is disabled
#[cfg(not(feature = "webauthn"))]
pub struct WebAuthnService;

#[cfg(not(feature = "webauthn"))]
impl WebAuthnService {
    pub fn new(_rp_id: &str, _rp_origin: &str) -> anyhow::Result<Self> {
        Ok(Self)
    }
}
