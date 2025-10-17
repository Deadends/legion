use crate::error::{Result, SidecarError};
use blake2::{Blake2b512, Digest};
use pasta_curves::Fp;
use rustls::ServerConnection;
use std::io;
use tokio_rustls::server::TlsStream;
use zeroize::Zeroize;

// OpenSSL removed - using rustls only

pub type FieldBytes = [u8; 32];

/// Export TLS binding material using rustls exporter
pub fn server_export_binding_rustls(conn_ref: &TlsStream<tokio::net::TcpStream>) -> Result<[u8; 32]> {
    {
        let mut binding = [0u8; 32];
        
        // Access the rustls connection
        let (_, server_conn) = conn_ref.get_ref();
        
        // Export keying material using rustls
        server_conn
            .export_keying_material(
                &mut binding,
                b"EXPORTER-legion-binding",
                Some(b"context"),
            )
            .map_err(|e| SidecarError::Tls(format!("Failed to export keying material: {:?}", e)))?;
        
        Ok(binding)
    }
}

// OpenSSL support removed - using rustls only

/// Convert TLS binding to field element
pub fn binding_to_field(binding: &[u8]) -> Fp {
    let mut hasher = Blake2b512::new();
    hasher.update(binding);
    let hash = hasher.finalize();
    
    // Convert to field element using from_bytes_wide for proper reduction
    let mut wide_bytes = [0u8; 64];
    wide_bytes.copy_from_slice(&hash);
    
    Fp::from_bytes_wide(&wide_bytes)
}

/// Public API for TLS binding field conversion
pub fn tls_binding_field(binding: &[u8]) -> Result<FieldBytes> {
    if binding.len() != 32 {
        return Err(SidecarError::Internal(
            "TLS binding must be exactly 32 bytes".to_string(),
        ));
    }
    
    let field_element = binding_to_field(binding);
    let field_bytes = field_element.to_bytes();
    
    Ok(field_bytes)
}

/// Server nonce for browser fallback
#[derive(Clone)]
pub struct ServerNonce {
    pub nonce: [u8; 32],
    pub created_at: std::time::Instant,
    pub ttl_secs: u64,
}

impl ServerNonce {
    pub fn new(ttl_secs: u64) -> Self {
        let mut nonce = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut nonce);
        
        Self {
            nonce,
            created_at: std::time::Instant::now(),
            ttl_secs,
        }
    }
    
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() > self.ttl_secs
    }
}

impl Drop for ServerNonce {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}

/// Compute session binding for browser clients
pub fn compute_session_binding(server_nonce: &[u8], client_secret: &[u8]) -> Result<FieldBytes> {
    let mut hasher = Blake2b512::new();
    hasher.update(server_nonce);
    hasher.update(client_secret);
    let hash = hasher.finalize();
    
    let field_element = Fp::from_bytes_wide(&{
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&hash);
        wide
    });
    
    Ok(field_element.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_binding_to_field_deterministic() {
        let binding = [0x42u8; 32];
        let field1 = binding_to_field(&binding);
        let field2 = binding_to_field(&binding);
        assert_eq!(field1, field2);
    }
    
    #[test]
    fn test_tls_binding_field() {
        let binding = [0x42u8; 32];
        let result = tls_binding_field(&binding).unwrap();
        assert_eq!(result.len(), 32);
    }
    
    #[test]
    fn test_server_nonce_expiry() {
        let nonce = ServerNonce::new(1);
        assert!(!nonce.is_expired());
        
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(nonce.is_expired());
    }
    
    #[test]
    fn test_session_binding_computation() {
        let server_nonce = [0x11u8; 32];
        let client_secret = [0x22u8; 32];
        
        let binding1 = compute_session_binding(&server_nonce, &client_secret).unwrap();
        let binding2 = compute_session_binding(&server_nonce, &client_secret).unwrap();
        
        assert_eq!(binding1, binding2);
        assert_eq!(binding1.len(), 32);
    }
}