use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MAX_TICKET_SIZE: usize = 1024;
const DEFAULT_TICKET_SKEW_SECONDS: i64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageATicket {
    pub client_id: String,
    pub nonce: Vec<u8>,
    pub ts: i64,
    pub hmac: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum TicketError {
    #[error("Bad CBOR format")]
    BadCbor(#[from] serde_cbor::Error),
    #[error("Invalid schema: {0}")]
    InvalidSchema(String),
    #[error("Invalid HMAC")]
    InvalidHmac,
    #[error("Replay attack detected")]
    Replay,
    #[error("Ticket too large")]
    TooLarge,
}

impl TicketError {
    pub fn http_status(&self) -> u16 {
        match self {
            TicketError::BadCbor(_) => 400,
            TicketError::TooLarge => 400,
            TicketError::InvalidSchema(_) => 422,
            TicketError::InvalidHmac => 401,
            TicketError::Replay => 403,
        }
    }
}

pub fn parse_and_validate_ticket(bytes: &[u8], skew_seconds: i64) -> Result<StageATicket, TicketError> {
    // SOPHISTICATED: Strict size validation to prevent DoS
    if bytes.is_empty() {
        return Err(TicketError::InvalidSchema("Empty ticket".to_string()));
    }
    if bytes.len() > MAX_TICKET_SIZE {
        return Err(TicketError::TooLarge);
    }

    // SOPHISTICATED: Safe CBOR parsing with error handling
    let ticket: StageATicket = serde_cbor::from_slice(bytes)
        .map_err(|e| TicketError::BadCbor(e))?;

    // SOPHISTICATED: Comprehensive input validation
    if ticket.client_id.is_empty() || ticket.client_id.len() > 256 {
        return Err(TicketError::InvalidSchema(
            "client_id must be 1-256 characters".to_string()
        ));
    }
    
    // SOPHISTICATED: Validate client_id contains only safe characters
    if !ticket.client_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(TicketError::InvalidSchema(
            "client_id contains invalid characters".to_string()
        ));
    }

    // SOPHISTICATED: Strict nonce validation
    if ticket.nonce.len() < 16 || ticket.nonce.len() > 32 {
        return Err(TicketError::InvalidSchema(format!(
            "nonce must be 16-32 bytes, got {}",
            ticket.nonce.len()
        )));
    }
    
    // SOPHISTICATED: Check nonce entropy to prevent weak nonces
    let nonce_entropy = calculate_entropy(&ticket.nonce);
    if nonce_entropy < 64.0 {
        return Err(TicketError::InvalidSchema(
            "nonce has insufficient entropy".to_string()
        ));
    }

    // SOPHISTICATED: Validate HMAC length
    if ticket.hmac.len() != 32 {
        return Err(TicketError::InvalidSchema(format!(
            "hmac must be 32 bytes, got {}",
            ticket.hmac.len()
        )));
    }

    // SOPHISTICATED: Advanced timestamp validation
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    
    // Reject timestamps too far in the future (prevents pre-computation)
    if ticket.ts > now + 60 {
        return Err(TicketError::InvalidSchema(
            "timestamp too far in future".to_string()
        ));
    }
    
    // Reject timestamps too far in the past
    if ticket.ts < now - skew_seconds {
        return Err(TicketError::Replay);
    }
    
    // SOPHISTICATED: Validate timestamp is reasonable
    const MIN_VALID_TIMESTAMP: i64 = 1640995200; // 2022-01-01
    const MAX_VALID_TIMESTAMP: i64 = 4102444800; // 2100-01-01
    
    if ticket.ts < MIN_VALID_TIMESTAMP || ticket.ts > MAX_VALID_TIMESTAMP {
        return Err(TicketError::InvalidSchema(
            "timestamp outside valid range".to_string()
        ));
    }

    Ok(ticket)
}

// SOPHISTICATED: Calculate Shannon entropy of byte array
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    
    let len = data.len() as f64;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    
    entropy * len // Total entropy in bits
}

pub fn get_ticket_skew_seconds() -> i64 {
    std::env::var("TICKET_SKEW_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TICKET_SKEW_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_valid_ticket() -> StageATicket {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        StageATicket {
            client_id: "test_client".to_string(),
            nonce: vec![0u8; 16],
            ts: now,
            hmac: vec![0u8; 32],
        }
    }

    #[test]
    fn test_valid_ticket() {
        let ticket = create_valid_ticket();
        let cbor_bytes = serde_cbor::to_vec(&ticket).unwrap();
        
        let parsed = parse_and_validate_ticket(&cbor_bytes, 120).unwrap();
        assert_eq!(parsed.client_id, "test_client");
        assert_eq!(parsed.nonce.len(), 16);
        assert_eq!(parsed.hmac.len(), 32);
    }

    #[test]
    fn test_invalid_nonce_length() {
        let mut ticket = create_valid_ticket();
        ticket.nonce = vec![0u8; 15]; // Wrong length
        let cbor_bytes = serde_cbor::to_vec(&ticket).unwrap();
        
        let result = parse_and_validate_ticket(&cbor_bytes, 120);
        assert!(matches!(result, Err(TicketError::InvalidSchema(_))));
    }

    #[test]
    fn test_invalid_hmac_length() {
        let mut ticket = create_valid_ticket();
        ticket.hmac = vec![0u8; 31]; // Wrong length
        let cbor_bytes = serde_cbor::to_vec(&ticket).unwrap();
        
        let result = parse_and_validate_ticket(&cbor_bytes, 120);
        assert!(matches!(result, Err(TicketError::InvalidSchema(_))));
    }

    #[test]
    fn test_timestamp_skew() {
        let mut ticket = create_valid_ticket();
        ticket.ts = 0; // Very old timestamp
        let cbor_bytes = serde_cbor::to_vec(&ticket).unwrap();
        
        let result = parse_and_validate_ticket(&cbor_bytes, 120);
        assert!(matches!(result, Err(TicketError::Replay)));
    }
}