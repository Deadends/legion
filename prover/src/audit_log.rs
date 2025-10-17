// Audit logging for authentication events
use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthAttempt {
    pub timestamp: u64,
    pub username: String,
    pub success: bool,
    pub security_level: String,
    pub client_ip: Option<String>,
    pub error: Option<String>,
}

pub fn log_auth_attempt(
    username: &str,
    success: bool,
    security_level: &str,
    client_ip: Option<&str>,
    error: Option<&str>,
) -> Result<()> {
    let attempt = AuthAttempt {
        timestamp: crate::get_timestamp(),
        username: username.to_string(),
        success,
        security_level: security_level.to_string(),
        client_ip: client_ip.map(|s| s.to_string()),
        error: error.map(|s| s.to_string()),
    };
    
    let log_entry = serde_json::to_string(&attempt)?;
    
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("legion_audit.log")?;
    
    writeln!(file, "{}", log_entry)?;
    
    Ok(())
}
