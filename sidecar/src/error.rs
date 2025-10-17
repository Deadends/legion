use thiserror::Error;

pub type Result<T> = std::result::Result<T, SidecarError>;

#[derive(Error, Debug)]
pub enum SidecarError {
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    #[error("ZK proof verification failed: {0}")]
    ZkVerification(String),
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Request timeout")]
    Timeout,
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Configuration error: {0}")]
    Config(#[from] anyhow::Error),
}

impl SidecarError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Auth(_) => 401,
            Self::RateLimit => 429,
            Self::Timeout => 408,
            Self::InvalidRequest(_) => 400,
            Self::ZkVerification(_) => 422,
            _ => 500,
        }
    }
}