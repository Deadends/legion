pub mod error;
pub mod tls;
pub mod tickets;
pub mod hardened_server;
pub mod replay;
pub mod session;
pub mod security;
pub mod stage_a;

// Re-export existing security system
pub use security::SecurityManager;
pub use stage_a::*;
pub use error::{Result, SidecarError};