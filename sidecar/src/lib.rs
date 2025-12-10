pub mod error;
pub mod tls;
pub mod tickets;
pub mod hardened_server;
pub mod replay;
pub mod session;
pub mod security;
pub mod stage_a;
pub mod stage_b;
pub mod config;
pub mod sidecar;

// Re-export existing security system
pub use security::SecurityManager;
pub use stage_a::*;
pub use stage_b::*;
pub use error::{Result, SidecarError};
pub use sidecar::SidecarServer;