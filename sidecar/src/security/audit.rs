use serde::{Serialize, Deserialize};
use std::time::SystemTime;
use anyhow::Result;
use tracing::{info, error};
use tokio::sync::mpsc;
use tokio::io::AsyncWriteExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: EventType,
    pub timestamp: SystemTime,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub source_ip: Option<String>,
    pub details: serde_json::Value,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    KeyAccess,
    KeyRotation,
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    TokenIssued,
    TokenVerified,
    TokenExpired,
    ProofVerification,
    ReplayAttackDetected,
    RateLimitExceeded,
    SystemStartup,
    SystemShutdown,
    ConfigurationChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct AuditSystem {
    event_sender: mpsc::UnboundedSender<SecurityEvent>,
    _audit_task: tokio::task::JoinHandle<()>,
}

impl AuditSystem {
    pub async fn new() -> Result<Self> {
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel::<SecurityEvent>();
        
        // Spawn audit processing task
        let audit_task = tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Err(e) = Self::process_event(event).await {
                    error!("Failed to process audit event: {}", e);
                }
            }
        });
        
        info!("Audit system initialized");
        
        Ok(Self {
            event_sender,
            _audit_task: audit_task,
        })
    }
    
    pub async fn log_event(&self, event: SecurityEvent) -> Result<()> {
        // Log to structured logging immediately
        match event.risk_level {
            RiskLevel::Critical => {
                tracing::error!(
                    event_type = ?event.event_type,
                    timestamp = ?event.timestamp,
                    user_id = ?event.user_id,
                    client_id = ?event.client_id,
                    source_ip = ?event.source_ip,
                    details = ?event.details,
                    "CRITICAL SECURITY EVENT"
                );
            }
            RiskLevel::High => {
                tracing::warn!(
                    event_type = ?event.event_type,
                    timestamp = ?event.timestamp,
                    user_id = ?event.user_id,
                    client_id = ?event.client_id,
                    source_ip = ?event.source_ip,
                    details = ?event.details,
                    "High risk security event"
                );
            }
            _ => {
                tracing::info!(
                    event_type = ?event.event_type,
                    timestamp = ?event.timestamp,
                    user_id = ?event.user_id,
                    client_id = ?event.client_id,
                    source_ip = ?event.source_ip,
                    details = ?event.details,
                    "Security event"
                );
            }
        }
        
        // Send to async processing
        self.event_sender.send(event)
            .map_err(|e| anyhow::anyhow!("Failed to send audit event: {}", e))?;
        
        Ok(())
    }
    
    async fn process_event(event: SecurityEvent) -> Result<()> {
        // Write to audit log file
        let log_entry = serde_json::to_string(&event)?;
        
        // In production, this would write to:
        // - Secure audit log files
        // - SIEM system
        // - Compliance database
        // - Real-time alerting system
        
        // For now, write to audit.log
        let log_file = std::env::var("AUDIT_LOG_PATH")
            .unwrap_or_else(|_| "/var/log/legion/audit.log".to_string());
        
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .await?
            .write_all(format!("{}\n", log_entry).as_bytes())
            .await?;
        
        // Alert on critical events
        if matches!(event.risk_level, RiskLevel::Critical) {
            Self::send_alert(event).await?;
        }
        
        Ok(())
    }
    
    async fn send_alert(event: SecurityEvent) -> Result<()> {
        // In production, this would:
        // - Send to PagerDuty/OpsGenie
        // - Send email alerts
        // - Send Slack notifications
        // - Trigger incident response
        
        error!("CRITICAL SECURITY ALERT: {:?}", event);
        Ok(())
    }
}

// Helper functions for common audit events
impl SecurityEvent {
    pub fn key_access(key_id: &str, client_id: Option<String>) -> Self {
        Self {
            event_type: EventType::KeyAccess,
            timestamp: SystemTime::now(),
            user_id: None,
            client_id,
            source_ip: None,
            details: serde_json::json!({
                "key_id": key_id,
                "operation": "access"
            }),
            risk_level: RiskLevel::Low,
        }
    }
    
    pub fn authentication_failure(client_id: String, source_ip: Option<String>, reason: &str) -> Self {
        Self {
            event_type: EventType::AuthenticationFailure,
            timestamp: SystemTime::now(),
            user_id: None,
            client_id: Some(client_id),
            source_ip,
            details: serde_json::json!({
                "failure_reason": reason
            }),
            risk_level: RiskLevel::Medium,
        }
    }
    
    pub fn replay_attack_detected(client_id: String, nonce: &str) -> Self {
        Self {
            event_type: EventType::ReplayAttackDetected,
            timestamp: SystemTime::now(),
            user_id: None,
            client_id: Some(client_id),
            source_ip: None,
            details: serde_json::json!({
                "nonce": nonce,
                "attack_type": "replay"
            }),
            risk_level: RiskLevel::Critical,
        }
    }
    
    pub fn token_issued(client_id: String, token_type: &str, expiry: SystemTime) -> Self {
        Self {
            event_type: EventType::TokenIssued,
            timestamp: SystemTime::now(),
            user_id: None,
            client_id: Some(client_id),
            source_ip: None,
            details: serde_json::json!({
                "token_type": token_type,
                "expiry": expiry.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
            }),
            risk_level: RiskLevel::Low,
        }
    }
}