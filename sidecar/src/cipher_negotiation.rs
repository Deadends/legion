use serde::{Serialize, Deserialize};
use std::time::SystemTime;
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    Classical = 0x0001,           // X25519 + Ed25519 + ChaCha20Poly1305
    PostQuantum = 0x0002,         // ML-KEM-1024 + ML-DSA-87 + ChaCha20Poly1305
    Hybrid = 0x0003,              // Both classical and PQ
    QuantumResistant = 0x0004,    // CRYSTALS-Kyber + CRYSTALS-Dilithium + AES-256-GCM
    HighSecurity = 0x0005,        // ML-KEM-1024 + ML-DSA-87 + XChaCha20Poly1305
    LegacyCompat = 0x0006,        // RSA-4096 + ECDSA-P521 + AES-256-GCM (for legacy systems)
    ExperimentalPQ = 0x0007,      // BIKE + Rainbow + ChaCha20Poly1305 (research)
}

impl CipherSuite {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::Classical),
            0x0002 => Some(Self::PostQuantum),
            0x0003 => Some(Self::Hybrid),
            0x0004 => Some(Self::QuantumResistant),
            0x0005 => Some(Self::HighSecurity),
            0x0006 => Some(Self::LegacyCompat),
            0x0007 => Some(Self::ExperimentalPQ),
            _ => None,
        }
    }
    
    pub fn to_u16(self) -> u16 {
        self as u16
    }
    
    pub fn is_pq_enabled(self) -> bool {
        matches!(self, Self::PostQuantum | Self::Hybrid | Self::QuantumResistant | Self::HighSecurity | Self::ExperimentalPQ)
    }
    
    pub fn is_classical_enabled(self) -> bool {
        matches!(self, Self::Classical | Self::Hybrid | Self::LegacyCompat)
    }
    
    pub fn quantum_security_level(self) -> u8 {
        match self {
            Self::Classical | Self::LegacyCompat => 0,
            Self::Hybrid => 128,
            Self::PostQuantum => 192,
            Self::QuantumResistant => 256,
            Self::HighSecurity => 384,
            Self::ExperimentalPQ => 512,
        }
    }
    
    pub fn performance_score(self) -> u8 {
        match self {
            Self::Classical => 100,
            Self::LegacyCompat => 60,
            Self::Hybrid => 80,
            Self::PostQuantum => 70,
            Self::QuantumResistant => 65,
            Self::HighSecurity => 50,
            Self::ExperimentalPQ => 30,
        }
    }
    
    pub fn is_deprecated(self) -> bool {
        matches!(self, Self::LegacyCompat)
    }
    
    pub fn requires_hardware_support(self) -> bool {
        matches!(self, Self::HighSecurity | Self::ExperimentalPQ)
    }
}

pub struct CipherNegotiator {
    supported_suites: Vec<CipherSuite>,
    preferred_suite: CipherSuite,
    quantum_threat_level: u8,
    compliance_requirements: ComplianceLevel,
    performance_priority: bool,
    negotiation_history: Vec<NegotiationEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceLevel {
    None,
    FIPS140_2,
    CommonCriteria,
    NSA_Suite_B,
    Quantum_Safe,
}

#[derive(Debug, Clone)]
struct NegotiationEvent {
    timestamp: SystemTime,
    client_suites: Vec<u16>,
    selected_suite: Option<CipherSuite>,
    threat_assessment: ThreatAssessment,
}

#[derive(Debug, Clone)]
struct ThreatAssessment {
    quantum_threat_level: u8,
    classical_attack_risk: u8,
    side_channel_risk: u8,
    implementation_maturity: u8,
}

impl CipherNegotiator {
    pub fn new() -> Self {
        let supported_suites = if cfg!(feature = "pq") {
            vec![CipherSuite::Hybrid, CipherSuite::PostQuantum, CipherSuite::Classical]
        } else {
            vec![CipherSuite::Classical]
        };
        
        let preferred_suite = if cfg!(feature = "pq") {
            CipherSuite::Hybrid
        } else {
            CipherSuite::Classical
        };
        
        Self {
            supported_suites,
            preferred_suite,
            quantum_threat_level: 128,
            compliance_requirements: ComplianceLevel::None,
            performance_priority: false,
            negotiation_history: Vec::new(),
        }
    }
    
    pub fn new_with_config(
        quantum_threat_level: u8,
        compliance: ComplianceLevel,
        performance_priority: bool
    ) -> Self {
        let mut negotiator = Self::new();
        negotiator.quantum_threat_level = quantum_threat_level;
        negotiator.compliance_requirements = compliance;
        negotiator.performance_priority = performance_priority;
        
        // Adjust supported suites based on configuration
        negotiator.update_supported_suites();
        
        negotiator
    }
    
    fn update_supported_suites(&mut self) {
        let mut suites = Vec::new();
        
        // Add suites based on compliance requirements
        match self.compliance_requirements {
            ComplianceLevel::Quantum_Safe => {
                suites.extend_from_slice(&[
                    CipherSuite::QuantumResistant,
                    CipherSuite::PostQuantum,
                    CipherSuite::Hybrid,
                ]);
            }
            ComplianceLevel::FIPS140_2 => {
                suites.extend_from_slice(&[
                    CipherSuite::Classical,
                    CipherSuite::Hybrid,
                ]);
            }
            ComplianceLevel::NSA_Suite_B => {
                suites.extend_from_slice(&[
                    CipherSuite::HighSecurity,
                    CipherSuite::QuantumResistant,
                ]);
            }
            _ => {
                suites.extend_from_slice(&[
                    CipherSuite::Classical,
                    CipherSuite::Hybrid,
                    CipherSuite::PostQuantum,
                ]);
            }
        }
        
        // Filter based on quantum threat level
        if self.quantum_threat_level >= 192 {
            suites.retain(|&suite| suite.quantum_security_level() >= 192);
        }
        
        // Prioritize performance if requested
        if self.performance_priority {
            suites.sort_by_key(|&suite| std::cmp::Reverse(suite.performance_score()));
        } else {
            suites.sort_by_key(|&suite| std::cmp::Reverse(suite.quantum_security_level()));
        }
        
        self.supported_suites = suites;
        
        // Update preferred suite
        if let Some(&first_suite) = self.supported_suites.first() {
            self.preferred_suite = first_suite;
        }
    }
    
    pub fn negotiate(&mut self, client_suites: &[u16]) -> Result<Option<CipherSuite>> {
        let threat_assessment = self.assess_threat_level(client_suites);
        
        // Try preferred suite first
        if client_suites.contains(&self.preferred_suite.to_u16()) {
            let selected = Some(self.preferred_suite);
            self.record_negotiation(client_suites, selected, threat_assessment)?;
            
            info!("Negotiated preferred cipher suite: {:?}", self.preferred_suite);
            return Ok(selected);
        }
        
        // Try other supported suites in order of preference
        for &suite in &self.supported_suites {
            if client_suites.contains(&suite.to_u16()) {
                // Additional security checks
                if self.validate_suite_security(suite, &threat_assessment)? {
                    let selected = Some(suite);
                    self.record_negotiation(client_suites, selected, threat_assessment)?;
                    
                    info!("Negotiated cipher suite: {:?}", suite);
                    return Ok(selected);
                }
            }
        }
        
        // No compatible suite found
        warn!("No compatible cipher suite found for client suites: {:?}", client_suites);
        self.record_negotiation(client_suites, None, threat_assessment)?;
        Ok(None)
    }
    
    fn assess_threat_level(&self, client_suites: &[u16]) -> ThreatAssessment {
        let mut quantum_threat = self.quantum_threat_level;
        let mut classical_risk = 50; // Base risk
        let mut side_channel_risk = 30;
        let mut implementation_maturity = 80;
        
        // FIXED: Comprehensive client suite analysis
        let client_cipher_suites: Vec<CipherSuite> = client_suites.iter()
            .filter_map(|&id| CipherSuite::from_u16(id))
            .collect();
        
        // FIXED: Analyze quantum readiness
        let has_pq_suites = client_cipher_suites.iter().any(|suite| suite.is_pq_enabled());
        let has_classical_only = client_cipher_suites.iter().any(|suite| !suite.is_pq_enabled());
        
        if !has_pq_suites {
            quantum_threat = quantum_threat.saturating_add(30);
            warn!("Client does not support post-quantum cryptography");
        }
        
        // FIXED: Check for deprecated/weak suites
        let has_deprecated = client_cipher_suites.iter().any(|suite| suite.is_deprecated());
        let has_weak_suites = client_cipher_suites.iter().any(|suite| suite.quantum_security_level() < 128);
        
        if has_deprecated {
            classical_risk = classical_risk.saturating_add(40);
            implementation_maturity = implementation_maturity.saturating_sub(30);
            warn!("Client supports deprecated cipher suites");
        }
        
        if has_weak_suites {
            quantum_threat = quantum_threat.saturating_add(25);
            classical_risk = classical_risk.saturating_add(20);
        }
        
        // FIXED: Analyze suite ordering (preference indication)
        if let Some(first_suite) = client_cipher_suites.first() {
            if first_suite.is_deprecated() {
                classical_risk = classical_risk.saturating_add(20);
                warn!("Client prefers deprecated cipher suite: {:?}", first_suite);
            }
            
            if !first_suite.is_pq_enabled() && has_pq_suites {
                quantum_threat = quantum_threat.saturating_add(15);
                warn!("Client prefers classical crypto over post-quantum");
            }
        }
        
        // FIXED: Check for downgrade attack indicators
        let suite_count = client_cipher_suites.len();
        if suite_count > 10 {
            // Too many suites might indicate downgrade attack
            classical_risk = classical_risk.saturating_add(15);
            side_channel_risk = side_channel_risk.saturating_add(10);
        } else if suite_count < 2 {
            // Too few suites might indicate limited implementation
            implementation_maturity = implementation_maturity.saturating_sub(10);
        }
        
        // FIXED: Check for mixed security levels (potential downgrade)
        let min_security = client_cipher_suites.iter().map(|s| s.quantum_security_level()).min().unwrap_or(0);
        let max_security = client_cipher_suites.iter().map(|s| s.quantum_security_level()).max().unwrap_or(0);
        
        if max_security > 0 && min_security == 0 {
            // Client supports both secure and insecure suites
            quantum_threat = quantum_threat.saturating_add(20);
            classical_risk = classical_risk.saturating_add(15);
            warn!("Client supports mixed security levels - potential downgrade risk");
        }
        
        ThreatAssessment {
            quantum_threat_level: quantum_threat.min(255),
            classical_attack_risk: classical_risk.min(255),
            side_channel_risk: side_channel_risk.min(255),
            implementation_maturity: implementation_maturity.max(0),
        }
    }
    
    fn validate_suite_security(&self, suite: CipherSuite, threat: &ThreatAssessment) -> Result<bool> {
        // Check if suite meets minimum security requirements
        if suite.quantum_security_level() < self.quantum_threat_level {
            debug!("Suite {:?} rejected: insufficient quantum security", suite);
            return Ok(false);
        }
        
        // Reject deprecated suites in high-threat environments
        if suite.is_deprecated() && threat.quantum_threat_level > 150 {
            debug!("Suite {:?} rejected: deprecated in high-threat environment", suite);
            return Ok(false);
        }
        
        // Check hardware requirements
        if suite.requires_hardware_support() && !self.check_hardware_support(suite)? {
            debug!("Suite {:?} rejected: hardware support not available", suite);
            return Ok(false);
        }
        
        Ok(true)
    }
    
    fn check_hardware_support(&self, _suite: CipherSuite) -> Result<bool> {
        // In a real implementation, this would check for hardware acceleration
        // For now, assume hardware support is available
        Ok(true)
    }
    
    fn record_negotiation(
        &mut self,
        client_suites: &[u16],
        selected_suite: Option<CipherSuite>,
        threat_assessment: ThreatAssessment
    ) -> Result<()> {
        let event = NegotiationEvent {
            timestamp: SystemTime::now(),
            client_suites: client_suites.to_vec(),
            selected_suite,
            threat_assessment,
        };
        
        self.negotiation_history.push(event);
        
        // Keep only recent history
        if self.negotiation_history.len() > 1000 {
            self.negotiation_history.remove(0);
        }
        
        Ok(())
    }
    
    pub fn get_supported_suites(&self) -> &[CipherSuite] {
        &self.supported_suites
    }
    
    pub fn get_negotiation_stats(&self) -> NegotiationStats {
        let total_negotiations = self.negotiation_history.len();
        let successful_negotiations = self.negotiation_history.iter()
            .filter(|event| event.selected_suite.is_some())
            .count();
        
        let suite_usage: std::collections::HashMap<CipherSuite, usize> = 
            self.negotiation_history.iter()
                .filter_map(|event| event.selected_suite)
                .fold(std::collections::HashMap::new(), |mut acc, suite| {
                    *acc.entry(suite).or_insert(0) += 1;
                    acc
                });
        
        NegotiationStats {
            total_negotiations,
            successful_negotiations,
            success_rate: if total_negotiations > 0 {
                (successful_negotiations as f64 / total_negotiations as f64) * 100.0
            } else {
                0.0
            },
            suite_usage,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NegotiationStats {
    pub total_negotiations: usize,
    pub successful_negotiations: usize,
    pub success_rate: f64,
    pub suite_usage: std::collections::HashMap<CipherSuite, usize>,
}

#[cfg(test)]\nmod tests {
    use super::*;
    
    #[test]
    fn test_cipher_suite_conversion() {
        assert_eq!(CipherSuite::from_u16(0x0001), Some(CipherSuite::Classical));
        assert_eq!(CipherSuite::from_u16(0x0002), Some(CipherSuite::PostQuantum));
        assert_eq!(CipherSuite::from_u16(0x0003), Some(CipherSuite::Hybrid));
        assert_eq!(CipherSuite::from_u16(0x9999), None);
        
        assert_eq!(CipherSuite::Classical.to_u16(), 0x0001);
        assert_eq!(CipherSuite::PostQuantum.to_u16(), 0x0002);
        assert_eq!(CipherSuite::Hybrid.to_u16(), 0x0003);
    }
    
    #[test]
    fn test_negotiation() -> Result<()> {
        let mut negotiator = CipherNegotiator::new();
        
        // Client supports hybrid
        let client_suites = vec![0x0003, 0x0001];
        let result = negotiator.negotiate(&client_suites)?;
        
        if cfg!(feature = "pq") {
            assert_eq!(result, Some(CipherSuite::Hybrid));
        } else {
            assert_eq!(result, Some(CipherSuite::Classical));
        }
        
        // Client only supports classical
        let client_suites = vec![0x0001];
        let result = negotiator.negotiate(&client_suites)?;
        assert_eq!(result, Some(CipherSuite::Classical));
        
        // No common suites
        let client_suites = vec![0x9999];
        let result = negotiator.negotiate(&client_suites)?;
        assert_eq!(result, None);
        
        Ok(())
    }
    
    #[test]
    fn test_quantum_threat_assessment() -> Result<()> {
        let mut negotiator = CipherNegotiator::new_with_config(
            200, // High quantum threat
            ComplianceLevel::Quantum_Safe,
            false
        );
        
        // Should prefer quantum-resistant suites
        let client_suites = vec![0x0001, 0x0004]; // Classical + QuantumResistant
        let result = negotiator.negotiate(&client_suites)?;
        assert_eq!(result, Some(CipherSuite::QuantumResistant));
        
        Ok(())
    }
}