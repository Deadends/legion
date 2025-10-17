use anyhow::Result;
use prover::{
    standardized_auth_system::StandardizedAuthSystem,
    minimal_auth_circuit::MinimalAuthCircuit,
};
use pasta_curves::Fp;
use ff::Field;

fn main() -> Result<()> {
    println!("🔧 REFACTORED: Legion Authentication System");
    println!("✅ Standardized cryptography (pure Ed25519)");
    println!("✅ Minimal ZK circuit (auth only)");
    println!("✅ Separated concerns");
    
    // Initialize standardized auth system
    StandardizedAuthSystem::initialize()?;
    println!("✅ Standardized auth system initialized");
    
    // Issue a certificate using standard Ed25519
    let cert = StandardizedAuthSystem::issue_certificate("user123", 86400)?;
    println!("✅ Certificate issued: {}", cert.subject);
    
    // Verify certificate signature
    let is_valid = cert.verify_signature()?;
    println!("✅ Certificate signature valid: {}", is_valid);
    
    // Create minimal auth circuit
    let username = b"alice";
    let password = b"secure_password_123";
    
    // Mock Merkle tree data (in production, this comes from the auth system)
    let merkle_path = [Fp::random(&mut rand::thread_rng()); 20];
    let leaf_index = 42u64;
    let merkle_root = Fp::random(&mut rand::thread_rng());
    
    let circuit = MinimalAuthCircuit::new(
        username,
        password,
        merkle_path,
        leaf_index,
        merkle_root,
    )?;
    
    println!("✅ Minimal auth circuit created");
    println!("   Public inputs: {:?}", circuit.public_inputs().len());
    
    // Publish merkle root (signed by CA)
    let root_bytes = merkle_root.to_repr();
    let mut root_array = [0u8; 32];
    root_array.copy_from_slice(&root_bytes[..32]);
    
    let signature = StandardizedAuthSystem::publish_merkle_root(root_array)?;
    println!("✅ Merkle root published and signed");
    
    // Verify merkle root signature
    let sig_valid = StandardizedAuthSystem::verify_merkle_root_signature(root_array, signature)?;
    println!("✅ Merkle root signature valid: {}", sig_valid);
    
    println!("\n🎯 REFACTORING COMPLETE:");
    println!("   • Auth system: Standard Ed25519 (no hybrids)");
    println!("   • ZK circuit: Minimal (auth only)");
    println!("   • PKI: Separate service layer");
    println!("   • Transport: Ready for standard TLS");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_standardized_system() -> Result<()> {
        StandardizedAuthSystem::initialize()?;
        
        let cert = StandardizedAuthSystem::issue_certificate("test_user", 3600)?;
        assert!(cert.is_valid());
        assert!(cert.verify_signature()?);
        
        StandardizedAuthSystem::revoke_certificate("test_user")?;
        let revoked_cert = StandardizedAuthSystem::get_certificate("test_user").unwrap();
        assert!(!revoked_cert.is_valid());
        
        Ok(())
    }
    
    #[test]
    fn test_minimal_circuit() -> Result<()> {
        let circuit = MinimalAuthCircuit::new(
            b"test_user",
            b"test_pass",
            [Fp::zero(); 20],
            0,
            Fp::zero(),
        )?;
        
        let public_inputs = circuit.public_inputs();
        assert_eq!(public_inputs.len(), 2); // merkle_root, nullifier
        
        Ok(())
    }
}