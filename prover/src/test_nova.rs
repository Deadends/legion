#[cfg(feature = "nova")]
use anyhow::Result;
#[cfg(feature = "nova")]
use pasta_curves::Fp;
#[cfg(feature = "nova")]
use crate::nova_accumulator::{run_legion_nova_auth, hash_credential};

#[cfg(all(test, feature = "nova"))]
mod tests {
    use super::*;

    #[test]
    fn test_legion_nova_authentication() -> Result<()> {
        println!("🧪 Testing Legion Nova Authentication");
        
        let proof = run_legion_nova_auth(
            b"alice",
            b"password123", 
            Fp::from(42u64),
            Fp::from(0u64),
            3,
        )?;
        
        assert!(!proof.is_empty());
        println!("✅ Nova authentication proof generated: {} bytes", proof.len());
        
        Ok(())
    }
}

#[cfg(feature = "nova")]
pub fn demo_working_nova() -> Result<()> {
    println!("🚀 Legion Nova Authentication Demo");
    
    let proof = run_legion_nova_auth(
        b"demo_user",
        b"demo_password",
        Fp::from(12345u64),
        Fp::from(0u64),
        5,
    )?;
    
    println!("✅ Nova authentication completed");
    println!("   Proof size: {} bytes", proof.len());
    
    Ok(())
}

#[cfg(not(feature = "nova"))]
pub fn demo_working_nova() -> anyhow::Result<()> {
    println!("⚠️  Nova feature not enabled");
    Ok(())
}
