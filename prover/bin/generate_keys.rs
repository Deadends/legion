// Utility to generate static proving keys for WASM client
use anyhow::Result;
use legion_prover::{AuthCircuit, ProofGenerator};
use pasta_curves::Fp;
use std::fs;

fn main() -> Result<()> {
    println!("🔧 Generating static proving keys for WASM client...");
    
    // Create static directory
    fs::create_dir_all("./static")?;
    
    // Create a dummy circuit for key generation
    let dummy_circuit = AuthCircuit::new(
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
        [Fp::zero(); 20],
        0,
        Fp::zero(),
        Fp::zero(),
        Fp::zero(),
    )?;
    
    // Generate proving keys
    println!("⏳ Generating params (k=16)...");
    let mut proof_gen = ProofGenerator::new(16)?;
    
    println!("⏳ Generating proving/verifying keys...");
    proof_gen.setup(&dummy_circuit)?;
    
    // Save params
    println!("💾 Saving params to ./static/k16.params...");
    let params_bytes = {
        let mut buf = Vec::new();
        proof_gen.params.write(&mut buf)?;
        buf
    };
    fs::write("./static/k16.params", &params_bytes)?;
    
    // Note: ProvingKey serialization not available in halo2_proofs 0.3.1
    println!("⚠️  Proving key serialization not supported in this version");
    
    println!("✅ Params generated successfully!");
    println!("   - ./static/k16.params ({} bytes)", fs::metadata("./static/k16.params")?.len());
    println!("\n🚀 Server can now serve params to WASM clients");
    
    Ok(())
}
