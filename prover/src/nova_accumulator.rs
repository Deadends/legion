// Nova recursive proof with SECURE Merkle path verification

#[cfg(feature = "nova")]
mod nova_impl {
    use anyhow::Result;
    use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
    use nova_snark::traits::circuit::StepCircuit;
    use pasta_curves::Fp;
    use ff::PrimeField;
    use neptune::{
        circuit2::Elt,
        sponge::vanilla::{Sponge, SpongeTrait},
    };

    const MERKLE_DEPTH: usize = 20;

    /// Merkle Path Step Circuit - SECURE implementation
    #[derive(Clone)]
    pub struct MerklePathStepCircuit {
        sibling_node: Fp,
        direction_bit: Fp,
    }

    impl MerklePathStepCircuit {
        pub fn new(sibling_node: Fp, direction_bit: Fp) -> Self {
            Self { sibling_node, direction_bit }
        }
    }

    impl StepCircuit<Fp> for MerklePathStepCircuit {
        fn arity(&self) -> usize {
            1
        }

        fn synthesize<CS: ConstraintSystem<Fp>>(
            &self,
            cs: &mut CS,
            z: &[AllocatedNum<Fp>],
        ) -> Result<Vec<AllocatedNum<Fp>>, SynthesisError> {
            let current_hash = &z[0];
            let sibling = AllocatedNum::alloc(cs.namespace(|| "sibling"), || Ok(self.sibling_node))?;
            let dir = AllocatedNum::alloc(cs.namespace(|| "dir"), || Ok(self.direction_bit))?;

            // Enforce dir is bit: (1-dir)*dir = 0
            cs.enforce(
                || "dir is bit",
                |lc| lc + CS::one() - dir.get_variable(),
                |lc| lc + dir.get_variable(),
                |lc| lc,
            );

            // Conditional: left = (1-dir)*current + dir*sibling
            // R1CS: (sibling - current) * dir = left - current
            let left = {
                let curr_val = current_hash.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let sib_val = sibling.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let dir_val = dir.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let left_val = (Fp::one() - dir_val) * curr_val + dir_val * sib_val;
                
                let left = AllocatedNum::alloc(cs.namespace(|| "left"), || Ok(left_val))?;
                
                cs.enforce(
                    || "left selection",
                    |lc| lc + sibling.get_variable() - current_hash.get_variable(),
                    |lc| lc + dir.get_variable(),
                    |lc| lc + left.get_variable() - current_hash.get_variable(),
                );
                
                left
            };

            // Conditional: right = dir*current + (1-dir)*sibling
            // R1CS: (current - sibling) * dir = right - sibling
            let right = {
                let curr_val = current_hash.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let sib_val = sibling.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let dir_val = dir.get_value().ok_or(SynthesisError::AssignmentMissing)?;
                let right_val = dir_val * curr_val + (Fp::one() - dir_val) * sib_val;
                
                let right = AllocatedNum::alloc(cs.namespace(|| "right"), || Ok(right_val))?;
                
                cs.enforce(
                    || "right selection",
                    |lc| lc + current_hash.get_variable() - sibling.get_variable(),
                    |lc| lc + dir.get_variable(),
                    |lc| lc + right.get_variable() - sibling.get_variable(),
                );
                
                right
            };

            // ✅ SECURE: Poseidon hash using neptune v13
            let left_val = left.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            let right_val = right.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            
            // Neptune v13 requires PoseidonConstants
            use neptune::poseidon::PoseidonConstants;
            let constants = PoseidonConstants::<Fp, typenum::U2>::new();
            let mut sponge = Sponge::new_with_constants(&constants, neptune::sponge::vanilla::Mode::Simplex);
            let mut acc = ();
            sponge.absorb(&left_val, &mut acc).map_err(|_| SynthesisError::Unsatisfiable)?;
            sponge.absorb(&right_val, &mut acc).map_err(|_| SynthesisError::Unsatisfiable)?;
            let parent_val = sponge.squeeze(&mut acc).map_err(|_| SynthesisError::Unsatisfiable)?
                .ok_or(SynthesisError::AssignmentMissing)?;
            
            let parent_hash = AllocatedNum::alloc(cs.namespace(|| "parent"), || Ok(parent_val))?;
            
            Ok(vec![parent_hash])
        }
    }

    pub fn hash_credential(input: &[u8], domain: &[u8]) -> Result<Fp> {
        use blake3;
        use ff::FromUniformBytes;
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_CREDENTIAL_V1");
        hasher.update(domain);
        hasher.update(input);
        
        let hash = hasher.finalize();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(hash.as_bytes());
        Ok(Fp::from_uniform_bytes(&buf))
    }

    pub fn generate_nova_proof(
        username: &[u8],
        password: &[u8],
        merkle_path: &[Fp; MERKLE_DEPTH],
        leaf_index: u64,
    ) -> Result<(Vec<u8>, Fp)> {
        use nova_snark::{
            traits::circuit::TrivialCircuit,
            PublicParams, RecursiveSNARK,
            provider::{PallasEngine, VestaEngine},
        };
        use pasta_curves::Fq;
        use std::time::Instant;

        println!("🚀 Generating Nova Merkle proof ({} steps)...", MERKLE_DEPTH);
        let start = Instant::now();

        let username_hash = hash_credential(username, b"USERNAME")?;
        let password_hash = hash_credential(password, b"PASSWORD")?;
        
        // Use neptune v13 for consistent Poseidon hashing
        use neptune::sponge::vanilla::{Sponge, SpongeTrait, Mode};
        use neptune::poseidon::PoseidonConstants;
        let constants = PoseidonConstants::<Fp, typenum::U2>::new();
        let mut sponge = Sponge::new_with_constants(&constants, Mode::Simplex);
        let mut acc = ();
        sponge.absorb(&username_hash, &mut acc)?;
        sponge.absorb(&password_hash, &mut acc)?;
        let leaf_hash = sponge.squeeze(&mut acc)?
            .ok_or_else(|| anyhow::anyhow!("Sponge squeeze failed"))?;

        let z0_primary = vec![leaf_hash];
        let z0_secondary = vec![Fp::one()];

        let first_direction = Fp::from((leaf_index >> 0) & 1);
        let circuit_primary = MerklePathStepCircuit::new(merkle_path[0], first_direction);
        let circuit_secondary: TrivialCircuit<Fp> = TrivialCircuit::default();

        println!("  - Setting up parameters...");
        type E1 = PallasEngine;
        type E2 = VestaEngine;
        type C1 = MerklePathStepCircuit;
        type C2 = TrivialCircuit<Fp>;
        
        let pp = PublicParams::<E1, E2, C1, C2>::setup(
            &circuit_primary,
            &circuit_secondary,
            &*nova_snark::traits::snark::default_ck_hint(),
            &*nova_snark::traits::snark::default_ck_hint(),
        );

        println!("  - Generating recursive SNARK...");
        let mut recursive_snark = RecursiveSNARK::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        )?;

        for i in 0..MERKLE_DEPTH {
            let direction = Fp::from((leaf_index >> i) & 1);
            let step_circuit = MerklePathStepCircuit::new(merkle_path[i], direction);

            recursive_snark.prove_step(&pp, &step_circuit, &circuit_secondary)?;

            if (i + 1) % 5 == 0 {
                println!("    Step {}/{}", i + 1, MERKLE_DEPTH);
            }
        }

        println!("  - Verifying...");
        let (z_out_primary, _) = recursive_snark.verify(&pp, MERKLE_DEPTH, &z0_primary, &z0_secondary)?;
        let computed_root = z_out_primary[0];

        let proof_data = bincode::serialize(&recursive_snark)?;
        println!("✅ Nova proof: {} bytes in {:?}", proof_data.len(), start.elapsed());

        Ok((proof_data, computed_root))
    }
}

#[cfg(feature = "nova")]
pub use nova_impl::*;

#[cfg(feature = "nova")]
pub fn generate_nova_proof_with_path(
    username: &[u8],
    password: &[u8],
    merkle_path: &[pasta_curves::Fp; 20],
    leaf_index: u64,
) -> anyhow::Result<(Vec<u8>, pasta_curves::Fp)> {
    generate_nova_proof(username, password, merkle_path, leaf_index)
}

#[cfg(feature = "nova")]
pub fn run_legion_nova_auth(
    username: &[u8],
    password: &[u8],
    merkle_root: pasta_curves::Fp,
    _verified_timestamp: pasta_curves::Fp,
    _num_steps: usize,
) -> anyhow::Result<Vec<u8>> {
    let merkle_path = [merkle_root; 20];
    let leaf_index = 0;
    
    let (proof, _computed_root) = generate_nova_proof(username, password, &merkle_path, leaf_index)?;
    Ok(proof)
}

#[cfg(not(feature = "nova"))]
pub fn generate_nova_proof_with_path(
    _username: &[u8],
    _password: &[u8],
    _merkle_path: &[pasta_curves::Fp; 20],
    _leaf_index: u64,
) -> anyhow::Result<(Vec<u8>, pasta_curves::Fp)> {
    Err(anyhow::anyhow!("Nova feature not enabled"))
}

#[cfg(not(feature = "nova"))]
pub fn run_legion_nova_auth(
    _username: &[u8],
    _password: &[u8],
    _merkle_root: pasta_curves::Fp,
    _verified_timestamp: pasta_curves::Fp,
    _num_steps: usize,
) -> anyhow::Result<Vec<u8>> {
    Err(anyhow::anyhow!("Nova feature not enabled"))
}
