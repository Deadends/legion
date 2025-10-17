// REAL PRODUCTION: Parameter caching for performance
use anyhow::Result;
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use std::sync::OnceLock;

static CACHED_PARAMS: OnceLock<Params<vesta::Affine>> = OnceLock::new();
#[allow(dead_code)]
static CACHED_VK: OnceLock<VerifyingKey<vesta::Affine>> = OnceLock::new();

pub fn get_cached_params(k: u32) -> Result<&'static Params<vesta::Affine>> {
    Ok(CACHED_PARAMS.get_or_init(|| Params::new(k)))
}

// Temporarily disabled - needs WorldClassAuthCircuit
/*
pub fn get_cached_vk(k: u32) -> Result<&'static VerifyingKey<vesta::Affine>> {
    use crate::global_registry::WorldClassAuthCircuit;
    use halo2_proofs::plonk::keygen_vk;

    Ok(CACHED_VK.get_or_init(|| {
        let params = get_cached_params(k).expect("Failed to get params");
        let empty_circuit = WorldClassAuthCircuit::default();
        keygen_vk(params, &empty_circuit).expect("VK generation failed")
    }))
}
*/
