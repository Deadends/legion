// Shared cryptographic helper functions (used by both server and WASM)
use anyhow::Result;
use ff::{FromUniformBytes, PrimeField};
use halo2_gadgets::poseidon::primitives as poseidon;
use pasta_curves::Fp;

/// Compute stored credential hash from username hash
pub fn compute_stored_hash(username_hash: &Fp) -> Result<Fp> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"USER_SPECIFIC_SALT_PREFIX");
    hasher.update(&username_hash.to_repr());
    let user_specific_salt_hash = hasher.finalize();

    let mut final_hasher = blake3::Hasher::new();
    final_hasher.update(b"STORED_CREDENTIAL_V1");
    final_hasher.update(&username_hash.to_repr());
    final_hasher.update(user_specific_salt_hash.as_bytes());

    let hash = final_hasher.finalize();
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(hash.as_bytes());
    Ok(Fp::from_uniform_bytes(&buf))
}

/// Compute user leaf from username and stored hashes
pub fn compute_user_leaf(username_hash: Fp, stored_hash: Fp) -> Result<Fp> {
    Ok(
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init()
            .hash([username_hash, stored_hash]),
    )
}

/// Build Merkle path from leaves array (client-side only)
pub fn build_merkle_path(leaves: &[Fp], index: usize) -> Result<[Fp; 20]> {
    let mut path = [Fp::zero(); 20];
    let mut current_level = leaves.to_vec();
    let mut current_index = index;

    for level in 0..20 {
        let sibling_index = current_index ^ 1;

        path[level] = if sibling_index < current_level.len() {
            current_level[sibling_index]
        } else {
            Fp::zero()
        };

        // Build next level
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                Fp::zero()
            };

            let parent =
                poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, 3, 2>::init(
                )
                .hash([left, right]);
            next_level.push(parent);
        }

        current_level = next_level;
        current_index >>= 1;
    }

    Ok(path)
}
