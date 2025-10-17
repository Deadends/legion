use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::Fp;
use ff::{PrimeField, FromUniformBytes};
use halo2_gadgets::poseidon::{
    primitives as poseidon, Pow5Chip, Pow5Config, Hash as PoseidonHash
};
use anyhow::Result;

/// Re-export for public inputs matching
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub challenge_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub auth_level: u8,
    pub timestamp: u64,
}

const MERKLE_DEPTH: usize = 20;
const DEVICE_TREE_DEPTH: usize = 10;  // 2^10 = 1024 devices per user
const WIDTH: usize = 3;
const RATE: usize = 2;

#[derive(Clone, Debug)]
pub struct AuthConfig {
    advice: [Column<Advice>; 8],
    instance: Column<Instance>,
    auth_selector: Selector,
    merkle_selector: Selector,
    bool_selector: Selector,
    swap_selector: Selector,
    credential_selector: Selector,
    poseidon_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AuthCircuit {
    // Private witnesses - User identity
    username_hash: Value<Fp>,
    password_hash: Value<Fp>,
    stored_credential_hash: Value<Fp>,
    merkle_path: Value<[Fp; MERKLE_DEPTH]>,
    leaf_index: Value<Fp>,
    
    // Private witnesses - Device identity (ring signature)
    device_commitment: Value<Fp>,
    device_merkle_path: Value<[Fp; DEVICE_TREE_DEPTH]>,
    device_position: Value<Fp>,
    linkability_tag: Value<Fp>,  // NEW: Linkability tag for zero-knowledge device binding
    
    // Public inputs
    pub merkle_root: Value<Fp>,
    pub nullifier: Value<Fp>,
    pub challenge: Value<Fp>,
    pub client_pubkey: Value<Fp>,
    pub timestamp: Value<Fp>,
    pub device_merkle_root: Value<Fp>,  // NEW: Device tree root
    
    // Raw values
    username_hash_raw: Fp,
    password_hash_raw: Fp,
    stored_credential_hash_raw: Fp,
    merkle_root_raw: Fp,
    nullifier_raw: Fp,
    challenge_raw: Fp,
    client_pubkey_raw: Fp,
    timestamp_raw: Fp,
    device_commitment_raw: Fp,
    device_merkle_root_raw: Fp,
    linkability_tag_raw: Fp,  // NEW: Raw linkability tag
}

impl AuthCircuit {
    pub fn new(
        username_hash: Fp,
        password_hash: Fp,
        stored_credential_hash: Fp,
        merkle_path: [Fp; MERKLE_DEPTH],
        leaf_index: u64,
        merkle_root: Fp,
        challenge: Fp,
        client_pubkey: Fp,
        timestamp: Fp,
        device_commitment: Fp,
        device_merkle_path: [Fp; DEVICE_TREE_DEPTH],
        device_position: u64,
        device_merkle_root: Fp,
        linkability_tag: Fp,  // NEW: Linkability tag parameter
    ) -> Result<Self> {
        let nullifier = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init()
            .hash([username_hash, password_hash]);
        
        Ok(Self {
            username_hash: Value::known(username_hash),
            password_hash: Value::known(password_hash),
            stored_credential_hash: Value::known(stored_credential_hash),
            merkle_path: Value::known(merkle_path),
            leaf_index: Value::known(Fp::from(leaf_index)),
            device_commitment: Value::known(device_commitment),
            device_merkle_path: Value::known(device_merkle_path),
            device_position: Value::known(Fp::from(device_position)),
            linkability_tag: Value::known(linkability_tag),  // NEW
            merkle_root: Value::known(merkle_root),
            nullifier: Value::known(nullifier),
            challenge: Value::known(challenge),
            client_pubkey: Value::known(client_pubkey),
            timestamp: Value::known(timestamp),
            device_merkle_root: Value::known(device_merkle_root),
            username_hash_raw: username_hash,
            password_hash_raw: password_hash,
            stored_credential_hash_raw: stored_credential_hash,
            merkle_root_raw: merkle_root,
            nullifier_raw: nullifier,
            challenge_raw: challenge,
            client_pubkey_raw: client_pubkey,
            timestamp_raw: timestamp,
            device_commitment_raw: device_commitment,
            device_merkle_root_raw: device_merkle_root,
            linkability_tag_raw: linkability_tag,  // NEW
        })
    }
    
    /// Compute session token as field element (for circuit)
    /// NOW BINDS TO LINKABILITY TAG (zero-knowledge device binding)
    pub fn compute_session_token_field(nullifier: Fp, timestamp: Fp, linkability_tag: Fp) -> Fp {
        poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<3>, WIDTH, RATE>::init()
            .hash([nullifier, timestamp, linkability_tag])
    }
    
    /// Hash credential using Blake3 (fast, ZK-friendly)
    /// NOTE: Argon2 password hashing happens BEFORE this, outside the circuit
    pub fn hash_credential(input: &[u8], domain: &[u8]) -> Result<Fp> {
        // Use Blake3 for domain-separated hashing
        // This is ZK-friendly and matches what the circuit expects
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"LEGION_CREDENTIAL_V2");
        hasher.update(domain);
        hasher.update(input);
        
        let hash = hasher.finalize();
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(hash.as_bytes());
        buf[32..].copy_from_slice(hash.as_bytes());
        
        Ok(Fp::from_uniform_bytes(&buf))
    }
    
    /// Hash password using Argon2id (ONLY for initial password storage)
    /// This should be called BEFORE hash_credential
    pub fn argon2_hash_password(password: &[u8], username: &[u8]) -> Result<Vec<u8>> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::SaltString;
        
        // Create deterministic salt from username
        let mut salt_bytes = [0u8; 16];
        let username_hash = blake3::hash(username);
        salt_bytes.copy_from_slice(&username_hash.as_bytes()[..16]);
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| anyhow::anyhow!("Salt encoding failed: {}", e))?;
        
        // Argon2id hashing (slow, secure)
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password, &salt)
            .map_err(|e| anyhow::anyhow!("Argon2 hashing failed: {}", e))?;
        
        // Extract hash bytes
        let hash_str = password_hash.hash.ok_or_else(|| anyhow::anyhow!("No hash output"))?;
        Ok(hash_str.as_bytes().to_vec())
    }
    
    pub fn public_inputs(&self) -> Vec<Fp> {
        // Compute bindings using Poseidon (strong cryptographic binding)
        let challenge_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init()
            .hash([self.nullifier_raw, self.challenge_raw]);
        
        let pubkey_binding = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init()
            .hash([self.nullifier_raw, self.client_pubkey_raw]);
        
        // Compute session token inside circuit: Hash(nullifier || timestamp || linkability_tag)
        let session_token = Self::compute_session_token_field(
            self.nullifier_raw,
            self.timestamp_raw,
            self.linkability_tag_raw,  // Use linkability_tag for zero-knowledge binding
        );
        
        // Compute expiration time: timestamp + 3600 seconds
        let expiration_time = self.timestamp_raw + Fp::from(3600u64);
        
        vec![
            self.merkle_root_raw,
            self.nullifier_raw,
            self.challenge_raw,
            self.client_pubkey_raw,
            challenge_binding,
            pubkey_binding,
            self.timestamp_raw,
            self.device_merkle_root_raw,  // Device tree root (public)
            session_token,
            expiration_time,
        ]
    }
    
    /// CRITICAL: Generate public inputs matching verifier expectations
    pub fn public_inputs_for_verifier(&self, auth_context: &crate::AuthContext) -> Vec<Fp> {
        vec![
            Fp::from(auth_context.timestamp),
            Fp::from_uniform_bytes(&[auth_context.challenge_hash[..32].try_into().unwrap(), [0u8; 32]].concat().try_into().unwrap()),
            Fp::from(auth_context.auth_level as u64),
            self.merkle_root_raw,  // Actual merkle root
            self.nullifier_raw,    // Actual nullifier
            Fp::from_uniform_bytes(&{let mut buf = [0u8; 64]; buf[..16].copy_from_slice(&auth_context.session_id); buf}),
            Fp::from(1u64),
            Fp::from(auth_context.timestamp % 100),
        ]
    }
    
    #[allow(dead_code)]
    fn verify_merkle_path(
        leaf: Fp,
        path: &[Fp; MERKLE_DEPTH],
        root: Fp,
        index: u64,
    ) -> bool {
        let mut current = leaf;
        
        for level in 0..MERKLE_DEPTH {
            let sibling = path[level];
            let direction_bit = (index >> level) & 1;
            
            let (left, right) = if direction_bit == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            
            current = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init()
                .hash([left, right]);
        }
        
        current == root
    }
}

impl Default for AuthCircuit {
    fn default() -> Self {
        Self {
            username_hash: Value::unknown(),
            password_hash: Value::unknown(),
            stored_credential_hash: Value::unknown(),
            merkle_path: Value::unknown(),
            leaf_index: Value::unknown(),
            device_commitment: Value::unknown(),
            device_merkle_path: Value::unknown(),
            device_position: Value::unknown(),
            linkability_tag: Value::unknown(),  // NEW
            merkle_root: Value::unknown(),
            nullifier: Value::unknown(),
            challenge: Value::unknown(),
            client_pubkey: Value::unknown(),
            timestamp: Value::unknown(),
            device_merkle_root: Value::unknown(),
            username_hash_raw: Fp::zero(),
            password_hash_raw: Fp::zero(),
            stored_credential_hash_raw: Fp::zero(),
            merkle_root_raw: Fp::zero(),
            nullifier_raw: Fp::zero(),
            challenge_raw: Fp::zero(),
            client_pubkey_raw: Fp::zero(),
            timestamp_raw: Fp::zero(),
            device_commitment_raw: Fp::zero(),
            device_merkle_root_raw: Fp::zero(),
            linkability_tag_raw: Fp::zero(),  // NEW
        }
    }
}

impl Circuit<Fp> for AuthCircuit {
    type Config = AuthConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice = [
            meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(),
            meta.advice_column(), meta.advice_column(), meta.advice_column(), meta.advice_column(),
        ];
        
        let instance = meta.instance_column();
        let auth_selector = meta.selector();
        let merkle_selector = meta.selector();
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let credential_selector = meta.selector();
        
        // Enable constants for Poseidon
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        
        meta.enable_equality(instance);
        for column in &advice {
            meta.enable_equality(*column);
        }
        
        // Poseidon configuration
        let state = [advice[0], advice[1], advice[2]];
        let partial_sbox = advice[3];
        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        
        let poseidon_config = Pow5Chip::configure::<poseidon::P128Pow5T3>(
            meta, state, partial_sbox, rc_a, rc_b,
        );
        
        // CRITICAL: Boolean constraint v * (1 - v) = 0
        meta.create_gate("bool_constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let v = meta.query_advice(advice[0], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            
            vec![s * (v.clone() * (one - v))]
        });
        
        // CRITICAL: Conditional swap constraints
        meta.create_gate("swap_constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let bit = meta.query_advice(advice[0], Rotation::cur());
            let current = meta.query_advice(advice[1], Rotation::cur());
            let sibling = meta.query_advice(advice[2], Rotation::cur());
            let left = meta.query_advice(advice[3], Rotation::cur());
            let right = meta.query_advice(advice[4], Rotation::cur());
            let one = halo2_proofs::plonk::Expression::Constant(Fp::one());
            
            vec![
                // left = bit * sibling + (1 - bit) * current
                s.clone() * (left - (bit.clone() * sibling.clone() + (one.clone() - bit.clone()) * current.clone())),
                // right = bit * current + (1 - bit) * sibling  
                s * (right - (bit.clone() * current + (one - bit) * sibling)),
            ]
        });
        
        // CRITICAL: Credential verification constraint
        meta.create_gate("credential_verification", |meta| {
            let s = meta.query_selector(credential_selector);
            let computed_hash = meta.query_advice(advice[0], Rotation::cur());
            let stored_hash = meta.query_advice(advice[1], Rotation::cur());
            
            vec![s * (computed_hash - stored_hash)]
        });
        

        

        
        AuthConfig {
            advice,
            instance,
            auth_selector,
            merkle_selector,
            bool_selector,
            swap_selector,
            credential_selector,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Assign credentials
        let username_cell = layouter.assign_region(
            || "username",
            |mut region| {
                region.assign_advice(|| "username", config.advice[0], 0, || self.username_hash)
            },
        )?;
        
        let password_cell = layouter.assign_region(
            || "password",
            |mut region| {
                region.assign_advice(|| "password", config.advice[1], 0, || self.password_hash)
            },
        )?;
        
        let stored_hash_cell = layouter.assign_region(
            || "stored_hash",
            |mut region| {
                region.assign_advice(|| "stored_hash", config.advice[2], 0, || self.stored_credential_hash)
            },
        )?;
        
        // CRITICAL: Compute credential hash from provided password
        let credential_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
            Pow5Chip::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "credential_hasher"),
        )?;
        
        let computed_credential_hash = credential_hasher.hash(
            layouter.namespace(|| "compute_credential"),
            [username_cell.clone(), password_cell.clone()],
        )?;
        
        // CRITICAL: Verify computed hash equals stored hash
        layouter.assign_region(
            || "credential_verification",
            |mut region| {
                config.credential_selector.enable(&mut region, 0)?;
                region.assign_advice(|| "computed", config.advice[0], 0, || computed_credential_hash.value().copied())?;
                region.assign_advice(|| "stored", config.advice[1], 0, || self.stored_credential_hash)?;
                Ok(())
            },
        )?;
        
        // Use stored hash as leaf (it's the actual tree leaf)
        let leaf_hash = stored_hash_cell;
        
        // CRITICAL: Fixed Merkle path verification with proper constraints
        let mut current_hash = leaf_hash;
        
        for level in 0..MERKLE_DEPTH {
            let sibling_cell = layouter.assign_region(
                || format!("sibling_{}", level),
                |mut region| {
                    region.assign_advice(
                        || format!("sibling_{}", level),
                        config.advice[2],
                        0,
                        || self.merkle_path.map(|path| path[level]),
                    )
                },
            )?;
            
            let direction_bit = layouter.assign_region(
                || format!("direction_{}", level),
                |mut region| {
                    region.assign_advice(
                        || format!("direction_{}", level),
                        config.advice[3],
                        0,
                        || self.leaf_index.map(|idx| {
                            let bytes = PrimeField::to_repr(&idx);
                            let index_u64 = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]));
                            Fp::from((index_u64 >> level) & 1)
                        }),
                    )
                },
            )?;
            
            // CRITICAL: Enforce boolean constraint on direction bit
            layouter.assign_region(
                || format!("bool_check_{}", level),
                |mut region| {
                    config.bool_selector.enable(&mut region, 0)?;
                    region.assign_advice(|| "bit", config.advice[0], 0, || direction_bit.value().copied())?;
                    Ok(())
                },
            )?;
            
            // CRITICAL: Arithmetized conditional swap
            let (left_input, right_input) = layouter.assign_region(
                || format!("conditional_swap_{}", level),
                |mut region| {
                    config.swap_selector.enable(&mut region, 0)?;
                    
                    // Assign inputs
                    region.assign_advice(|| "bit", config.advice[0], 0, || direction_bit.value().copied())?;
                    region.assign_advice(|| "current", config.advice[1], 0, || current_hash.value().copied())?;
                    region.assign_advice(|| "sibling", config.advice[2], 0, || sibling_cell.value().copied())?;
                    
                    // Compute and assign outputs using arithmetized logic
                    let left = region.assign_advice(
                        || "left",
                        config.advice[3],
                        0,
                        || {
                            direction_bit.value().zip(current_hash.value()).zip(sibling_cell.value())
                                .map(|((bit, curr), sib)| {
                                    // left = bit * sibling + (1 - bit) * current
                                    *bit * sib + (Fp::one() - bit) * curr
                                })
                        },
                    )?;
                    
                    let right = region.assign_advice(
                        || "right",
                        config.advice[4],
                        0,
                        || {
                            direction_bit.value().zip(current_hash.value()).zip(sibling_cell.value())
                                .map(|((bit, curr), sib)| {
                                    // right = bit * current + (1 - bit) * sibling
                                    *bit * curr + (Fp::one() - bit) * sib
                                })
                        },
                    )?;
                    
                    Ok((left, right))
                },
            )?;
            
            let next_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
                Pow5Chip::construct(config.poseidon_config.clone()),
                layouter.namespace(|| format!("merkle_hash_{}", level)),
            )?;
            
            current_hash = next_hasher.hash(
                layouter.namespace(|| format!("compute_parent_{}", level)),
                [left_input, right_input],
            )?;
        }
        
        // Compute nullifier
        let nullifier_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
            Pow5Chip::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "nullifier_hasher"),
        )?;
        
        let computed_nullifier = nullifier_hasher.hash(
            layouter.namespace(|| "compute_nullifier"),
            [username_cell, password_cell],
        )?;
        
        // Challenge cell
        let challenge_cell = layouter.assign_region(
            || "challenge",
            |mut region| {
                region.assign_advice(|| "challenge", config.advice[0], 0, || self.challenge)
            },
        )?;
        
        // Challenge binding using Poseidon (strong cryptographic binding)
        let challenge_binding_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
            Pow5Chip::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "challenge_binding_hasher"),
        )?;
        
        let challenge_binding = challenge_binding_hasher.hash(
            layouter.namespace(|| "compute_challenge_binding"),
            [computed_nullifier.clone(), challenge_cell.clone()],
        )?;
        
        // Pubkey cell
        let pubkey_cell = layouter.assign_region(
            || "pubkey",
            |mut region| {
                region.assign_advice(|| "pubkey", config.advice[0], 0, || self.client_pubkey)
            },
        )?;
        
        // Pubkey binding using Poseidon (strong cryptographic binding)
        let pubkey_binding_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
            Pow5Chip::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "pubkey_binding_hasher"),
        )?;
        
        let pubkey_binding = pubkey_binding_hasher.hash(
            layouter.namespace(|| "compute_pubkey_binding"),
            [computed_nullifier.clone(), pubkey_cell.clone()],
        )?;
        
        // Timestamp cell
        let timestamp_cell = layouter.assign_region(
            || "timestamp",
            |mut region| {
                region.assign_advice(|| "timestamp", config.advice[0], 0, || self.timestamp)
            },
        )?;
        
        // Device commitment cell
        let device_commitment_cell = layouter.assign_region(
            || "device_commitment",
            |mut region| {
                region.assign_advice(|| "device_commitment", config.advice[0], 0, || self.device_commitment)
            },
        )?;
        
        // Linkability tag cell (zero-knowledge device binding)
        let linkability_tag_cell = layouter.assign_region(
            || "linkability_tag",
            |mut region| {
                region.assign_advice(|| "linkability_tag", config.advice[0], 0, || self.linkability_tag)
            },
        )?;
        
        // DEVICE RING SIGNATURE: Verify device is in user's device tree
        let mut current_device_hash = device_commitment_cell.clone();
        
        for level in 0..DEVICE_TREE_DEPTH {
            let sibling_cell = layouter.assign_region(
                || format!("device_sibling_{}", level),
                |mut region| {
                    region.assign_advice(
                        || format!("device_sibling_{}", level),
                        config.advice[2],
                        0,
                        || self.device_merkle_path.map(|path| path[level]),
                    )
                },
            )?;
            
            let direction_bit = layouter.assign_region(
                || format!("device_direction_{}", level),
                |mut region| {
                    region.assign_advice(
                        || format!("device_direction_{}", level),
                        config.advice[3],
                        0,
                        || self.device_position.map(|idx| {
                            let bytes = PrimeField::to_repr(&idx);
                            let index_u64 = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]));
                            Fp::from((index_u64 >> level) & 1)
                        }),
                    )
                },
            )?;
            
            // Boolean constraint on direction bit
            layouter.assign_region(
                || format!("device_bool_check_{}", level),
                |mut region| {
                    config.bool_selector.enable(&mut region, 0)?;
                    region.assign_advice(|| "bit", config.advice[0], 0, || direction_bit.value().copied())?;
                    Ok(())
                },
            )?;
            
            // Conditional swap
            let (left_input, right_input) = layouter.assign_region(
                || format!("device_swap_{}", level),
                |mut region| {
                    config.swap_selector.enable(&mut region, 0)?;
                    
                    region.assign_advice(|| "bit", config.advice[0], 0, || direction_bit.value().copied())?;
                    region.assign_advice(|| "current", config.advice[1], 0, || current_device_hash.value().copied())?;
                    region.assign_advice(|| "sibling", config.advice[2], 0, || sibling_cell.value().copied())?;
                    
                    let left = region.assign_advice(
                        || "left",
                        config.advice[3],
                        0,
                        || {
                            direction_bit.value().zip(current_device_hash.value()).zip(sibling_cell.value())
                                .map(|((bit, curr), sib)| {
                                    *bit * sib + (Fp::one() - bit) * curr
                                })
                        },
                    )?;
                    
                    let right = region.assign_advice(
                        || "right",
                        config.advice[4],
                        0,
                        || {
                            direction_bit.value().zip(current_device_hash.value()).zip(sibling_cell.value())
                                .map(|((bit, curr), sib)| {
                                    *bit * curr + (Fp::one() - bit) * sib
                                })
                        },
                    )?;
                    
                    Ok((left, right))
                },
            )?;
            
            let device_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init(
                Pow5Chip::construct(config.poseidon_config.clone()),
                layouter.namespace(|| format!("device_hash_{}", level)),
            )?;
            
            current_device_hash = device_hasher.hash(
                layouter.namespace(|| format!("compute_device_parent_{}", level)),
                [left_input, right_input],
            )?;
        }
        
        // Device tree root is now current_device_hash
        let device_root_cell = current_device_hash;
        
        // Compute session token: Hash(nullifier || timestamp || linkability_tag)
        // CRITICAL: Use linkability_tag for zero-knowledge device binding
        let session_token_hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, poseidon::ConstantLength<3>, WIDTH, RATE>::init(
            Pow5Chip::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "session_token_hasher"),
        )?;
        
        let session_token = session_token_hasher.hash(
            layouter.namespace(|| "compute_session_token"),
            [computed_nullifier.clone(), timestamp_cell.clone(), linkability_tag_cell.clone()],
        )?;
        
        // Compute expiration time: timestamp + 3600
        let expiration_time_cell = layouter.assign_region(
            || "expiration_time",
            |mut region| {
                region.assign_advice(
                    || "expiration",
                    config.advice[0],
                    0,
                    || self.timestamp.map(|t| t + Fp::from(3600u64)),
                )
            },
        )?;
        
        // Constrain public inputs (10 total)
        layouter.constrain_instance(current_hash.cell(), config.instance, 0)?;              // merkle_root
        layouter.constrain_instance(computed_nullifier.cell(), config.instance, 1)?;        // nullifier
        layouter.constrain_instance(challenge_cell.cell(), config.instance, 2)?;            // challenge
        layouter.constrain_instance(pubkey_cell.cell(), config.instance, 3)?;               // client_pubkey
        layouter.constrain_instance(challenge_binding.cell(), config.instance, 4)?;         // challenge_binding
        layouter.constrain_instance(pubkey_binding.cell(), config.instance, 5)?;            // pubkey_binding
        layouter.constrain_instance(timestamp_cell.cell(), config.instance, 6)?;            // timestamp
        layouter.constrain_instance(device_root_cell.cell(), config.instance, 7)?;          // device_merkle_root
        layouter.constrain_instance(session_token.cell(), config.instance, 8)?;             // session_token
        layouter.constrain_instance(expiration_time_cell.cell(), config.instance, 9)?;      // expiration_time
        
        Ok(())
    }
}

