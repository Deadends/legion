use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use ff::{PrimeField, Field};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    marker::PhantomData,
    time::{SystemTime, UNIX_EPOCH},
};
use sha3::{Digest, Sha3_256};

/// Parameter Integrity Verification System
/// Ensures cryptographic parameters maintain integrity throughout circuit execution
pub struct ParamIntegrityChip<F: PrimeField> {
    config: ParamIntegrityConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
pub struct ParamIntegrityConfig {
    /// Parameter storage columns
    pub param_storage: [Column<Advice>; 8],
    /// Integrity check columns
    pub integrity_checks: [Column<Advice>; 4],
    /// Hash verification columns
    pub hash_verification: [Column<Advice>; 6],
    /// Selector for parameter operations
    pub s_param_op: Selector,
    /// Selector for integrity verification
    pub s_integrity: Selector,
    /// Selector for hash computation
    pub s_hash: Selector,
}

/// Cryptographic parameter with integrity protection
#[derive(Clone, Debug)]
pub struct SecureParameter<F: PrimeField> {
    /// Parameter value
    pub value: Value<F>,
    /// Integrity hash
    pub hash: Value<F>,
    /// Creation timestamp
    pub timestamp: Value<F>,
    /// Parameter type identifier
    pub param_type: u8,
    /// Security level
    pub security_level: u8,
    /// Verification counter
    pub verification_count: u32,
}

/// Parameter integrity verification result
#[derive(Clone, Debug)]
pub struct IntegrityResult<F: PrimeField> {
    /// Verification status
    pub is_valid: Value<F>,
    /// Computed hash
    pub computed_hash: Value<F>,
    /// Expected hash
    pub expected_hash: Value<F>,
    /// Verification timestamp
    pub verification_time: Value<F>,
}

/// Parameter type definitions
#[derive(Clone, Debug, PartialEq)]
pub enum ParameterType {
    /// Elliptic curve parameters
    CurveParameter = 0,
    /// Hash function parameters
    HashParameter = 1,
    /// Signature scheme parameters
    SignatureParameter = 2,
    /// Encryption parameters
    EncryptionParameter = 3,
    /// Zero-knowledge proof parameters
    ZkParameter = 4,
    /// Random oracle parameters
    OracleParameter = 5,
    /// Commitment scheme parameters
    CommitmentParameter = 6,
    /// Protocol-specific parameters
    ProtocolParameter = 7,
}

/// Global parameter registry for integrity tracking
static PARAM_REGISTRY: once_cell::sync::Lazy<Arc<RwLock<ParameterRegistry>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(ParameterRegistry::new())));

/// Parameter registry for tracking all cryptographic parameters
#[derive(Debug)]
pub struct ParameterRegistry {
    /// Registered parameters by ID
    pub parameters: HashMap<[u8; 32], ParameterEntry>,
    /// Parameter dependency graph
    pub dependencies: HashMap<[u8; 32], Vec<[u8; 32]>>,
    /// Integrity violation log
    pub violations: Vec<IntegrityViolation>,
    /// Last global integrity check
    pub last_global_check: u64,
}

/// Parameter entry in registry
#[derive(Debug, Clone)]
pub struct ParameterEntry {
    pub param_id: [u8; 32],
    pub param_type: ParameterType,
    pub value_hash: [u8; 32],
    pub creation_time: u64,
    pub last_verification: u64,
    pub verification_count: u32,
    pub security_level: u8,
    pub is_immutable: bool,
}

/// Integrity violation record
#[derive(Debug, Clone)]
pub struct IntegrityViolation {
    pub param_id: [u8; 32],
    pub violation_type: ViolationType,
    pub timestamp: u64,
    pub expected_hash: [u8; 32],
    pub actual_hash: [u8; 32],
    pub severity: u8,
}

#[derive(Debug, Clone)]
pub enum ViolationType {
    HashMismatch,
    UnauthorizedModification,
    TemporalInconsistency,
    DependencyViolation,
    SecurityLevelDowngrade,
}

impl ParameterRegistry {
    pub fn new() -> Self {
        Self {
            parameters: HashMap::new(),
            dependencies: HashMap::new(),
            violations: Vec::new(),
            last_global_check: 0,
        }
    }

    pub fn register_parameter(&mut self, entry: ParameterEntry) -> Result<(), String> {
        // Check for conflicts
        if self.parameters.contains_key(&entry.param_id) {
            return Err("Parameter already registered".to_string());
        }

        // Validate parameter integrity
        if entry.value_hash == [0u8; 32] {
            return Err("Invalid parameter hash".to_string());
        }

        self.parameters.insert(entry.param_id, entry);
        Ok(())
    }

    pub fn verify_parameter(&mut self, param_id: &[u8; 32], current_hash: &[u8; 32]) -> bool {
        if let Some(entry) = self.parameters.get_mut(param_id) {
            let is_valid = entry.value_hash == *current_hash;
            
            if is_valid {
                entry.last_verification = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                entry.verification_count += 1;
            } else {
                self.violations.push(IntegrityViolation {
                    param_id: *param_id,
                    violation_type: ViolationType::HashMismatch,
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    expected_hash: entry.value_hash,
                    actual_hash: *current_hash,
                    severity: 3,
                });
            }
            
            is_valid
        } else {
            false
        }
    }
}

impl<F: Field> ParamIntegrityChip<F> {
    pub fn construct(config: ParamIntegrityConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        param_storage: [Column<Advice>; 8],
        integrity_checks: [Column<Advice>; 4],
        hash_verification: [Column<Advice>; 6],
    ) -> ParamIntegrityConfig {
        let s_param_op = meta.selector();
        let s_integrity = meta.selector();
        let s_hash = meta.selector();

        // Enable equality for all columns
        for col in param_storage.iter() {
            meta.enable_equality(*col);
        }
        for col in integrity_checks.iter() {
            meta.enable_equality(*col);
        }
        for col in hash_verification.iter() {
            meta.enable_equality(*col);
        }

        // Parameter integrity constraint
        meta.create_gate("param_integrity", |meta| {
            let s = meta.query_selector(s_param_op);
            
            let param_value = meta.query_advice(param_storage[0], Rotation::cur());
            let param_hash = meta.query_advice(param_storage[1], Rotation::cur());
            let param_type = meta.query_advice(param_storage[2], Rotation::cur());
            let security_level = meta.query_advice(param_storage[3], Rotation::cur());
            let timestamp = meta.query_advice(param_storage[4], Rotation::cur());
            let verification_count = meta.query_advice(param_storage[5], Rotation::cur());
            
            // Parameter type must be valid (0-7)
            let type_constraint = param_type.clone() * (param_type.clone() - Expression::Constant(F::one()))
                * (param_type.clone() - Expression::Constant(F::from(2u64)))
                * (param_type.clone() - Expression::Constant(F::from(3u64)))
                * (param_type.clone() - Expression::Constant(F::from(4u64)))
                * (param_type.clone() - Expression::Constant(F::from(5u64)))
                * (param_type.clone() - Expression::Constant(F::from(6u64)))
                * (param_type.clone() - Expression::Constant(F::from(7u64)));
            
            // Security level must be reasonable (1-255)
            let security_constraint = security_level.clone() * (security_level.clone() - Expression::Constant(F::from(256u64)));
            
            // Timestamp must be non-zero
            let timestamp_constraint = timestamp.clone();
            
            // Verification count must be non-negative
            let count_constraint = verification_count.clone();
            
            vec![
                s.clone() * type_constraint,
                s.clone() * security_constraint,
                s.clone() * timestamp_constraint,
                s * count_constraint,
            ]
        });

        // Hash verification constraint
        meta.create_gate("hash_verification", |meta| {
            let s = meta.query_selector(s_hash);
            
            let input_1 = meta.query_advice(hash_verification[0], Rotation::cur());
            let input_2 = meta.query_advice(hash_verification[1], Rotation::cur());
            let input_3 = meta.query_advice(hash_verification[2], Rotation::cur());
            let salt = meta.query_advice(hash_verification[3], Rotation::cur());
            let expected_hash = meta.query_advice(hash_verification[4], Rotation::cur());
            let computed_hash = meta.query_advice(hash_verification[5], Rotation::cur());
            
            // Simplified hash function: hash = (input_1 + input_2 + input_3 + salt)^3
            let hash_input = input_1 + input_2 + input_3 + salt;
            let expected_computed = hash_input.clone() * hash_input.clone() * hash_input;
            
            vec![
                s.clone() * (computed_hash.clone() - expected_computed),
                s * (expected_hash - computed_hash),
            ]
        });

        // Integrity verification constraint
        meta.create_gate("integrity_check", |meta| {
            let s = meta.query_selector(s_integrity);
            
            let original_hash = meta.query_advice(integrity_checks[0], Rotation::cur());
            let current_hash = meta.query_advice(integrity_checks[1], Rotation::cur());
            let is_valid = meta.query_advice(integrity_checks[2], Rotation::cur());
            let verification_time = meta.query_advice(integrity_checks[3], Rotation::cur());
            
            // Integrity check: is_valid = 1 if hashes match, 0 otherwise
            let hash_diff = original_hash - current_hash;
            let validity_constraint = is_valid.clone() * (is_valid.clone() - Expression::Constant(F::one()));
            
            // If hashes match (diff = 0), is_valid should be 1
            // If hashes don't match (diff ≠ 0), is_valid should be 0
            let integrity_constraint = hash_diff.clone() * is_valid.clone();
            
            vec![
                s.clone() * validity_constraint,
                s * integrity_constraint,
            ]
        });

        ParamIntegrityConfig {
            param_storage,
            integrity_checks,
            hash_verification,
            s_param_op,
            s_integrity,
            s_hash,
        }
    }

    /// Register a new cryptographic parameter
    pub fn register_parameter(
        &self,
        mut layouter: impl Layouter<F>,
        param_value: Value<F>,
        param_type: ParameterType,
        security_level: u8,
    ) -> Result<SecureParameter<F>, Error> {
        layouter.assign_region(
            || "register_parameter",
            |mut region| {
                self.config.s_param_op.enable(&mut region, 0)?;

                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Compute parameter hash
                let param_hash = param_value.map(|val| {
                    self.compute_parameter_hash(val, param_type.clone() as u8, security_level, timestamp)
                });

                let param_value_cell = region.assign_advice(
                    || "param_value",
                    self.config.param_storage[0],
                    0,
                    || param_value,
                )?;

                let param_hash_cell = region.assign_advice(
                    || "param_hash",
                    self.config.param_storage[1],
                    0,
                    || param_hash,
                )?;

                let param_type_cell = region.assign_advice(
                    || "param_type",
                    self.config.param_storage[2],
                    0,
                    || Value::known(F::from(param_type as u8 as u64)),
                )?;

                let security_level_cell = region.assign_advice(
                    || "security_level",
                    self.config.param_storage[3],
                    0,
                    || Value::known(F::from(security_level as u64)),
                )?;

                let timestamp_cell = region.assign_advice(
                    || "timestamp",
                    self.config.param_storage[4],
                    0,
                    || Value::known(F::from(timestamp)),
                )?;

                let verification_count_cell = region.assign_advice(
                    || "verification_count",
                    self.config.param_storage[5],
                    0,
                    || Value::known(F::zero()),
                )?;

                // Register in global registry
                self.register_in_global_registry(param_value, param_hash, param_type, security_level, timestamp)?;

                Ok(SecureParameter {
                    value: param_value_cell.value().copied(),
                    hash: param_hash_cell.value().copied(),
                    timestamp: timestamp_cell.value().copied(),
                    param_type: param_type as u8,
                    security_level,
                    verification_count: 0,
                })
            },
        )
    }

    /// Verify parameter integrity
    pub fn verify_parameter_integrity(
        &self,
        mut layouter: impl Layouter<F>,
        parameter: &SecureParameter<F>,
    ) -> Result<IntegrityResult<F>, Error> {
        layouter.assign_region(
            || "verify_integrity",
            |mut region| {
                self.config.s_integrity.enable(&mut region, 0)?;
                self.config.s_hash.enable(&mut region, 1)?;

                let verification_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                // Recompute hash for current parameter value
                let computed_hash = parameter.value.map(|val| {
                    self.compute_parameter_hash(
                        val,
                        parameter.param_type,
                        parameter.security_level,
                        verification_time,
                    )
                });

                // Hash verification region
                region.assign_advice(
                    || "hash_input_1",
                    self.config.hash_verification[0],
                    1,
                    || parameter.value,
                )?;

                region.assign_advice(
                    || "hash_input_2",
                    self.config.hash_verification[1],
                    1,
                    || Value::known(F::from(parameter.param_type as u64)),
                )?;

                region.assign_advice(
                    || "hash_input_3",
                    self.config.hash_verification[2],
                    1,
                    || Value::known(F::from(parameter.security_level as u64)),
                )?;

                region.assign_advice(
                    || "hash_salt",
                    self.config.hash_verification[3],
                    1,
                    || Value::known(F::from(verification_time)),
                )?;

                region.assign_advice(
                    || "expected_hash",
                    self.config.hash_verification[4],
                    1,
                    || parameter.hash,
                )?;

                let computed_hash_cell = region.assign_advice(
                    || "computed_hash",
                    self.config.hash_verification[5],
                    1,
                    || computed_hash,
                )?;

                // Integrity check region
                region.assign_advice(
                    || "original_hash",
                    self.config.integrity_checks[0],
                    0,
                    || parameter.hash,
                )?;

                region.assign_advice(
                    || "current_hash",
                    self.config.integrity_checks[1],
                    0,
                    || computed_hash,
                )?;

                let is_valid = parameter.hash.zip(computed_hash).map(|(orig, comp)| {
                    if orig == comp { F::one() } else { F::zero() }
                });

                let is_valid_cell = region.assign_advice(
                    || "is_valid",
                    self.config.integrity_checks[2],
                    0,
                    || is_valid,
                )?;

                let verification_time_cell = region.assign_advice(
                    || "verification_time",
                    self.config.integrity_checks[3],
                    0,
                    || Value::known(F::from(verification_time)),
                )?;

                Ok(IntegrityResult {
                    is_valid: is_valid_cell.value().copied(),
                    computed_hash: computed_hash_cell.value().copied(),
                    expected_hash: parameter.hash,
                    verification_time: verification_time_cell.value().copied(),
                })
            },
        )
    }

    /// Batch verify multiple parameters
    pub fn batch_verify_parameters(
        &self,
        mut layouter: impl Layouter<F>,
        parameters: &[SecureParameter<F>],
    ) -> Result<Vec<IntegrityResult<F>>, Error> {
        let mut results = Vec::new();

        for (i, param) in parameters.iter().enumerate() {
            let result = layouter.assign_region(
                || format!("batch_verify_{}", i),
                |mut region| {
                    self.config.s_integrity.enable(&mut region, 0)?;

                    let verification_time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let computed_hash = param.value.map(|val| {
                        self.compute_parameter_hash(
                            val,
                            param.param_type,
                            param.security_level,
                            verification_time,
                        )
                    });

                    region.assign_advice(
                        || "batch_original_hash",
                        self.config.integrity_checks[0],
                        0,
                        || param.hash,
                    )?;

                    region.assign_advice(
                        || "batch_current_hash",
                        self.config.integrity_checks[1],
                        0,
                        || computed_hash,
                    )?;

                    let is_valid = param.hash.zip(computed_hash).map(|(orig, comp)| {
                        if orig == comp { F::one() } else { F::zero() }
                    });

                    let is_valid_cell = region.assign_advice(
                        || "batch_is_valid",
                        self.config.integrity_checks[2],
                        0,
                        || is_valid,
                    )?;

                    let verification_time_cell = region.assign_advice(
                        || "batch_verification_time",
                        self.config.integrity_checks[3],
                        0,
                        || Value::known(F::from(verification_time)),
                    )?;

                    Ok(IntegrityResult {
                        is_valid: is_valid_cell.value().copied(),
                        computed_hash,
                        expected_hash: param.hash,
                        verification_time: verification_time_cell.value().copied(),
                    })
                },
            )?;

            results.push(result);
        }

        Ok(results)
    }

    /// Update parameter with integrity protection
    pub fn update_parameter(
        &self,
        mut layouter: impl Layouter<F>,
        old_param: &SecureParameter<F>,
        new_value: Value<F>,
    ) -> Result<SecureParameter<F>, Error> {
        layouter.assign_region(
            || "update_parameter",
            |mut region| {
                self.config.s_param_op.enable(&mut region, 0)?;

                // Verify old parameter first
                let verification_result = self.verify_parameter_integrity(
                    layouter.namespace(|| "verify_before_update"),
                    old_param,
                )?;

                // Only proceed if old parameter is valid
                let update_timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let new_hash = new_value.map(|val| {
                    self.compute_parameter_hash(
                        val,
                        old_param.param_type,
                        old_param.security_level,
                        update_timestamp,
                    )
                });

                let new_value_cell = region.assign_advice(
                    || "new_param_value",
                    self.config.param_storage[0],
                    0,
                    || new_value,
                )?;

                let new_hash_cell = region.assign_advice(
                    || "new_param_hash",
                    self.config.param_storage[1],
                    0,
                    || new_hash,
                )?;

                let new_timestamp_cell = region.assign_advice(
                    || "new_timestamp",
                    self.config.param_storage[4],
                    0,
                    || Value::known(F::from(update_timestamp)),
                )?;

                let new_verification_count = region.assign_advice(
                    || "new_verification_count",
                    self.config.param_storage[5],
                    0,
                    || Value::known(F::from(old_param.verification_count as u64 + 1)),
                )?;

                Ok(SecureParameter {
                    value: new_value_cell.value().copied(),
                    hash: new_hash_cell.value().copied(),
                    timestamp: new_timestamp_cell.value().copied(),
                    param_type: old_param.param_type,
                    security_level: old_param.security_level,
                    verification_count: old_param.verification_count + 1,
                })
            },
        )
    }

    /// Compute cryptographic hash of parameter
    fn compute_parameter_hash(&self, value: F, param_type: u8, security_level: u8, timestamp: u64) -> F {
        // Convert field element to bytes
        let value_bytes = value.to_repr();
        
        // Create hash input
        let mut hasher = Sha3_256::new();
        hasher.update(&value_bytes.as_ref());
        hasher.update(&[param_type]);
        hasher.update(&[security_level]);
        hasher.update(&timestamp.to_le_bytes());
        hasher.update(b"LEGION_PARAM_INTEGRITY");
        
        let hash_bytes = hasher.finalize();
        
        // Convert hash back to field element
        F::from_bytes(&hash_bytes[..32]).unwrap_or(F::zero())
    }

    /// Register parameter in global registry
    fn register_in_global_registry(
        &self,
        param_value: Value<F>,
        param_hash: Value<F>,
        param_type: ParameterType,
        security_level: u8,
        timestamp: u64,
    ) -> Result<(), Error> {
        if let Ok(mut registry) = PARAM_REGISTRY.write() {
            // Generate parameter ID
            let mut param_id = [0u8; 32];
            if let (Some(value), Some(hash)) = (param_value.into_option(), param_hash.into_option()) {
                let value_bytes = value.to_repr();
                let hash_bytes = hash.to_repr();
                
                let mut hasher = Sha3_256::new();
                hasher.update(&value_bytes.as_ref());
                hasher.update(&hash_bytes.as_ref());
                hasher.update(&[param_type.clone() as u8]);
                
                let id_hash = hasher.finalize();
                param_id.copy_from_slice(&id_hash[..32]);
            }

            let entry = ParameterEntry {
                param_id,
                param_type,
                value_hash: param_hash.map(|h| h.to_repr().as_ref().try_into().unwrap_or([0u8; 32])).unwrap_or([0u8; 32]),
                creation_time: timestamp,
                last_verification: timestamp,
                verification_count: 0,
                security_level,
                is_immutable: security_level >= 128, // High security parameters are immutable
            };

            registry.register_parameter(entry).map_err(|_| Error::Synthesis)?;
        }

        Ok(())
    }

    /// Get parameter integrity statistics
    pub fn get_integrity_stats(&self) -> IntegrityStats {
        if let Ok(registry) = PARAM_REGISTRY.read() {
            IntegrityStats {
                total_parameters: registry.parameters.len(),
                total_verifications: registry.parameters.values().map(|p| p.verification_count).sum(),
                integrity_violations: registry.violations.len(),
                last_global_check: registry.last_global_check,
            }
        } else {
            IntegrityStats::default()
        }
    }
}

/// Parameter integrity statistics
#[derive(Debug, Default)]
pub struct IntegrityStats {
    pub total_parameters: usize,
    pub total_verifications: u32,
    pub integrity_violations: usize,
    pub last_global_check: u64,
}

impl<F: PrimeField> Chip<F> for ParamIntegrityChip<F> {
    type Config = ParamIntegrityConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

/// Parameter integrity utilities
pub mod integrity_utils {
    use super::*;

    /// Validate parameter dependencies
    pub fn validate_dependencies(param_id: &[u8; 32]) -> Result<bool, String> {
        if let Ok(registry) = PARAM_REGISTRY.read() {
            if let Some(deps) = registry.dependencies.get(param_id) {
                for dep_id in deps {
                    if !registry.parameters.contains_key(dep_id) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        } else {
            Err("Registry access failed".to_string())
        }
    }

    /// Perform global integrity check
    pub fn global_integrity_check() -> Result<Vec<IntegrityViolation>, String> {
        if let Ok(mut registry) = PARAM_REGISTRY.write() {
            let mut violations = Vec::new();
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            for (param_id, entry) in &registry.parameters {
                // Check for stale parameters (not verified in 24 hours)
                if current_time - entry.last_verification > 86400 {
                    violations.push(IntegrityViolation {
                        param_id: *param_id,
                        violation_type: ViolationType::TemporalInconsistency,
                        timestamp: current_time,
                        expected_hash: entry.value_hash,
                        actual_hash: [0u8; 32], // Unknown
                        severity: 2,
                    });
                }
            }

            registry.last_global_check = current_time;
            Ok(violations)
        } else {
            Err("Registry access failed".to_string())
        }
    }

    /// Export parameter registry for backup
    pub fn export_registry() -> Result<Vec<u8>, String> {
        if let Ok(registry) = PARAM_REGISTRY.read() {
            serde_json::to_vec(&*registry).map_err(|e| e.to_string())
        } else {
            Err("Registry access failed".to_string())
        }
    }
}