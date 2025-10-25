# Cryptographic Specification

## Overview

This document provides detailed cryptographic specifications for Legion Zero-Knowledge Authentication System. Legion implements a novel combination of zero-knowledge proofs, ring signatures, and hardware-bound authentication to achieve anonymous yet secure user authentication.

## Cryptographic Primitives

### Hash Functions

#### Blake3
- **Purpose**: Fast, secure hashing for credential processing
- **Output Size**: 256 bits
- **Security Level**: 128-bit security
- **Usage**: Username/password hashing, linkability tag generation

#### Poseidon Hash
- **Purpose**: Zero-knowledge friendly hashing within circuits
- **Field**: Pasta curves (Pallas/Vesta)
- **Parameters**: P128Pow5T3 (128-bit security, power-of-5 S-box, 3 full rounds)
- **Usage**: Merkle tree construction, nullifier generation, session token computation

#### Argon2id
- **Purpose**: Password-based key derivation
- **Memory**: 64 MB default
- **Iterations**: 3 default
- **Parallelism**: 4 threads default
- **Usage**: Secure password hashing before circuit input

### Elliptic Curves

#### Pasta Curves (Pallas/Vesta)
- **Field Size**: 255 bits
- **Security Level**: 128-bit
- **Cycle Property**: Enables efficient recursive proof composition
- **Usage**: Zero-knowledge proof system base field

#### secp256k1 (WebAuthn)
- **Field Size**: 256 bits
- **Usage**: Hardware-bound device key generation
- **Integration**: WebAuthn Level 2 compliance

### Zero-Knowledge Proof System

#### Halo2 PLONK
- **Type**: Universal, updatable zk-SNARK
- **Setup**: Transparent (no trusted setup required)
- **Proof Size**: ~3.5 KB (k=16)
- **Verification Time**: ~10 milliseconds
- **Security Parameters**:
  - k=12: Testing (2^12 = 4,096 constraints)
  - k=14: Development (2^14 = 16,384 constraints)
  - k=16: Production (2^16 = 65,536 constraints)
  - k=18: High Security (2^18 = 262,144 constraints)

## Authentication Protocol

### Credential Processing

#### Username Hash Computation
```
username_hash = Blake3("LEGION_CREDENTIAL_V2" || "USERNAME" || username)
```

#### Password Hash Computation
```
salt = Blake3(username)[0..16]
argon2_output = Argon2id(password, salt, memory=64MB, iterations=3, parallelism=4)
password_hash = Blake3("LEGION_CREDENTIAL_V2" || "PASSWORD" || argon2_output)
```

#### User Leaf Generation
```
user_leaf = Poseidon(username_hash, password_hash)
```

### Anonymity Set Construction

#### Merkle Tree Structure
- **Depth**: 20 levels (supports 2^20 = 1,048,576 users)
- **Hash Function**: Poseidon
- **Leaf Computation**: `Poseidon(username_hash, password_hash)`
- **Internal Node**: `Poseidon(left_child, right_child)`

#### Tree Index Assignment
```
tree_position = register_order  // Sequential assignment
merkle_path = compute_path(tree_position, tree_depth=20)
```

### Device Ring Signatures

#### Device Tree Structure
- **Depth**: 10 levels (supports 2^10 = 1,024 devices per user)
- **Hash Function**: Poseidon
- **Leaf**: Device commitment (WebAuthn public key)
- **Purpose**: Anonymous device authentication within user's device set

#### Device Commitment
```
device_private_key = WebAuthn_generate_key()
device_public_key = device_private_key * G  // Elliptic curve point multiplication
device_commitment = Poseidon(device_public_key.x, device_public_key.y)
```

### Zero-Knowledge Circuit

#### Public Inputs (10 elements)
1. `merkle_root`: Current anonymity tree root
2. `nullifier`: Unique authentication identifier
3. `challenge`: Server-generated randomness
4. `client_pubkey`: Device public key
5. `challenge_binding`: Cryptographic binding of nullifier and challenge
6. `pubkey_binding`: Cryptographic binding of nullifier and device key
7. `timestamp`: Authentication timestamp
8. `device_merkle_root`: User's device tree root
9. `session_token`: Computed session identifier
10. `expiration_time`: Session expiration timestamp

#### Private Witnesses
- `username_hash`: Hashed username
- `password_hash`: Hashed password
- `merkle_path[20]`: Path from user leaf to tree root
- `leaf_index`: User's position in anonymity tree
- `device_commitment`: Device public key commitment
- `device_merkle_path[10]`: Path from device to device tree root
- `device_position`: Device position in user's device tree
- `linkability_tag`: Zero-knowledge device binding tag

#### Circuit Constraints

##### Credential Verification
```
computed_hash = Poseidon(username_hash, password_hash)
assert(computed_hash == stored_credential_hash)
```

##### Merkle Path Verification
```
current = stored_credential_hash
for i in 0..20:
    direction_bit = (leaf_index >> i) & 1
    sibling = merkle_path[i]
    
    // Conditional swap based on direction
    left = direction_bit * sibling + (1 - direction_bit) * current
    right = direction_bit * current + (1 - direction_bit) * sibling
    
    current = Poseidon(left, right)

assert(current == merkle_root)
```

##### Device Ring Signature Verification
```
current_device = device_commitment
for i in 0..10:
    direction_bit = (device_position >> i) & 1
    sibling = device_merkle_path[i]
    
    left = direction_bit * sibling + (1 - direction_bit) * current_device
    right = direction_bit * current_device + (1 - direction_bit) * sibling
    
    current_device = Poseidon(left, right)

assert(current_device == device_merkle_root)
```

##### Nullifier Generation
```
nullifier = Poseidon(username_hash, password_hash)
```

##### Binding Computations
```
challenge_binding = Poseidon(nullifier, challenge)
pubkey_binding = Poseidon(nullifier, client_pubkey)
```

##### Session Token Generation
```
session_token = Poseidon(nullifier, timestamp, linkability_tag)
expiration_time = timestamp + 3600  // 1 hour validity
```

## Security Properties

### Zero-Knowledge Properties

#### Completeness
If a user possesses valid credentials and is registered in the anonymity set, the proof will verify successfully with overwhelming probability.

#### Soundness
An adversary cannot generate a valid proof without knowing valid credentials for some user in the anonymity set. Soundness error is bounded by 2^-128.

#### Zero-Knowledge
The proof reveals no information about which specific user in the anonymity set is authenticating, beyond the fact that some valid user is authenticating.

### Anonymity Guarantees

#### User Anonymity
- **Anonymity Set Size**: 2^20 (1,048,576 users)
- **Indistinguishability**: Server cannot determine which user is authenticating
- **Unlinkability**: Multiple authentications by the same user appear independent

#### Device Anonymity
- **Device Set Size**: 2^10 (1,024 devices per user)
- **Ring Signature**: Proves device ownership without revealing which device
- **Linkability Control**: Linkability tags enable session binding while preserving anonymity

### Replay Protection

#### Nullifier System
```
nullifier = Poseidon(username_hash, password_hash)
nullifier_hash = Blake3(nullifier)
```

- **Uniqueness**: Each credential pair produces a unique nullifier
- **Deterministic**: Same credentials always produce the same nullifier
- **Storage**: Nullifiers are stored to prevent reuse
- **Cleanup**: Expired nullifiers are periodically removed

#### Challenge-Response
```
challenge = random_256_bits()
challenge_binding = Poseidon(nullifier, challenge)
```

- **Freshness**: Each authentication requires a fresh challenge
- **Binding**: Challenge is cryptographically bound to the proof
- **Expiration**: Challenges expire after 5 minutes

### Forward Secrecy

#### Session Key Rotation
- **Session Tokens**: Generated fresh for each authentication
- **Expiration**: Sessions automatically expire after 1 hour
- **Revocation**: Sessions can be immediately invalidated

#### Device Key Management
- **Hardware Binding**: Device keys are bound to hardware security modules
- **Rotation**: Device keys can be rotated without losing user identity
- **Revocation**: Compromised devices can be immediately blacklisted

## Implementation Security

### Constant-Time Operations

All cryptographic operations are implemented to run in constant time to prevent timing attacks:

- Field arithmetic operations
- Hash function computations
- Merkle path traversals
- Proof generation and verification

### Memory Protection

Sensitive data is protected using secure memory management:

- Credential data is zeroed after use
- Private keys are stored in protected memory regions
- Proof generation uses secure random number generation

### Side-Channel Resistance

The implementation includes protections against side-channel attacks:

- Power analysis resistance through uniform operations
- Cache-timing attack mitigation via constant memory access patterns
- Electromagnetic emanation protection through balanced implementations

## Cryptographic Assumptions

### Hardness Assumptions

#### Discrete Logarithm Problem
The security of device keys relies on the hardness of computing discrete logarithms in elliptic curve groups.

#### Hash Function Security
- **Collision Resistance**: Blake3 and Poseidon are assumed to be collision-resistant
- **Preimage Resistance**: Hash functions are assumed to be one-way
- **Random Oracle Model**: Hash functions are modeled as random oracles in security proofs

#### Knowledge of Exponent Assumption
The soundness of Halo2 proofs relies on the Knowledge of Exponent Assumption over the Pasta curve cycle.

### Quantum Resistance

#### Current Status
Legion's current cryptographic primitives are not quantum-resistant:
- Elliptic curve cryptography is vulnerable to Shor's algorithm
- Hash functions remain secure against quantum attacks

#### Migration Path
- Post-quantum signature schemes can replace WebAuthn device keys
- Hash-based signatures provide quantum-resistant device authentication
- Lattice-based zero-knowledge proofs offer quantum-resistant anonymity

## Performance Characteristics

### Proof Generation
- **k=12**: ~10 seconds, 2.5 KB proof
- **k=14**: ~60 seconds, 3.0 KB proof
- **k=16**: ~4 minutes, 3.5 KB proof (recommended)
- **k=18**: ~15 minutes, 4.0 KB proof

### Verification
- **Time**: ~10 milliseconds (all security levels)
- **Memory**: ~100 MB peak usage
- **Parallelization**: Verification can be parallelized across multiple cores

### Storage Requirements
- **Anonymity Tree**: ~32 MB for 1M users
- **Device Trees**: ~32 KB per user (1K devices)
- **Nullifier Storage**: ~32 bytes per authentication
- **Session Storage**: ~256 bytes per active session

## Compliance and Standards

### Cryptographic Standards
- **FIPS 140-2**: Hash functions and random number generation
- **NIST SP 800-56A**: Elliptic curve key agreement
- **RFC 8017**: PKCS #1 RSA cryptography (WebAuthn compatibility)

### Privacy Regulations
- **GDPR**: Zero-knowledge properties support data minimization
- **CCPA**: Anonymous authentication reduces personal data collection
- **HIPAA**: Cryptographic protections support healthcare compliance

### Authentication Standards
- **WebAuthn Level 2**: Hardware-bound device authentication
- **FIDO2**: Passwordless authentication compatibility
- **OAuth 2.0**: Session management integration patterns