# Legion ZK Auth - Complete Architecture Flow 🔐

## 🎯 True Zero-Knowledge Authentication Flow

This document provides a detailed, step-by-step visualization of how Legion implements true zero-knowledge authentication with hardware-bound device signatures.

---

## 📊 Complete Authentication Flow

```
╔══════════════════════════════════════════════════════════════════════════╗
║                     LEGION ZK AUTHENTICATION FLOW                        ║
║                  (True Zero-Knowledge with Hardware Binding)             ║
╚══════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────┐
│                          CLIENT (Browser/WASM)                          │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 1: CREDENTIAL HASHING (Client-Side)                  ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
    ┌──────────────────────────────────────────────────────────┐
    │  Input: 24-word recovery phrase (BIP-39)                 │
    │         "abandon abandon ... art"                        │
    │                                                          │
    │  Compute:                                                │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ bip39_seed = BIP39.to_seed(mnemonic)              │   │
    │  │ → 64 bytes (512-bit seed)                         │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ account_id = Blake3("LEGION_ACCOUNT_V2" ||        │   │
    │  │                     bip39_seed)                   │   │
    │  │ → 32 bytes (deterministic account ID)             │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ credential_hash = Poseidon(account_id)            │   │
    │  │ → Field element for Merkle tree                   │   │
    │  └───────────────────────────────────────────────────┘   │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 2: REQUEST MERKLE PATH (Client → Server)             ║
    ║  🔒 TRUE ZERO-KNOWLEDGE: Uses tree_index, NOT credentials  ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
                                 ▼
         POST /api/get-merkle-path {tree_index: 42}
                                 │
                                 │ HTTPS/TLS 1.3
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          SERVER (Rust/Axum)                             │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ 1. Get Merkle path by position (2^20 capacity)                   │   │
│  │    → Input: tree_index = 42 (just a number!)                     │   │
│  │    → Extract authentication path (20 siblings)                   │   │
│  │    → Server CANNOT identify which user (TRUE ZK!)                │   │
│  │                                                                  │   │
│  │ 2. Generate random challenge                                     │   │
│  │    → challenge = random_bytes(32)                                │   │
│  │    → Store in Redis with 5-minute TTL                            │   │
│  │    → Key: challenge_id → Value: challenge                        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 │
                                 ▼
         Response: {
           merkle_path: [sibling_0, ..., sibling_19],
           merkle_root: root_hash,
           challenge: random_32_bytes,
           position: 42
         }
                                 │
                                 │ HTTPS/TLS 1.3
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          CLIENT (Browser/WASM)                          │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 3: WEBAUTHN KEY GENERATION (Hardware-Bound)          ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
    ┌──────────────────────────────────────────────────────────┐
    │  Trigger WebAuthn API (Level 2)                          │
    │                                                          │
    │  navigator.credentials.create({                          │
    │    publicKey: {                                          │
    │      challenge: server_challenge,                        │
    │      rp: {name: "Legion ZK Auth"},                       │
    │      user: {id: username_hash, name: "anonymous"},       │
    │      pubKeyCredParams: [{alg: -7, type: "public-key"}],  │
    │      authenticatorSelection: {                           │
    │        authenticatorAttachment: "platform",              │
    │        userVerification: "required"                      │
    │      }                                                   │
    │    }                                                     │
    │  })                                                      │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ Hardware Security Module (TPM/Secure Enclave)     │   │
    │  │ ──────────────────────────────────────────────    │   │
    │  │ • User gesture required (touch/biometric)         │   │
    │  │ • Generate/retrieve ECDSA P-256 key pair          │   │
    │  │ • Private key NEVER leaves hardware               │   │
    │  │ • Returns: device_pubkey (33 bytes compressed)    │   │
    │  │ • Attestation: Proves genuine hardware            │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  Output: device_pubkey = 0x02... (33 bytes)              │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 4: NULLIFIER COMPUTATION (Replay Protection)         ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
    ┌──────────────────────────────────────────────────────────┐
    │  Compute nullifier (unique per auth attempt)             │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ nullifier = Poseidon(credential_hash || challenge)│   │
    │  │                                                   │   │
    │  │ Why Poseidon?                                     │   │
    │  │ • ZK-friendly hash (efficient in circuits)        │   │
    │  │ • 128-bit security                                │   │
    │  │ • Deterministic (same inputs → same output)       │   │
    │  │                                                   │   │
    │  │ Properties:                                       │   │
    │  │ ✓ Unique per challenge (prevents replay)          │   │
    │  │ ✓ Binds credential to this auth session           │   │
    │  │ ✓ Cannot be reversed to get credentials           │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  Check: Has this nullifier been used before?             │
    │  → Query server's nullifier database                     │
    │  → If exists: ABORT (replay attack detected)             │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 5: LINKABILITY TAG (Session Binding)                 ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
    ┌──────────────────────────────────────────────────────────┐
    │  Compute linkability tag (prevents session theft)        │
    │                                                          │
    │  ┌────────────────────────────────────────────────────┐  │
    │  │ linkability_tag = Blake3(device_pubkey ||          │  │
    │  │                          nullifier)                │  │
    │  │                                                    │  │
    │  │ Critical Security Property:                        │  │
    │  │ ═══════════════════════════                        │  │
    │  │ • Binds session to SPECIFIC device + user          │  │
    │  │ • Attacker cannot steal session token because:     │  │
    │  │   → They don't have device_pubkey (in hardware)    │  │
    │  │   → Cannot recompute linkability_tag               │  │
    │  │   → Server rejects mismatched tags                 │  │
    │  │                                                    │  │
    │  │ • Maintains zero-knowledge:                        │  │
    │  │   → Server sees tag but not identity               │  │
    │  │   → Same tag for entire session (linkable)         │  │
    │  │   → Different tag per auth (unlinkable across)     │  │
    │  └────────────────────────────────────────────────────┘  │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 6: ZK PROOF GENERATION (Halo2 PLONK Circuit)         ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
    ┌──────────────────────────────────────────────────────────┐
    │  Generate zero-knowledge proof (~4 minutes for k=16)     │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ CIRCUIT INPUTS (Private Witnesses)                │   │
    │  │ ══════════════════════════════════                │   │
    │  │ • credential_hash (64 bytes) - PRIVATE            │   │
    │  │ • merkle_path (20 siblings) - PRIVATE             │   │
    │  │ • leaf_index (position in tree) - PRIVATE         │   │
    │  │ • device_pubkey (33 bytes) - PRIVATE              │   │
    │  │ • device_path (10 siblings) - PRIVATE             │   │
    │  │ • device_index - PRIVATE                          │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ CIRCUIT OUTPUTS (Public Inputs)                   │   │
    │  │ ════════════════════════════════                  │   │
    │  │ • merkle_root (user tree) - PUBLIC                │   │
    │  │ • device_merkle_root - PUBLIC                     │   │
    │  │ • nullifier - PUBLIC                              │   │
    │  │ • challenge - PUBLIC                              │   │
    │  │ • timestamp - PUBLIC                              │   │
    │  └───────────────────────────────────────────────────┘   │
    │                                                          │
    │  ┌───────────────────────────────────────────────────┐   │
    │  │ CIRCUIT CONSTRAINTS (What We Prove)               │   │
    │  │ ════════════════════════════════════              │   │
    │  │                                                   │   │
    │  │ 1. Merkle Tree Membership (User Anonymity)        │   │
    │  │    ✓ credential_hash is leaf in tree              │  │
    │  │    ✓ Path verification: leaf → root               │  │
    │  │    ✓ Root matches public merkle_root              │  │
    │  │    ✗ Leaf position HIDDEN (1 of 2^20)             │  │
    │  │                                                   │   │
    │  │ 2. Device Tree Membership (Device Anonymity)      │   │
    │  │    ✓ device_pubkey is leaf in device tree         │  │
    │  │    ✓ Path verification: device → root             │  │
    │  │    ✓ Root matches public device_merkle_root       │  │
    │  │    ✗ Device position HIDDEN (1 of 2^10)           │  │
    │  │                                                   │  │
    │  │ 3. Nullifier Correctness                          │  │
    │  │    ✓ nullifier = Poseidon(credential_hash ||      │  │
    │  │                           challenge)              │  │
    │  │    ✓ Binds proof to specific challenge            │  │
    │  │                                                   │  │
    │  │ 4. Credential Hash Integrity                      │  │
    │  │    ✓ credential_hash properly formatted           │  │
    │  │    ✓ Matches stored hash in Merkle tree           │  │
    │  │                                                   │  │
    │  │ 5. Timestamp Freshness                            │  │
    │  │    ✓ timestamp = current_time (Unix epoch)        │  │
    │  │    ✓ Prevents old proof replay                    │  │
    │  └───────────────────────────────────────────────────┘  │
    │                                                         │
    │  ┌───────────────────────────────────────────────────┐  │
    │  │ PROOF OUTPUT (Halo2 PLONK)                        │  │
    │  │ ══════════════════════════                        │  │
    │  │ • Proof size: ~3.5 KB (k=16)                      │  │
    │  │ • Generation time: ~4 minutes                     │  │
    │  │ • Verification time: ~10ms                        │  │
    │  │ • Security: 2^-128 soundness error                │  │
    │  │ • No trusted setup required                       │  │
    │  └───────────────────────────────────────────────────┘  │
    └──────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 7: PROOF SUBMISSION (Client → Server)                ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
                                 ▼
         POST /auth/verify {
           proof: bytes,
           public_inputs: {
             merkle_root,
             device_merkle_root,
             nullifier,
             challenge,
             timestamp
           },
           linkability_tag: bytes
         }
                                 │
                                 │ HTTPS/TLS 1.3
                                 │
┌────────────────────────────────▼───────────────────────────────────────┐
│                          SERVER (Rust/Axum)                            │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ VERIFICATION STEPS (All Must Pass)                               │  │
│  │ ═════════════════════════════════════                            │  │
│  │                                                                  │  │
│  │ 1. Device Revocation Check (NEW v1.1.0)                          │  │
│  │    ✓ Check if device_commitment is revoked                       │  │
│  │    ✗ If YES: REJECT (stolen device blocked)                      │  │
│  │    ✓ If NO: Continue verification                                │  │
│  │                                                                  │  │
│  │ 2. Timestamp Validation                                          │  │
│  │    ✓ |proof_timestamp - server_time| < 10 minutes                │  │
│  │    ✗ Reject if too old (replay protection)                       │  │
│  │                                                                  │  │
│  │ 3. Challenge Verification                                        │  │
│  │    ✓ Lookup challenge in Redis                                   │  │
│  │    ✓ Verify challenge matches proof's public input               │  │
│  │    ✓ Delete challenge (one-time use)                             │  │
│  │    ✗ Reject if challenge not found or mismatched                 │  │
│  │                                                                  │  │
│  │ 4. Rate Limiting (NEW v1.1.0)                                    │  │
│  │    ✓ Check attempts for this nullifier                           │  │
│  │    ✓ Increment counter in Redis                                  │  │
│  │    ✗ If > 5 attempts/hour: REJECT (brute force protection)       │  │
│  │                                                                  │  │
│  │ 5. Nullifier Check (Replay Protection)                           │  │
│  │    ✓ Query RocksDB: Has nullifier been used?                     │  │
│  │    ✗ If YES: REJECT (replay attack)                              │  │
│  │    ✓ If NO: Continue verification                                │  │
│  │                                                                  │  │
│  │ 6. Merkle Root Validation                                        │  │
│  │    ✓ Verify merkle_root matches current tree root                │  │
│  │    ✓ Verify device_merkle_root matches user's device tree        │  │
│  │    ✗ Reject if roots don't match                                 │  │
│  │                                                                  │  │
│  │ 7. ZK Proof Verification (Halo2)                                 │  │
│  │    ✓ Verify proof against public inputs                          │  │
│  │    ✓ Check all circuit constraints satisfied                     │  │
│  │    ✓ Verification time: ~10ms                                    │  │
│  │    ✗ Reject if proof invalid                                     │  │
│  │                                                                  │  │
│  │ 8. Mark Nullifier as Used                                        │  │
│  │    ✓ Store nullifier in RocksDB (permanent)                      │  │
│  │    ✓ Cache in Redis (fast lookup)                                │  │
│  │    ✓ Prevents future replay of this proof                        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ SESSION TOKEN GENERATION                                         │  │
│  │ ═══════════════════════                                          │  │
│  │                                                                  │  │
│  │ session_token = Poseidon(nullifier ||                            │  │
│  │                          timestamp ||                            │  │
│  │                          linkability_tag)                        │  │
│  │                                                                  │  │
│  │ Store in Redis:                                                  │  │
│  │   Key: session_token                                             │  │
│  │   Value: linkability_tag                                         │  │
│  │   TTL: 1 hour (sliding window)                                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                                 │
                                 ▼
         Response: {
           session_token: bytes,
           expires_at: timestamp
         }
                                 │
                                 │ HTTPS/TLS 1.3
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          CLIENT (Browser/WASM)                          │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ Store session credentials:                                       │   │
│  │ • session_token → localStorage                                   │   │
│  │ • linkability_tag → memory (recompute from device_pubkey)        │   │
│  │ • expires_at → localStorage                                      │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 │
    ╔════════════════════════════════════════════════════════════╗
    ║  STEP 8: SESSION VALIDATION (Every Subsequent Request)    ║
    ╚════════════════════════════════════════════════════════════╝
                                 │
                                 ▼
         POST /auth/session {
           session_token,
           linkability_tag
         }
                                 │
                                 │ HTTPS/TLS 1.3
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          SERVER (Rust/Axum)                             │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │ SESSION VALIDATION (Fast - No ZK Proof)                          │   │
│  │ ═══════════════════════════════════════                          │   │
│  │                                                                  │   │
│  │ 1. Lookup session in Redis                                       │   │
│  │    ✓ Key: session_token                                          │   │
│  │    ✓ Get stored_linkability_tag                                  │   │
│  │    ✗ If not found: Session expired/invalid                       │   │
│  │                                                                  │   │
│  │ 2. Verify Linkability Tag                                        │   │
│  │    ✓ Compare: stored_tag == provided_tag                         │   │
│  │    ✗ If mismatch: SESSION THEFT DETECTED                         │   │
│  │       → Attacker has token but not device key                    │   │
│  │       → Cannot recompute correct linkability_tag                 │   │
│  │       → REJECT request                                           │   │ 
│  │                                                                  │   │
│  │ 3. Check Expiration                                              │   │
│  │    ✓ Verify current_time < expires_at                            │   │
│  │    ✓ Extend TTL (sliding window)                                 │   │
│  │                                                                  │   │
│  │ 4. Return Success                                                │   │
│  │    ✓ User authenticated (anonymously)                            │   │
│  │    ✓ Server knows: "valid user" but NOT which user               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
         Response: {
           valid: true,
           user_anonymous: true
         }
                                 │
                                 │
┌────────────────────────────────▼────────────────────────────────────────┐
│                          CLIENT (Browser/WASM)                          │
│                                                                         │
│  ✅ Authenticated! User can now access protected resources              │
│  🔒 Server knows user is valid but NOT their identity                   │
│  🛡️ Session bound to device (cannot be stolen)                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Properties Explained

### 1. User Anonymity (1 of 2^20)
```
Server's View:
┌─────────────────────────────────────────────────────────────┐
│ Merkle Tree (1,048,576 users)                               │
│                                                             │
│     Root: 0xabc123...                                       │
│      /              \                                       │
│    ...              ...                                     │
│   /   \            /   \                                    │
│  ?     ?          ?     ?     ← Server sees tree structure  │
│                                                             │
│ ✓ Proof shows: "One of these leaves is valid"               │
│ ✗ Proof hides: "Which specific leaf"                        │
│                                                             │
│ Result: Server cannot determine which user authenticated    │
└─────────────────────────────────────────────────────────────┘
```

### 2. Device Anonymity (1 of 2^10)
```
Per-User Device Tree:
┌─────────────────────────────────────────────────────────────┐
│ Device Tree (1,024 devices per user)                        │
│                                                             │
│     Device Root: 0xdef456...                                │
│      /                    \                                 │
│    ...                    ...                               │
│   /   \                  /   \                              │
│  ?     ?                ?     ?     ← Devices hidden        │
│                                                             │
│ ✓ Proof shows: "One of user's devices is valid"             │
│ ✗ Proof hides: "Which specific device"                      │
│                                                             │
│ Result: Server cannot link sessions to specific devices     │
└─────────────────────────────────────────────────────────────┘
```

### 3. Nullifier-Based Replay Protection
```
Timeline:
┌─────────────────────────────────────────────────────────────┐
│ Auth Attempt 1:                                             │
│   challenge_1 → nullifier_1 → ✅ Accepted (first use)       │
│   Server stores: nullifier_1 in RocksDB                     │
│                                                             │
│ Auth Attempt 2 (replay attack):                             │
│   challenge_1 → nullifier_1 → ❌ REJECTED (already used)    │
│   Server checks: nullifier_1 exists → replay detected       │
│                                                             │
│ Auth Attempt 3 (legitimate):                                │
│   challenge_2 → nullifier_2 → ✅ Accepted (new nullifier)   │
│   Server stores: nullifier_2 in RocksDB                     │
└─────────────────────────────────────────────────────────────┘
```

### 4. Linkability Tag Session Binding
```
Scenario: Attacker steals session_token
┌─────────────────────────────────────────────────────────────┐
│ Legitimate User:                                            │
│   device_pubkey (in TPM) → linkability_tag_A                │
│   session_token + linkability_tag_A → ✅ Valid              │
│                                                             │
│ Attacker (different device):                                │
│   Stolen: session_token                                     │
│   Missing: device_pubkey (locked in victim's TPM)           │
│   Computes: linkability_tag_B (wrong!)                      │
│   session_token + linkability_tag_B → ❌ REJECTED           │
│                                                             │
│ Server verification:                                        │
│   stored_tag (tag_A) ≠ provided_tag (tag_B)                 │
│   → Session theft detected → Request denied                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Performance Characteristics

| Operation | Time | Notes |
|-----------|------|-------|
| Credential Hashing | <1ms | Blake3 + BIP-39 (client-side) |
| WebAuthn Key Gen | ~1s | User gesture required |
| Nullifier Computation | <1ms | Poseidon hash |
| ZK Proof Generation | ~4min | k=16, client-side |
| Proof Submission | ~50ms | Network + processing |
| Proof Verification | ~10ms | Server-side (fast!) |
| Session Validation | <1ms | Redis lookup only |

---

## 🎯 Zero-Knowledge Guarantees

### What Server Learns ✅
- Someone in the anonymity set (1 of 1M users) authenticated
- Proof is cryptographically valid (2^-128 soundness)
- Same user+device for session (via linkability tag)
- Nullifier is unique (no replay)

### What Server CANNOT Learn ❌
- Which specific user (position in Merkle tree hidden)
- Which specific device (position in device tree hidden)
- Username or password (only hashes in circuit)
- Device private key (locked in hardware)
- Any linkage between sessions (different nullifiers)

---

## 🛡️ Attack Resistance

| Attack Type | Defense Mechanism | Result |
|-------------|-------------------|--------|
| Replay Attack | Nullifier tracking | ❌ Rejected |
| Session Theft | Linkability tag binding | ❌ Rejected |
| Brute Force | Rate limiting (5/hour) | ❌ Blocked (NEW v1.1.0) |
| Stolen Device | Device revocation API | ❌ Blocked (NEW v1.1.0) |
| Identity Leakage | tree_index (not credentials) | ❌ Prevented (NEW v1.1.0) |
| Credential Stuffing | BIP-39 entropy + rate limiting | ❌ Mitigated |
| Timing Attack | Constant-time circuit ops | ❌ No leakage |
| Proof Forgery | Halo2 soundness (2^-128) | ❌ Infeasible |
| Device Cloning | Hardware attestation | ❌ Detected |
| MitM Attack | TLS 1.3 + certificate pinning | ❌ Prevented |

---

**Built with ❤️ for privacy and security**
