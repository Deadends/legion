# Legion ZK Auth 🛡️

**True Zero-Knowledge Authentication with Hardware-Bound Device Ring Signatures**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/security-2%5E--128-green.svg)](SECURITY.md)
[![Version](https://img.shields.io/badge/version-1.3.0-blue.svg)](SECURITY_FIXES.md)

## 🎯 What is Legion?

Legion is a **passwordless zero-knowledge authentication system** that proves you're authorized **without revealing who you are**. 

Authenticate using only your **fingerprint + 24-word recovery phrase** (like MetaMask). No usernames, no passwords, no server-side secrets. 

### Key Features

- ✅ **Passwordless Authentication**: BIP-39 recovery phrase + fingerprint (no username/password)
- ✅ **True Zero-Knowledge**: Server never learns your identity (1 of 1M users)
- ✅ **Device Anonymity**: Hardware-bound with ring signatures (1 of 1K devices)
- ✅ **No Trusted Setup**: Halo2 PLONK (transparent setup)
- ✅ **Hardware Security**: WebAuthn TPM/Secure Enclave binding
- ✅ **Replay Protection**: Nullifiers + timestamps
- ✅ **Session Security**: Linkability tags prevent theft
- ✅ **Multi-Device Support**: Use same account on 2 devices (laptop + phone)
- ✅ **Rate Limiting**: 5 attempts/hour (generic errors prevent enumeration)
- ✅ **Device Revocation**: Block stolen devices instantly

## 🔒 Security Guarantees (v1.3.0)

| Property | Guarantee |
|----------|-----------|
| Authentication | Passwordless (BIP-39 + Fingerprint) |
| User Anonymity | 1 of 2^20 (1,048,576) |
| Device Anonymity | 1 of 2^10 (1,024) per user |
| Soundness Error | 2^-128 |
| Proof System | Halo2 PLONK (transparent setup) |
| Credential Derivation | Blake3 (BIP-39 seed) |
| Hardware Binding | WebAuthn Level 2 (TPM/Secure Enclave) |
| Multi-Device | Max 2 devices per account |
| Rate Limiting | 5 attempts/hour |
| Device Revocation | Instant blacklist |

## 🚀 Quick Start (One Command!)

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) (includes Docker Compose)

### Install & Run

```bash
# Clone and run
git clone https://github.com/deadends/legion.git
cd legion

# Linux/macOS
chmod +x install.sh && ./install.sh

# Windows
install.bat
```

**That's it!** Open http://localhost in your browser.

### What Gets Installed
- ✅ Redis (session storage)
- ✅ Legion Server (ZK proof verifier)
- ✅ Frontend (WASM client)
- ✅ Nginx (reverse proxy)

**Performance**: Registration ~5s, Authentication ~2min (k=14 proof generation)

---

### Manual Setup (Without Docker)

<details>
<summary>Click to expand manual installation</summary>

```bash
# 1. Install Redis
# macOS: brew install redis && redis-server
# Ubuntu: sudo apt install redis && redis-server
# Windows: https://redis.io/docs/install/install-redis/install-redis-on-windows/

# 2. Run server (terminal 1)
cd legion-server
cargo run --release --features redis

# 3. Build frontend (terminal 2)
cd wasm-client
wasm-pack build --target web --release
python3 -m http.server 8000

# 4. Open http://localhost:8000
```

</details>

---

**For production deployment**, see [DEPLOYMENT.md](docs/DEPLOYMENT.md)

## 📊 Performance

| Security Level | k | Proof Time | Proof Size | Use Case |
|----------------|---|------------|------------|----------|
| **Development** | **12** | **~30s** | **3.2 KB** | **Testing** |
| **Production** | **14** | **~2min** | **3.4 KB** | **Recommended** |

### Verification Benchmarks

**Test Hardware:** Lenovo IdeaPad 3 - Intel Core i3 11th Gen  
**Note:** Performance may vary based on hardware specifications.

#### k=12 (Development/Testing)

| Metric | Value | Notes |
|--------|-------|-------|
| **Proof Size** | 3,264 bytes | 3.19 KB compressed |
| **Public Inputs** | 10 | User tree root, device tree root, nullifier, etc. |
| **Params Generation** | 7.03s | One-time setup per k value |
| **Circuit Creation** | 2.3µs | Negligible overhead |
| **Verifying Key Gen** | 1.29s | One-time keygen |
| **Proof Verification** | 107.7ms | Actual ZK proof check |
| **Total Verification** | 8.43s | End-to-end (without caching) |

**Breakdown:**
- 🔥 **Cold start** (first verification): **~8.4s** (includes params + keygen + verification)
- ⚡ **Subsequent verifications** (with caching): **~108ms** (params/keygen cached)
- 💾 **Proof overhead**: **~326 bytes per public input**
- 🔐 **Circuit complexity**: User tree (20 levels) + Device tree (10 levels) + bindings

#### k=14 (Production - Recommended)

| Metric | Value | Notes |
|--------|-------|-------|
| **Proof Size** | 3,392 bytes | 3.31 KB compressed |
| **Public Inputs** | 10 | User tree root, device tree root, nullifier, etc. |
| **Params Generation** | 100.78s | One-time setup per k value |
| **Circuit Creation** | 5µs | Negligible overhead |
| **Verifying Key Gen** | 12.89s | One-time keygen |
| **Proof Verification** | 967.2ms | Actual ZK proof check |
| **Total Verification** | 114.65s | End-to-end (without caching) |

**Breakdown:**
- 🔥 **Cold start** (first verification): **~115s** (includes params + keygen + verification)
- ⚡ **Subsequent verifications** (with caching): **~967ms** (params/keygen cached)
- 💾 **Proof overhead**: **~339 bytes per public input**
- 🔐 **Circuit complexity**: User tree (20 levels) + Device tree (10 levels) + bindings

**Important:** Params generation and keygen are one-time costs that can be cached. Once cached, verification takes only ~108-967ms depending on k value. Current implementation does not cache params yet.

**Why slower than old benchmarks?** The passwordless circuit now verifies TWO Merkle trees (user + device) instead of one, providing true device-level anonymity (1-of-1024 devices per user).

## 🏗️ Architecture

**📖 For detailed step-by-step authentication flow with cryptographic details, see [ARCHITECTURE_FLOW.md](docs/ARCHITECTURE_FLOW.md)**

### System Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       CLIENT (Browser + WASM)                           │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐  │
│  │  UI Layer      │  │  WASM Prover    │  │  Local Storage           │  │
│  │  (Vanilla JS)  │  │  (Rust→WASM)    │  │  (IndexedDB)             │  │
│  ├────────────────┤  ├─────────────────┤  ├──────────────────────────┤  │
│  │ • Registration │  │ • Blake3 Hash   │  │ • Full Merkle Tree       │  │
│  │ • Login Form   │  │ • BIP-39 Derive │  │ • Device Trees           │  │
│  │ • Session UI   │  │ • Halo2 Prover  │  │ • WebAuthn Credentials   │  │
│  │ • Tree Sync    │  │ • Merkle Proof  │  │ • Tree Version Cache     │  │
│  └────────────────┘  │ • Ring Sigs     │  └──────────────────────────┘  │
│                      └─────────────────┘                                │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │              Hardware Security (WebAuthn Level 2)                │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │ • TPM 2.0 / Secure Enclave    • FIDO2 Authenticator              │   │
│  │ • Device Private Key (ECDSA)  • Biometric/Touch Required         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ HTTPS/TLS 1.3
                                 │ (Encrypted Channel)
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    LEGION SERVER (Rust/Axum)                             │
├──────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                      API Layer (Axum)                           │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ POST /api/register-blind          │ Blind registration          │     │
│  │ GET  /api/download-tree           │ Download full Merkle tree   │     │
│  │ POST /api/verify-anonymous-proof  │ Verify ZK proof             │     │
│  │ POST /api/verify-session          │ Session validation          │     │
│  │ POST /api/webauthn/*              │ WebAuthn endpoints          │     │
│  │ GET  /health                      │ Health check                │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                   Business Logic Layer                          │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ • Blind Registration    │ • Tree Synchronization                │     │
│  │ • ZK Proof Verifier     │ • Nullifier Tracker (replay)          │     │
│  │ • Session Manager       │ • Linkability Tag Validator           │     │
│  │ • WebAuthn Service      │ • Timestamp Validator (±10min)        │     │
│  │ • Device Revocation     │ • Rate Limiter (5/hour)               │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                   Cryptographic Layer                           │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ • Halo2 Verifier (PLONK) │ • Poseidon Hash (ZK-friendly)        │     │
│  │ • Blake3 (credential)    │ • BIP-39 (recovery phrase)           │     │
│  │ • Merkle Tree (2^20)     │ • Device Trees (2^10 per user)       │     │
│  │ • Ring Signature Verify  │ • WebAuthn Signature Verify          │     │
│  └─────────────────────────────────────────────────────────────────┘     │
└────────────────────────┬──────────────────────┬──────────────────────────┘
                         │                      │
                         ▼                      ▼
        ┌────────────────────────┐  ┌───────────────────────────┐
        │   Redis (In-Memory)    │  │  RocksDB (Persistent)     │
        ├────────────────────────┤  ├───────────────────────────┤
        │ • Session Tokens       │  │ • Merkle Tree Leaves      │
        │ • Linkability Tags     │  │ • Device Trees            │
        │ • Spent Nullifiers     │  │ • Nullifier History       │
        │ • Rate Limit Counters  │  │ • WebAuthn Credentials    │
        │ TTL: 1 hour            │  │ • Revoked Devices         │
        └────────────────────────┘  └───────────────────────────┘
```

### Authentication Flow (Simplified)

```
┌─────────────┐                                                ┌──────────────┐
│   Client    │                                                │    Server    │
│  (Browser)  │                                                │  (Verifier)  │
└──────┬──────┘                                                └──────┬───────┘
       │                                                              │
       │ 1. Generate 24-word recovery phrase (BIP-39)                 │
       │    → 256-bit entropy (like MetaMask)                         │
       │    → User writes down on paper                               │
       │                                                              │
       │ 2. Derive account_id from phrase (Blake3)                    │
       │    account_id = Blake3("LEGION_ACCOUNT_V2" || bip39_seed)    │
       │    → Deterministic, no server interaction                    │
       │                                                              │
       │ 3. Hash account_id for tree leaf (Poseidon)                  │
       │    credential_hash = Poseidon(account_id)                    │
       │                                                              │
       │ 4. Blind registration (TRUE zero-knowledge)             ────►│
       │    → Sends ONLY credential_hash (no phrase/identity)         │
       │    → Server adds to tree, returns tree_index                 │
       │                                                         ◄────│ {tree_index: 114}
       │                                                              │
       │ 5. Download full Merkle tree (one-time sync)            ────►│
       │    → Client stores entire tree in IndexedDB                  │
       │    → Enables TRUE zero-knowledge (no server queries)         │
       │                                                         ◄────│ {tree_data: [all leaves],
       │                                                              │  merkle_root, version}
       │                                                              │
       │ 6. Generate WebAuthn key (TPM/Secure Enclave)                │
       │    → Fingerprint prompt creates hardware-bound key           │
       │    → device_pubkey (ECDSA P-256, non-exportable)             │
       │    → Stored in TPM 2.0 / Secure Enclave                      │
       │                                                              │
       │ 7. Register device in device tree                       ────►│
       │    → device_commitment = Blake3(credential_id)               │
       │    → Server converts to valid field element if needed        │
       │    → Server adds to user's device tree (1 of 1024 slots)     │
       │                                                         ◄────│ {device_position: 0,
       │                                                              │  device_tree_root}
       │                                                              │
       │ 8. LOGIN: Touch fingerprint to authenticate                  │
       │    → WebAuthn verifies hardware-bound key                    │
       │    → Decrypts recovery phrase from local storage             │
       │    → Re-derives account_id from phrase                       │
       │                                                              │
       │ 9. Fetch device Merkle proof                            ────►│
       │    → Sends account_id (derived from phrase)                  │
       │    → Server returns device tree path                         │
       │                                                         ◄────│ {device_path: [siblings],
       │                                                              │  device_root}
       │                                                              │
       │ 10. Compute user Merkle proof CLIENT-SIDE                    │
       │    → Uses local tree from IndexedDB                          │
       │    → Computes path for tree_index                            │
       │    → Server NEVER learns which user!                         │
       │                                                              │
       │ 11. Compute nullifier (replay protection)                    │
       │    nullifier = Poseidon(account_id || challenge)             │
       │    → ONE-TIME USE: Different every login                     │
       │    → Prevents proof replay attacks                           │
       │                                                              │
       │ 12. Compute linkability tag (session binding)                │
       │    linkability_tag = Blake3(device_pubkey || nullifier)      │
       │    ⚠️  Binds session to specific device+user                 │        
       │                                                              │
       │ 13. Generate ZK proof (Halo2 PLONK, ~2min for k=14)          │
       │    Proves in zero-knowledge:                                 │
       │    ✓ User exists in Merkle tree (1 of 2^20)                  │
       │    ✓ Device exists in device tree (1 of 2^10)                │
       │    ✓ account_id hashes to credential_hash                    │
       │    ✓ Nullifier computed correctly                            │
       │    ✓ Timestamp is fresh                                      │
       │    WITHOUT revealing which user or device                    │
       │                                                              │
       │ 14. Submit proof                                        ────►│
       │    {proof, public_inputs, linkability_tag, k=14}             │
       │                                                              │ • Check device not revoked
       │                                                              │ • Verify timestamp (±10min)
       │                                                              │ • Rate limit check (5/hour)
       │                                                              │ • Check nullifier (replay?)
       │                                                              │ • Verify ZK proof (~115s)
       │                                                              │ • Mark nullifier as used
       │                                                              │
       │                                                         ◄────│ {session_token, expires_at}
       │                                                              │
       │ 15. Verify session (every request)                      ────►│
       │    {session_token, linkability_tag}                          │
       │                                                              │ • Lookup in Redis
       │                                                              │ • Verify linkability_tag
       │                                                              │   (prevents session theft)
       │                                                              │ • Check not spent
       │                                                         ◄────│ {valid: true}
       │                                                              │
```

**🔍 Want more details?** See [ARCHITECTURE_FLOW.md](docs/ARCHITECTURE_FLOW.md) for:
- Step-by-step cryptographic operations
- Circuit constraint details
- Security property explanations
- Attack resistance mechanisms

### Session Security Deep Dive

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SESSION SECURITY MECHANISMS                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  1. LINKABILITY TAG (Zero-Knowledge Device Binding)                     │
│  ═══════════════════════════════════════════════════════                │
│                                                                         │
│     linkability_tag = Blake3(device_pubkey || nullifier)                │
│                                                                         │
│     • Computed client-side using hardware-bound device key              │
│     • Sent with every session validation request                        │
│     • Server verifies: stored_tag == provided_tag                       │
│                                                                         │
│     ✅ PREVENTS: Session token theft/replay on different device        │
│     ✅ ENSURES: Same user + same device for entire session             │
│     ✅ MAINTAINS: Zero-knowledge (server doesn't learn identity)       │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────      │
│                                                                         │
│  2. SESSION TOKEN (Cryptographic Binding)                               │
│  ═══════════════════════════════════════════════════════                │
│                                                                         │
│     session_token = Poseidon(nullifier || timestamp || linkability_tag) │
│                                                                         │
│     • Generated server-side after proof verification                    │
│     • Stored in Redis with linkability_tag as value                     │
│     • Cannot be forged without knowing nullifier                        │
│                                                                         │
│     ✅ PREVENTS: Token forgery                                         │
│     ✅ ENSURES: Cryptographic binding to proof                         │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────      │
│                                                                         │
│  3. NULLIFIER (Replay Protection)                                       │
│  ═══════════════════════════════════════════════════════                │
│                                                                         │
│     nullifier = Poseidon(credential_hash || challenge)                  │
│                                                                         │
│     • Unique per authentication attempt                                 │
│     • Tracked in RocksDB (permanent) and Redis (cache)                  │
│     • Server rejects if nullifier seen before                           │
│                                                                         │
│     ✅ PREVENTS: Proof replay attacks                                  │
│     ✅ ENSURES: One-time use per challenge                             │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────      │
│                                                                         │
│  4. TIMESTAMP VALIDATION (Time-Bound Security)                          │
│  ═══════════════════════════════════════════════════════                │
│                                                                         │
│     • Proof includes timestamp (Unix epoch)                             │
│     • Server validates: |proof_time - server_time| < 5 minutes          │
│     • Session TTL: 1 hour (sliding window)                              │
│                                                                         │
│     ✅ PREVENTS: Old proof replay                                      │
│     ✅ ENSURES: Fresh authentication                                   │
│                                                                         │
│  ─────────────────────────────────────────────────────────────────      │
│                                                                         │
│  5. CHALLENGE-RESPONSE (Freshness Guarantee)                            │
│  ═══════════════════════════════════════════════════════                │
│                                                                         │
│     • Server generates random 32-byte challenge                         │
│     • Stored in Redis with 5-minute TTL                                 │
│     • Client must include in proof                                      │
│     • Server verifies challenge matches and deletes                     │
│                                                                         │
│     ✅ PREVENTS: Pre-computed proof attacks                             │
│     ✅ ENSURES: Proof generated for this specific session               │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

## 🔐 Zero-Knowledge Properties

### What Server Knows
- ✅ Someone in anonymity set authenticated
- ✅ Proof is cryptographically valid
- ✅ Same user+device via linkability tag
- ✅ Rate limit status (attempts remaining)
- ✅ Device revocation status
- ✅ Total number of registered users
- ✅ Merkle tree root (public)

### What Server CANNOT Know
- ❌ Which specific user (1 of 1M)
- ❌ Which specific device (1 of 1K per user)
- ❌ Recovery phrase (BIP-39 seed)
- ❌ account_id (derived from phrase)
- ❌ Device private key (in TPM/Secure Enclave)
- ❌ Which tree leaf belongs to which user
- ❌ User Merkle path (computed client-side)
- ❌ User's tree_index position

## 📦 Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed production deployment guide.

### Quick Deploy with Docker

```bash
# Production build
docker-compose -f docker-compose.yml up -d

# Check logs
docker-compose logs -f legion-server

# Check health
curl http://localhost/health
```

### Environment Variables

```env
RUST_LOG=info
LEGION_DATA_PATH=/var/lib/legion/data
REDIS_URL=redis://127.0.0.1:6379
```

## 🧪 Testing

```bash
# Run all tests
cargo test --workspace

# Run with Redis features
cargo test --workspace --features redis

# Benchmark
cargo bench
```

## 📚 Documentation

- [Architecture Flow](docs/ARCHITECTURE_FLOW.md) - Detailed authentication flow
- [Security Fixes](SECURITY_FIXES.md) - v1.1.0 security improvements
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment
- [Security Policy](docs/SECURITY.md) - Security guarantees and reporting
- [Contributing](docs/CONTRIBUTING.md) - Contribution guidelines

## 🛠️ Technology Stack

- **ZK Proofs**: Halo2 (PLONK) - Transparent setup, no trusted ceremony
- **Curves**: Pasta (Pallas/Vesta) - Cycle of curves for recursion
- **Hash**: Blake3 (credential derivation), Poseidon (ZK-friendly)
- **Key Derivation**: BIP-39 (24-word mnemonic)
- **Hardware**: WebAuthn Level 2 (TPM 2.0, Secure Enclave)
- **Backend**: Rust, Axum, Redis (sessions), RocksDB (persistence)
- **Frontend**: Rust→WASM (prover), Vanilla JS (UI), IndexedDB (storage)
- **Deployment**: Docker, Nginx, systemd

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](docs/CONTRIBUTING.md) first.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 🔒 Security

Found a security issue? See [SECURITY.md](docs/SECURITY.md) for responsible disclosure.

**DO NOT** open public issues for vulnerabilities.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🔄 Changelog

### v1.3.0 - Passwordless Authentication (2024)

**Major Changes**:
- ✅ **Passwordless authentication** - BIP-39 recovery phrase + fingerprint
- ✅ **Single-field circuit** - account_id derived from BIP-39 seed
- ✅ **Device ring signatures** - 1-of-1024 device anonymity per user
- ✅ **Multi-device support** - Use same account on 2 devices
- ✅ **Hardware-bound keys** - WebAuthn TPM/Secure Enclave integration
- ✅ **Blake3 field element handling** - Automatic conversion for device commitments

**Architecture**:
- 🏗️ No username/password - just recovery phrase + fingerprint
- 🏗️ Client-side account_id derivation (Blake3 + BIP-39)
- 🏗️ Device trees stored server-side (per-user isolation)
- 🏗️ Dual Merkle tree verification (user tree + device tree)
- 🏗️ Robust field element conversion (handles Blake3 outputs >= field modulus)

### v1.2.0 - Client-Side Proving Architecture (2024)

**Major Changes**:
- ✅ **Client-side Merkle tree storage** (IndexedDB) - TRUE zero-knowledge
- ✅ **Blind registration** - Server never sees credentials
- ✅ **Local proof generation** - All cryptography in WASM
- ✅ **Tree synchronization** - Download full tree once, compute paths locally
- ✅ **Spent nullifiers** - Single-use sessions prevent concurrent access

### v1.1.0 - Security Hardening (2024)

**Added**:
- ✅ Rate limiting (5 attempts/hour per credential)
- ✅ Device revocation API and enforcement
- ✅ Linkability tags for session theft prevention

**Security Fixes**:
- 🔒 Fixed identity leakage in challenge requests
- 🔒 Prevented brute force attacks with rate limiting
- 🔒 Enabled stolen device mitigation via revocation

---

## 🙏 Acknowledgments

- [Halo2](https://github.com/zcash/halo2) - ZK proof system
- [WebAuthn](https://www.w3.org/TR/webauthn-2/) - Hardware authentication
- [Blake3](https://github.com/BLAKE3-team/BLAKE3) - Fast hashing
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing

## 📞 Contact

- GitHub: [@deadends](https://github.com/deadends)
- Email: nantha.ponmudi@gmail.com
- Website: https://nantha.dev

---

**Built with ❤️ for privacy and security**
