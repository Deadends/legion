# Legion ZK Auth 🛡️

**True Zero-Knowledge Authentication with Hardware-Bound Device Ring Signatures**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/security-2%5E--128-green.svg)](SECURITY.md)
[![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)](SECURITY_FIXES.md)

## 🎯 What is Legion?

Legion is a production-ready zero-knowledge authentication system that proves you're authorized **without revealing who you are**. 
You prove something based on public data without linking your current action back to your public address. 

### Key Features

- ✅ **True Zero-Knowledge**: Server never learns your identity (1 of 1M users)
- ✅ **Device Anonymity**: Hardware-bound with ring signatures (1 of 1K devices)
- ✅ **No Trusted Setup**: Halo2 PLONK (transparent setup)
- ✅ **Hardware Security**: WebAuthn TPM/Secure Enclave binding
- ✅ **Replay Protection**: Nullifiers + timestamps
- ✅ **Session Security**: Linkability tags prevent theft
- ✅ **Rate Limiting**: 5 attempts/hour (generic errors prevent enumeration)
- ✅ **Device Revocation**: Block stolen devices instantly
- ✅ **Production Ready**: Docker, systemd, monitoring included

## 🔒 Security Guarantees (v1.1.0)

| Property | Guarantee |
|----------|-----------|
| User Anonymity | 1 of 2^20 (1,048,576) |
| Device Anonymity | 1 of 2^10 (1,024) |
| Soundness Error | 2^-128 |
| Proof System | Halo2 PLONK |
| Password Hashing | Argon2id |
| Hardware Binding | WebAuthn Level 2 |
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

**Performance**: Registration ~10s, Authentication ~4min (k=16 proof generation)

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
| Testing | 12 | ~10s | 2.5 KB | Development |
| Standard | 14 | ~60s | 3.0 KB | Staging |
| **Production** | **16** | **~4min** | **3.5 KB** | **Recommended** |
| High Security | 18 | ~15min | 4.0 KB | Enterprise |

## 🏗️ Architecture

**📖 For detailed step-by-step authentication flow with cryptographic details, see [ARCHITECTURE_FLOW.md](docs/ARCHITECTURE_FLOW.md)**

### System Components

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            CLIENT (Browser)                              │
├──────────────────────────────────────────────────────────────────────────┤
│  ┌────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐   │
│  │  UI Layer      │  │  WASM Module    │  │  Hardware Security       │   │
│  │  (Vanilla JS)  │  │  (Rust→WASM)    │  │  (WebAuthn Level 2)      │   │
│  ├────────────────┤  ├─────────────────┤  ├──────────────────────────┤   │
│  │ • Registration │  │ • Blake3 Hash   │  │ • TPM 2.0                │   │
│  │ • Login Form   │  │ • Argon2id KDF  │  │ • Secure Enclave         │   │
│  │ • Session UI   │  │ • Halo2 Prover  │  │ • FIDO2 Authenticator    │   │
│  │ • Error Handle │  │ • Merkle Proof  │  │ • Device Private Key     │   │
│  └────────────────┘  └─────────────────┘  └──────────────────────────┘   │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ HTTPS/TLS 1.3
                                 │ (Encrypted Channel)
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         REVERSE PROXY (Nginx)                            │
├──────────────────────────────────────────────────────────────────────────┤
│  • TLS Termination          • Rate Limiting (100 req/min)                │
│  • Load Balancing           • Request Logging                            │
│  • Static File Serving      • Security Headers (CSP, HSTS)               │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ HTTP (Internal Network)
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    LEGION SERVER (Rust/Axum)                             │
├──────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                      API Layer (Axum)                           │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ POST /register        │ POST /auth/challenge │ POST /auth/verify│     │
│  │ POST /auth/session    │ GET  /health         │ POST /logout     │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                   Business Logic Layer                          │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ • Credential Manager    │ • Challenge Generator (32-byte random)│     │
│  │ • Merkle Tree Builder   │ • Nullifier Tracker (replay protection)│    │
│  │ • ZK Proof Verifier     │ • Session Manager (linkability tags)  │     │
│  │ • Device Tree Manager   │ • Timestamp Validator (±5min window)  │     │
│  └─────────────────────────────────────────────────────────────────┘     │
│                                   │                                      │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                   Cryptographic Layer                           │     │
│  ├─────────────────────────────────────────────────────────────────┤     │
│  │ • Halo2 Verifier (PLONK) │ • Poseidon Hash (ZK-friendly)        │     │
│  │ • Blake3 (credential hash)│ • Argon2id (password KDF)           │     │
│  │ • Merkle Tree (2^20 users)│ • Device Tree (2^10 devices/user)   │     │
│  └─────────────────────────────────────────────────────────────────┘     │
└────────────────────────┬──────────────────────┬──────────────────────────┘
                         │                      │
                         ▼                      ▼
        ┌────────────────────────┐  ┌───────────────────────────┐
        │   Redis (In-Memory)    │  │  RocksDB (Persistent)     │
        ├────────────────────────┤  ├───────────────────────────┤
        │ • Session Tokens       │  │ • User Credentials        │
        │ • Linkability Tags     │  │ • Merkle Tree Nodes       │
        │ • Active Challenges    │  │ • Device Trees            │
        │ • Nullifier Cache      │  │ • Nullifier History       │
        │ TTL: 1 hour            │  │ Persistent Storage        │
        └────────────────────────┘  └───────────────────────────┘
```

### Authentication Flow (Simplified)

```
┌─────────────┐                                                ┌──────────────┐
│   Client    │                                                │    Server    │
│  (Browser)  │                                                │  (Verifier)  │
└──────┬──────┘                                                └──────┬───────┘
       │                                                              │
       │ 1. Hash credentials (Blake3 + Argon2id)                      │
       │    credential_hash = Blake3(username) || Argon2id(password)  │
       │                                                              │
       │ 2. Request Merkle path + challenge (tree_index)         ────►│
       │    → Sends position number (e.g., 42), NOT credentials      │
       │    → Server cannot identify which user (TRUE ZERO-KNOWLEDGE)│
       │                                                         ◄────│ {merkle_path, challenge,
       │                                                              │  position}
       │                                                              │
       │ 3. Generate WebAuthn key (TPM/Secure Enclave)                │
       │    → device_pubkey (hardware-bound, ECDSA P-256)             │
       │    → User gesture required (touch/biometric)                 │
       │                                                              │
       │ 4. Compute nullifier (replay protection)                     │
       │    nullifier = Poseidon(credential_hash || challenge)        │
       │    → Check if nullifier already exists (abort if yes)        │
       │                                                              │
       │ 5. Compute linkability tag (session binding)                 │
       │    linkability_tag = Blake3(device_pubkey || nullifier)      │
       │    ⚠️  Binds session to specific device+user                 │        
       │                                                              │
       │ 6. Generate ZK proof (Halo2 PLONK, ~4min for k=16)           │
       │    Proves in zero-knowledge:                                 │
       │    ✓ User exists in Merkle tree (1 of 2^20)                  │
       │    ✓ Device exists in device tree (1 of 2^10)                │
       │    ✓ Credential hash is correct                              │
       │    ✓ Nullifier computed correctly                            │
       │    ✓ Challenge binding valid                                 │
       │    WITHOUT revealing which user or device                    │
       │                                                              │
       │ 7. Submit proof                                         ────►│
       │    {proof, public_inputs, linkability_tag}                   │
       │                                                              │ • Check device not revoked (NEW)
       │                                                              │ • Verify timestamp (±10min)
       │                                                              │ • Rate limit check (5/hour) (NEW)
       │                                                              │ • Check nullifier (replay?)
       │                                                              │ • Verify ZK proof (~10ms)
       │                                                              │ • Validate challenge
       │                                                              │ • Mark nullifier as used
       │                                                              │
       │                                                         ◄────│ {session_token, expires_at}
       │                                                              │
       │ 8. Verify session (every request)                       ────►│
       │    {session_token, linkability_tag}                          │
       │                                                              │ • Lookup in Redis
       │                                                              │ • Verify linkability_tag
       │                                                              │   (prevents session theft)
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

### What Server CANNOT Know
- ❌ Which specific user (1 of 1M)
- ❌ Which specific device (1 of 1K)
- ❌ Username or password
- ❌ Device private key
- ❌ Merkle tree position (uses tree_index for true ZK)

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

- **ZK Proofs**: Halo2 (PLONK)
- **Curves**: Pasta (Pallas/Vesta)
- **Hash**: Blake3, Poseidon
- **Password**: Argon2id
- **Hardware**: WebAuthn Level 2
- **Backend**: Rust, Axum, Redis, RocksDB
- **Frontend**: WASM, Vanilla JS

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

### v1.1.0 - Security Hardening (2024)

**Added**:
- ✅ True zero-knowledge authentication using `tree_index`
- ✅ Rate limiting (5 attempts/hour per credential)
- ✅ Device revocation API and enforcement
- ✅ Backward compatibility for old clients

**Security Fixes**:
- 🔒 Fixed identity leakage in challenge requests
- 🔒 Prevented brute force attacks with rate limiting
- 🔒 Enabled stolen device mitigation via revocation

**See [SECURITY_FIXES.md](SECURITY_FIXES.md) for complete details.**

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
