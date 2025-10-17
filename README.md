# Legion ZK Auth 🛡️

**True Zero-Knowledge Authentication with Hardware-Bound Device Ring Signatures**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Security](https://img.shields.io/badge/security-2%5E--128-green.svg)](SECURITY.md)

## 🎯 What is Legion?

Legion is a production-ready zero-knowledge authentication system that proves you're authorized **without revealing who you are**.

### Key Features

- ✅ **True Zero-Knowledge**: Server never learns your identity (1 of 1M users)
- ✅ **Device Anonymity**: Hardware-bound with ring signatures (1 of 1K devices)
- ✅ **No Trusted Setup**: Halo2 PLONK (transparent setup)
- ✅ **Hardware Security**: WebAuthn TPM/Secure Enclave binding
- ✅ **Replay Protection**: Nullifiers + timestamps
- ✅ **Session Security**: Linkability tags prevent theft
- ✅ **Production Ready**: Docker, systemd, monitoring included

## 🔒 Security Guarantees

| Property | Guarantee |
|----------|-----------|
| User Anonymity | 1 of 2^20 (1,048,576) |
| Device Anonymity | 1 of 2^10 (1,024) |
| Soundness Error | 2^-128 |
| Proof System | Halo2 PLONK |
| Password Hashing | Argon2id |
| Hardware Binding | WebAuthn Level 2 |

## 🚀 Quick Start (Local Demo)

```bash
# 1. Clone repository
git clone https://github.com/deadends/legion.git
cd legion

# 2. Install Redis (required for sessions)
# macOS: brew install redis && redis-server
# Ubuntu: sudo apt install redis && redis-server
# Windows: https://redis.io/docs/install/install-redis/install-redis-on-windows/

# 3. Run server (in one terminal)
cd legion-server
cargo run --release --features redis

# 4. Build and serve frontend (in another terminal)
cd wasm-client
wasm-pack build --target web --release
python3 -m http.server 8000

# 5. Open browser: http://localhost:8000
# Register → Authenticate → See zero-knowledge magic! ✨
```

**Expected**: Registration ~10s, Authentication ~4 minutes (k=16 proof generation)

**For production deployment**, see [DEPLOYMENT.md](DEPLOYMENT.md)

## 📊 Performance

| Security Level | k | Proof Time | Proof Size | Use Case |
|----------------|---|------------|------------|----------|
| Testing | 12 | ~10s | 2.5 KB | Development |
| Standard | 14 | ~60s | 3.0 KB | Staging |
| **Production** | **16** | **~4min** | **3.5 KB** | **Recommended** |
| High Security | 18 | ~15min | 4.0 KB | Enterprise |

## 🏗️ Architecture

```
┌─────────────┐                    ┌──────────────┐
│   Client    │                    │    Server    │
│  (Browser)  │                    │  (Verifier)  │
└──────┬──────┘                    └──────┬───────┘
       │                                  │
       │ 1. Hash credentials (Blake3)     │
       │    + Argon2id password           │
       │                                  │
       │ 2. Request Merkle path      ────►│
       │                             ◄────│ Path + Challenge
       │                                  │
       │ 3. Generate WebAuthn key         │
       │    (TPM/Secure Enclave)          │
       │                                  │
       │ 4. Compute linkability tag       │
       │    Blake3(device_pk || nullifier)│
       │                                  │
       │ 5. Generate ZK proof (Halo2)     │
       │    - User in Merkle tree         │
       │    - Device in device tree       │
       │    - Credential valid            │
       │    - Nullifier computed          │
       │                                  │
       │ 6. Submit proof             ────►│
       │                             ◄────│ Session token
       │                                  │
       │ 7. Verify session           ────►│
       │    (linkability tag binding) ◄───│ Welcome!
       │                                  │
```

## 🔐 Zero-Knowledge Properties

### What Server Knows
- ✅ Someone in anonymity set authenticated
- ✅ Proof is cryptographically valid
- ✅ Same user+device via linkability tag

### What Server CANNOT Know
- ❌ Which specific user (1 of 1M)
- ❌ Which specific device (1 of 1K)
- ❌ Username or password
- ❌ Device private key
- ❌ Merkle tree position

## 📦 Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed production deployment guide.

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

- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [Security Policy](SECURITY.md) - Security guarantees and reporting
- [API Documentation](docs/API.md) - REST API reference
- [Architecture](docs/ARCHITECTURE.md) - System design details

## 🛠️ Technology Stack

- **ZK Proofs**: Halo2 (PLONK)
- **Curves**: Pasta (Pallas/Vesta)
- **Hash**: Blake3, Poseidon
- **Password**: Argon2id
- **Hardware**: WebAuthn Level 2
- **Backend**: Rust, Axum, Redis, RocksDB
- **Frontend**: WASM, Vanilla JS

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## 🔒 Security

Found a security issue? See [SECURITY.md](SECURITY.md) for responsible disclosure.

**DO NOT** open public issues for vulnerabilities.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

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
