# Legion WASM Client

Browser-based client for Legion Zero-Knowledge Authentication System.

## Quick Start

### 1. Build WASM Client

```powershell
.\build.ps1
```

### 2. Start Backend Services

```powershell
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Legion Web Server
cd ..\prover
cargo run --bin web_server --features redis
```

### 3. Start Web Server

```powershell
# Terminal 3: Serve WASM client
.\serve.ps1
```

### 4. Open Browser

Navigate to: http://localhost:8000

## Features

- **Register Tab**: Add users to the anonymity set
- **Login Tab**: Generate ZK proofs and authenticate
- **Security Levels**: Standard, Production, Quantum, Enterprise

## Architecture

```
Browser (WASM Client)
    ↓ HTTP POST
Legion Web Server (Rust)
    ↓
Authentication Protocol
    ↓
Redis (Params Cache + Nullifiers)
```

## API Endpoints

- `POST /register` - Register new user
- `POST /login` - Authenticate with ZK proof

## Notes

- First login takes 3 minutes (key generation)
- Subsequent logins use cached keys
- Proofs generated server-side for performance
