# API Reference

## Overview

This document provides comprehensive API reference for Legion Zero-Knowledge Authentication System. All endpoints maintain zero-knowledge properties while providing robust authentication and user management capabilities.

## Base Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `LEGION_DATA_PATH` | Data storage directory | `./legion_data` | No |
| `REDIS_URL` | Redis connection string | `redis://127.0.0.1:6379` | No |
| `RUST_LOG` | Logging level | `info` | No |

### Response Format

All API responses follow a consistent JSON structure:

```json
{
  "success": boolean,
  "data": object | null,
  "error": string | null,
  "timestamp": number
}
```

## Authentication Endpoints

### Register User

Registers a new user in the anonymity set.

**Endpoint:** `POST /api/register`

**Request Body:**
```json
{
  "user_leaf_hex": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "tree_index": 42,
    "anonymity_set_size": 1000
  }
}
```

**Parameters:**
- `user_leaf_hex`: Hex-encoded Poseidon hash of user credentials

### Get Merkle Path

Retrieves Merkle proof for zero-knowledge authentication.

**Endpoint:** `GET /api/merkle-path/{tree_index}`

**Response:**
```json
{
  "success": true,
  "data": {
    "merkle_path": ["hex_string", "hex_string", ...],
    "merkle_root": "hex_string"
  }
}
```

**Parameters:**
- `tree_index`: User's position in anonymity tree (0-based)

### Generate Challenge

Creates authentication challenge for proof generation.

**Endpoint:** `POST /api/challenge`

**Response:**
```json
{
  "success": true,
  "data": {
    "challenge": "hex_string",
    "expires_at": 1640995200
  }
}
```

### Verify Anonymous Proof

Verifies zero-knowledge proof and establishes authenticated session.

**Endpoint:** `POST /api/verify-proof`

**Request Body:**
```json
{
  "proof_hex": "string",
  "merkle_root_hex": "string",
  "nullifier_hex": "string",
  "challenge_hex": "string",
  "client_pubkey_hex": "string",
  "timestamp_hex": "string",
  "device_merkle_root_hex": "string",
  "session_token_hex": "string",
  "expiration_time_hex": "string",
  "linkability_tag_hex": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session_token": "hex_string",
    "user_data_id": "hex_string",
    "expires_at": 1640995200
  }
}
```

## Device Management

### Register Device

Registers a device for ring signature authentication.

**Endpoint:** `POST /api/device/register`

**Request Body:**
```json
{
  "nullifier_hash": "string",
  "device_commitment_hex": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "device_position": 5,
    "device_merkle_root": "hex_string"
  }
}
```

### Get Device Proof

Retrieves device Merkle proof for ring signature.

**Endpoint:** `GET /api/device/proof/{nullifier_hash}/{position}`

**Response:**
```json
{
  "success": true,
  "data": {
    "device_path": ["hex_string", "hex_string", ...],
    "device_root": "hex_string"
  }
}
```

### Revoke Device

Immediately revokes a compromised device.

**Endpoint:** `POST /api/device/revoke`

**Request Body:**
```json
{
  "nullifier_hash": "string",
  "device_commitment_hex": "string"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "revoked": true
  }
}
```

## Session Management

### Validate Session

Validates active session token.

**Endpoint:** `GET /api/session/validate`

**Headers:**
```
Authorization: Bearer {session_token}
X-Linkability-Tag: {linkability_tag}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "valid": true,
    "expires_at": 1640995200,
    "user_data_id": "hex_string"
  }
}
```

### Logout

Invalidates current session.

**Endpoint:** `POST /api/logout`

**Headers:**
```
Authorization: Bearer {session_token}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "logged_out": true
  }
}
```

## System Information

### Health Check

Returns system health status.

**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "anonymity_set_size": 1000,
    "uptime": 3600
  }
}
```

### Anonymity Set Info

Retrieves anonymity set metadata.

**Endpoint:** `GET /api/anonymity-set`

**Response:**
```json
{
  "success": true,
  "data": {
    "merkle_root": "hex_string",
    "tree_size": 1000,
    "depth": 20
  }
}
```

## Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| `AUTH_001` | Invalid proof | Regenerate proof with correct parameters |
| `AUTH_002` | Nullifier already used | Wait for next authentication window |
| `AUTH_003` | Rate limit exceeded | Reduce authentication frequency |
| `AUTH_004` | Device revoked | Use different device or contact administrator |
| `AUTH_005` | Session expired | Reauthenticate to obtain new session |
| `AUTH_006` | Invalid tree index | Verify registration status |
| `AUTH_007` | Timestamp out of range | Synchronize system clock |

## Rate Limiting

### Authentication Attempts

- Maximum 5 attempts per hour per credential
- Rate limiting based on nullifier hash
- Generic error responses prevent enumeration attacks

### API Requests

- 100 requests per minute per IP address
- Burst allowance of 20 requests
- Exponential backoff recommended for retries

## Security Headers

### Required Headers

```
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

### Recommended Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
```

## Client Libraries

### JavaScript/TypeScript

```javascript
import { LegionClient } from '@legion/client';

const client = new LegionClient({
  baseUrl: 'https://api.legion.example.com',
  timeout: 30000
});

const result = await client.authenticate(credentials);
```

### Rust

```rust
use legion_client::LegionClient;

let client = LegionClient::new("https://api.legion.example.com")?;
let result = client.verify_proof(proof_data).await?;
```

## WebAssembly Integration

### Client-Side Proving

```javascript
import init, { generate_proof } from './legion_wasm_client.js';

await init();
const proof = generate_proof(credentials, merkle_path, challenge);
```

### Performance Considerations

- Proof generation: 10 seconds (k=12) to 4 minutes (k=16)
- Memory usage: 2-8 GB during proof generation
- Recommend web workers for non-blocking operation