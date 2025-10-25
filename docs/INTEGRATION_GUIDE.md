# Integration Guide

## Overview

This guide provides step-by-step instructions for integrating Legion Zero-Knowledge Authentication into applications. Legion enables anonymous authentication while maintaining user data persistence and session management.

## Prerequisites

### System Requirements

- Redis server (for session management)
- Modern web browser with WebAssembly support
- HTTPS endpoint (required for WebAuthn)

### Dependencies

#### Server-Side (Rust)
```toml
[dependencies]
legion-server = "1.1.0"
redis = "0.23"
tokio = { version = "1.0", features = ["full"] }
```

#### Client-Side (JavaScript)
```json
{
  "dependencies": {
    "@legion/wasm-client": "^1.1.0"
  }
}
```

## Quick Start

### 1. Server Setup

Initialize Legion authentication server:

```rust
use legion_server::AuthenticationProtocol;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Legion protocol
    let protocol = AuthenticationProtocol::new()?;
    
    // Start HTTP server
    let app = create_routes(protocol);
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;
    
    Ok(())
}
```

### 2. Client Integration

Initialize WASM client for proof generation:

```javascript
import init, { LegionClient } from '@legion/wasm-client';

async function initializeLegion() {
    await init();
    return new LegionClient({
        serverUrl: 'https://your-legion-server.com'
    });
}
```

### 3. User Registration

Register users in the anonymity set:

```javascript
async function registerUser(username, password) {
    const client = await initializeLegion();
    
    // Generate credential hash client-side
    const credentials = await client.hashCredentials(username, password);
    
    // Register with server
    const response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            user_leaf_hex: credentials.leafHex
        })
    });
    
    const result = await response.json();
    
    // Store tree index locally (zero-knowledge)
    localStorage.setItem('legion_tree_index', result.data.tree_index);
    
    return result;
}
```

### 4. Authentication Flow

Implement zero-knowledge authentication:

```javascript
async function authenticate(username, password) {
    const client = await initializeLegion();
    const treeIndex = localStorage.getItem('legion_tree_index');
    
    // Get Merkle path from server
    const pathResponse = await fetch(`/api/merkle-path/${treeIndex}`);
    const pathData = await pathResponse.json();
    
    // Get authentication challenge
    const challengeResponse = await fetch('/api/challenge', { method: 'POST' });
    const challengeData = await challengeResponse.json();
    
    // Generate WebAuthn device key
    const deviceKey = await generateDeviceKey();
    
    // Generate zero-knowledge proof
    const proof = await client.generateProof({
        username,
        password,
        merklePath: pathData.data.merkle_path,
        merkleRoot: pathData.data.merkle_root,
        challenge: challengeData.data.challenge,
        deviceKey: deviceKey,
        treeIndex: parseInt(treeIndex)
    });
    
    // Submit proof for verification
    const authResponse = await fetch('/api/verify-proof', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proof)
    });
    
    const authResult = await authResponse.json();
    
    if (authResult.success) {
        // Store session credentials
        sessionStorage.setItem('session_token', authResult.data.session_token);
        sessionStorage.setItem('user_data_id', authResult.data.user_data_id);
        
        return {
            sessionToken: authResult.data.session_token,
            userDataId: authResult.data.user_data_id,
            expiresAt: authResult.data.expires_at
        };
    }
    
    throw new Error('Authentication failed');
}
```

## Advanced Integration

### Session Management

Implement session validation and renewal:

```javascript
class SessionManager {
    constructor() {
        this.sessionToken = sessionStorage.getItem('session_token');
        this.userDataId = sessionStorage.getItem('user_data_id');
    }
    
    async validateSession() {
        if (!this.sessionToken) return false;
        
        const response = await fetch('/api/session/validate', {
            headers: {
                'Authorization': `Bearer ${this.sessionToken}`
            }
        });
        
        const result = await response.json();
        return result.success && result.data.valid;
    }
    
    async makeAuthenticatedRequest(url, options = {}) {
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${this.sessionToken}`
        };
        
        return fetch(url, { ...options, headers });
    }
    
    logout() {
        sessionStorage.removeItem('session_token');
        sessionStorage.removeItem('user_data_id');
        this.sessionToken = null;
        this.userDataId = null;
    }
}
```

### User Data Persistence

Implement persistent user data storage:

```javascript
class UserDataManager {
    constructor(sessionManager) {
        this.sessionManager = sessionManager;
    }
    
    async saveUserData(dataType, content) {
        return this.sessionManager.makeAuthenticatedRequest('/api/user-data', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: this.sessionManager.userDataId,
                data_type: dataType,
                content: content
            })
        });
    }
    
    async getUserData(dataType) {
        const response = await this.sessionManager.makeAuthenticatedRequest(
            `/api/user-data/${this.sessionManager.userDataId}/${dataType}`
        );
        return response.json();
    }
    
    async deleteUserData(dataType) {
        return this.sessionManager.makeAuthenticatedRequest(
            `/api/user-data/${this.sessionManager.userDataId}/${dataType}`,
            { method: 'DELETE' }
        );
    }
}
```

### Device Management

Handle multiple devices per user:

```javascript
async function registerDevice() {
    const deviceKey = await generateDeviceKey();
    const nullifierHash = await computeNullifierHash();
    
    const response = await fetch('/api/device/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            nullifier_hash: nullifierHash,
            device_commitment_hex: deviceKey.commitmentHex
        })
    });
    
    const result = await response.json();
    
    // Store device information locally
    localStorage.setItem('device_position', result.data.device_position);
    localStorage.setItem('device_key', JSON.stringify(deviceKey));
    
    return result;
}

async function revokeDevice(deviceCommitment) {
    const nullifierHash = await computeNullifierHash();
    
    return fetch('/api/device/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            nullifier_hash: nullifierHash,
            device_commitment_hex: deviceCommitment
        })
    });
}
```

## Server-Side Implementation

### Route Handlers

Implement Legion API endpoints:

```rust
use axum::{extract::Path, http::StatusCode, response::Json, Extension};
use legion_server::AuthenticationProtocol;

async fn register_user(
    Extension(protocol): Extension<Arc<AuthenticationProtocol>>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    match protocol.register_blind_leaf(&payload.user_leaf_hex) {
        Ok(tree_index) => Ok(Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "tree_index": tree_index,
                "anonymity_set_size": protocol.get_anonymity_set_size()
            })),
            error: None,
        })),
        Err(e) => Err(StatusCode::BAD_REQUEST),
    }
}

async fn verify_proof(
    Extension(protocol): Extension<Arc<AuthenticationProtocol>>,
    Json(payload): Json<ProofRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    match protocol.verify_anonymous_proof(
        &payload.proof_hex,
        &payload.merkle_root_hex,
        &payload.nullifier_hex,
        &payload.challenge_hex,
        &payload.client_pubkey_hex,
        &payload.timestamp_hex,
        &payload.device_merkle_root_hex,
        &payload.session_token_hex,
        &payload.expiration_time_hex,
        &payload.linkability_tag_hex,
    ) {
        Ok((session_token, user_data_id)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(serde_json::json!({
                "session_token": session_token,
                "user_data_id": user_data_id,
                "expires_at": get_timestamp() + 3600
            })),
            error: None,
        })),
        Err(e) => Err(StatusCode::UNAUTHORIZED),
    }
}
```

### Middleware

Implement authentication middleware:

```rust
use axum::{extract::Request, middleware::Next, response::Response};

async fn auth_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));
    
    let session_token = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;
    
    // Validate session token with Redis
    if !validate_session_token(session_token).await? {
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    Ok(next.run(request).await)
}
```

## Error Handling

### Client-Side Error Handling

```javascript
class LegionError extends Error {
    constructor(code, message, details = null) {
        super(message);
        this.code = code;
        this.details = details;
    }
}

async function handleLegionResponse(response) {
    const data = await response.json();
    
    if (!data.success) {
        throw new LegionError(
            data.error_code || 'UNKNOWN_ERROR',
            data.error || 'An unknown error occurred',
            data.details
        );
    }
    
    return data;
}
```

### Server-Side Error Handling

```rust
#[derive(Debug, thiserror::Error)]
pub enum LegionError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Invalid proof: {0}")]
    InvalidProof(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Device revoked")]
    DeviceRevoked,
}

impl IntoResponse for LegionError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            LegionError::AuthenticationFailed(msg) => {
                (StatusCode::UNAUTHORIZED, "AUTH_001", msg)
            }
            LegionError::InvalidProof(msg) => {
                (StatusCode::BAD_REQUEST, "AUTH_002", msg)
            }
            LegionError::RateLimitExceeded => {
                (StatusCode::TOO_MANY_REQUESTS, "AUTH_003", "Rate limit exceeded".to_string())
            }
            LegionError::DeviceRevoked => {
                (StatusCode::FORBIDDEN, "AUTH_004", "Device has been revoked".to_string())
            }
        };
        
        let body = Json(serde_json::json!({
            "success": false,
            "error_code": error_code,
            "error": message
        }));
        
        (status, body).into_response()
    }
}
```

## Testing

### Unit Tests

```javascript
describe('Legion Integration', () => {
    let client;
    
    beforeEach(async () => {
        client = await initializeLegion();
    });
    
    test('should register user successfully', async () => {
        const result = await registerUser('testuser', 'testpass');
        expect(result.success).toBe(true);
        expect(result.data.tree_index).toBeGreaterThanOrEqual(0);
    });
    
    test('should authenticate user successfully', async () => {
        await registerUser('testuser', 'testpass');
        const auth = await authenticate('testuser', 'testpass');
        
        expect(auth.sessionToken).toBeDefined();
        expect(auth.userDataId).toBeDefined();
    });
});
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_authentication_flow() {
    let protocol = AuthenticationProtocol::new().unwrap();
    
    // Register user
    let tree_index = protocol.register_user(b"testuser", b"testpass").unwrap();
    
    // Generate proof (would be done client-side)
    let proof_data = generate_test_proof(&protocol, tree_index).await;
    
    // Verify proof
    let (session_token, user_data_id) = protocol
        .verify_anonymous_proof(
            &proof_data.proof_hex,
            &proof_data.merkle_root_hex,
            &proof_data.nullifier_hex,
            &proof_data.challenge_hex,
            &proof_data.client_pubkey_hex,
            &proof_data.timestamp_hex,
            &proof_data.device_merkle_root_hex,
            &proof_data.session_token_hex,
            &proof_data.expiration_time_hex,
            &proof_data.linkability_tag_hex,
        )
        .unwrap();
    
    assert!(!session_token.is_empty());
    assert!(!user_data_id.is_empty());
}
```

## Performance Optimization

### Client-Side Optimization

- Use Web Workers for proof generation to avoid blocking UI
- Implement proof caching for repeated authentications
- Optimize WASM module loading with preloading strategies

### Server-Side Optimization

- Implement connection pooling for Redis
- Use async/await patterns for non-blocking operations
- Cache Merkle tree computations for frequently accessed paths

## Production Deployment

### Security Checklist

- Enable HTTPS for all endpoints
- Configure proper CORS policies
- Implement rate limiting and DDoS protection
- Set up monitoring and alerting for authentication failures
- Regular security audits and penetration testing

### Scaling Considerations

- Horizontal scaling with load balancers
- Redis clustering for session management
- Database sharding for user data persistence
- CDN deployment for WASM client distribution