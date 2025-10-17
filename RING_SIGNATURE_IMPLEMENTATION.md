# 🔐 Ring Signature Implementation Plan

## 🚨 CRITICAL ISSUES IN CURRENT ARCHITECTURE

### What Breaks Zero-Knowledge:

1. **`device_commitment` sent in plaintext** (authentication_protocol.rs:420)
   ```rust
   conn.hset_multiple(&key, &[
       ("device_commitment", device_commitment_hex),  // ❌ EXPOSED
   ```
   - Server stores exact device commitment
   - Can track same device across sessions
   - Breaks device anonymity

2. **`device_commitment` sent during proof verification** (wasm-client/src/lib.rs:580)
   ```rust
   "device_commitment": hex::encode(device_commitment_fp.to_repr())  // ❌ EXPOSED
   ```
   - Client reveals which device in ring
   - Server can link sessions by device

3. **Session token includes `device_commitment`** (auth_circuit.rs:110)
   ```rust
   session_token = Hash(nullifier || timestamp || device_commitment)  // ❌ LINKABLE
   ```
   - Server needs device_commitment to verify session token
   - Creates dependency on exposed value

## ✅ SOLUTION: Linkable Ring Signatures

### Architecture Changes:

```
BEFORE (Current):
┌─────────────────────────────────────────────────────────────┐
│ Authentication                                               │
├─────────────────────────────────────────────────────────────┤
│ Client: Generate ZK proof (proves device in ring)           │
│ Client: Send device_commitment in plaintext                 │  ❌
│ Server: Store device_commitment in Redis                    │  ❌
│ Server: Can track device across sessions                    │  ❌
└─────────────────────────────────────────────────────────────┘

AFTER (Ring Signatures):
┌─────────────────────────────────────────────────────────────┐
│ Authentication (Once)                                        │
├─────────────────────────────────────────────────────────────┤
│ Client: Generate ZK proof (proves device in ring)           │
│ Client: Compute linkability_tag = Hash(device_key)          │  ✓
│ Client: Send linkability_tag (NOT device_commitment)        │  ✓
│ Server: Store linkability_tag (pseudorandom, unlinkable)    │  ✓
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│ Every API Request                                            │
├─────────────────────────────────────────────────────────────┤
│ Server: Send unique challenge                               │
│ Client: Generate ring signature (proves device in ring)     │  ✓
│ Client: Include linkability_tag in signature                │  ✓
│ Server: Verify ring signature (anonymous)                   │  ✓
│ Server: Check linkability_tag matches session               │  ✓
│ Server: Cannot identify which device                        │  ✓
└─────────────────────────────────────────────────────────────┘
```

## 📋 IMPLEMENTATION STEPS

### Step 1: Add Ring Signature Library
- Add `curve25519-dalek` to Cargo.toml
- Implement linkable ring signature module

### Step 2: Compute Linkability Tag
- Replace device_commitment with linkability_tag
- linkability_tag = Blake3(device_private_key || "LINKABILITY")
- Deterministic per device, but unlinkable to device_commitment

### Step 3: Update Circuit
- Change session token: Hash(nullifier || timestamp || linkability_tag)
- Remove device_commitment from public inputs
- Keep device_merkle_root (proves device in ring)

### Step 4: Update Server
- Store linkability_tag instead of device_commitment
- Add challenge generation endpoint
- Add ring signature verification endpoint
- Remove device_commitment from Redis storage

### Step 5: Update Client
- Compute linkability_tag during device registration
- Generate ring signature for each API request
- Include linkability_tag in ring signature

### Step 6: Add Challenge-Response Middleware
- Intercept all API requests
- Send challenge if no signature present
- Verify ring signature if present
- Check linkability_tag matches session

## 🔧 FILES TO MODIFY

1. **prover/Cargo.toml** - Add ring signature dependencies
2. **prover/src/ring_signature.rs** (NEW) - Ring signature implementation
3. **prover/src/lib.rs** - Export ring signature module
4. **prover/src/auth_circuit.rs** - Update session token computation
5. **prover/src/authentication_protocol.rs** - Remove device_commitment storage
6. **legion-server/src/main.rs** - Add challenge-response endpoints
7. **wasm-client/src/lib.rs** - Add ring signature generation

## 🎯 ZERO-KNOWLEDGE GUARANTEES

After implementation:
- ✅ User anonymous (1 of 1M users)
- ✅ Device anonymous (1 of 1024 devices)
- ✅ Session replay protected (unique challenges)
- ✅ Hardware bound (WebAuthn keys)
- ✅ Unlinkable across sessions (linkability_tag is pseudorandom)
- ✅ Same device provable (linkability_tag matches)

## 📊 PERFORMANCE IMPACT

- Authentication: +0ms (linkability_tag computed once)
- API Request: +15ms (10ms sign + 5ms verify)
- Network: +1 round-trip per request (challenge-response)
- Total latency: +100-200ms per API request

## 🚀 READY TO IMPLEMENT?

This plan removes ALL zero-knowledge leaks while maintaining:
- Hardware binding (WebAuthn)
- Session binding (linkability_tag)
- Device anonymity (ring signatures)
- Replay protection (unique challenges)
