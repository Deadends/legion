# Legion Storage Architecture

## Server-Side: RocksDB (Default)

**Location**: `prover/legion_data/rocksdb_merkle/`

**What it stores**:
- Merkle tree leaves (user credential hashes)
- Merkle tree nodes (intermediate hashes)
- Merkle root
- Leaf-to-index mappings
- Tree metadata

**Why RocksDB**:
- ✅ Production-grade (used by Ethereum, Bitcoin)
- ✅ Instant startup (no JSON parsing)
- ✅ Scales to millions of users
- ✅ Fast O(log n) lookups
- ✅ LZ4 compression
- ✅ Atomic batch writes
- ✅ ACID guarantees

**Performance**:
- Startup: <100ms (vs 5+ seconds for JSON)
- Lookup: <1ms
- Insert: <5ms
- Disk usage: ~50% smaller than JSON (compression)

---

## Client-Side: IndexedDB (Browser Cache)

**Location**: Browser's IndexedDB (`legion_zk_cache` database)

**What it stores**:
- Proving parameters per k-value
  - `params_k12` → ~2MB
  - `params_k14` → ~10MB
  - `params_k16` → ~40MB
  - `params_k18` → ~160MB

**Why IndexedDB**:
- ✅ Stores large binary data (params are 2-160MB)
- ✅ Persists across browser sessions
- ✅ Async API (non-blocking)
- ✅ Per-origin isolation (secure)
- ✅ Automatic garbage collection

**Performance Impact**:
- **First login** (no cache): 40-90 seconds (generate params + keys + proof)
- **Subsequent logins** (cached): 10-20 seconds (load params + generate keys + proof)
- **Savings**: 30-70 seconds per login after first time

**Cache Strategy**:
- Params are cached by k-value
- User can switch between k=12 (fast) and k=18 (secure)
- Each k-value is cached separately
- Cache survives browser restarts
- User can clear cache via browser settings

---

## Redis (Session & Nullifier Storage)

**What it stores**:
- Session tokens (after successful authentication)
- Nullifiers (prevent double-spending/replay attacks)
- Merkle root cache (optional, 1 hour TTL)

**Why Redis**:
- ✅ Fast in-memory lookups
- ✅ TTL support (auto-expiry)
- ✅ Distributed (can scale horizontally)
- ✅ Pub/sub for real-time updates

---

## Data Flow

### Registration:
1. Client hashes credentials → `user_leaf`
2. Client sends `user_leaf` to server
3. Server adds to RocksDB Merkle tree
4. RocksDB persists to disk

### Authentication (First Time):
1. Client generates params (40-90s) → stores in IndexedDB
2. Client generates keys from params (10-15s)
3. Client generates proof (5-30s)
4. Server verifies proof
5. Server stores nullifier in Redis
6. Server returns session token

### Authentication (Subsequent):
1. Client loads params from IndexedDB (instant)
2. Client generates keys from cached params (10-15s)
3. Client generates proof (5-30s)
4. Server verifies proof
5. Server stores nullifier in Redis
6. Server returns session token

---

## Storage Comparison

| Storage | Use Case | Size | Speed | Persistence |
|---------|----------|------|-------|-------------|
| **RocksDB** | Server Merkle tree | ~10MB for 100K users | <1ms reads | Permanent |
| **IndexedDB** | Client params cache | 2-160MB per k-value | Instant loads | Browser session |
| **Redis** | Sessions & nullifiers | ~1KB per session | <1ms | TTL-based |
| **LocalStorage** | Session pubkey | 64 bytes | Instant | Browser session |

---

## Migration from JSON

Old system used JSON files:
- `anonymity_tree.json` - Merkle tree (slow, doesn't scale)
- `challenges.json` - Challenges (not needed with ZK)

New system uses RocksDB:
- Instant startup
- Scales to millions
- Production-ready
- No manual file management

To migrate existing data:
```bash
# Old data is in legion_data/anonymity_tree.json
# RocksDB will be created at legion_data/rocksdb_merkle/
# First run will create empty RocksDB
# Re-register users to populate RocksDB
```

---

## Security Notes

**RocksDB**:
- Stores only hashed credentials (never plaintext)
- Merkle tree is public data (anonymity set)
- No sensitive data at rest

**IndexedDB**:
- Stores only proving parameters (public data)
- No credentials or private keys
- Per-origin isolation (can't be accessed by other sites)

**Redis**:
- Stores session tokens (random, time-limited)
- Stores nullifiers (hashed, prevents replay)
- No user identity information

**LocalStorage**:
- Stores only ephemeral public key
- Used for session binding
- Cleared on logout
