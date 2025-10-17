# Discord-Style Username System

## 🎯 Problem Solved

**Before:** Username "alice" must be unique → Registration fails if taken
**After:** Username "alice" can have 1,000,000 variants → alice#000000 to alice#999999

## 🔐 Security Benefits

### Attack Difficulty Comparison

**Without discriminator:**
```
Attacker knows: "alice"
Must test: 1 leaf
Time: 100ms (1 Argon2 attempt)
Result: EASY to find
```

**With 6-digit discriminator:**
```
Attacker knows: "alice"
Must test: 1,000,000 leaves (alice#000000 to alice#999999)
Time: 100,000 seconds = 27.7 hours
Result: MUCH HARDER
```

**With strong password:**
```
Even if attacker finds correct discriminator,
still needs to brute force password (infeasible)
```

## 📋 Implementation Flow

### Registration
```
1. User enters: "alice" + "password123"
2. Server generates: random 6-digit discriminator (#123456)
3. Server returns: "alice#123456"
4. Client computes: 
   - username_hash = Blake3("alice#123456")
   - password_hash = Blake3(Argon2("password123", "alice#123456"))
   - user_leaf = Poseidon(username_hash, password_hash)
5. Client sends: user_leaf to server
6. Server adds: leaf to Merkle tree
7. User saves: "alice#123456" (needed for login)
```

### Login
```
1. User enters: "alice#123456" + "password123"
2. Client downloads: Merkle tree
3. Client computes: same hashing as registration
4. Client finds: their leaf in tree
5. Client generates: ZK proof
6. Client sends: proof to server
7. Server verifies: proof and creates session
```

## 🎨 UX Design

### Registration Screen
```
┌─────────────────────────────────────┐
│  Register                            │
├─────────────────────────────────────┤
│  Username: [alice____________]       │
│  Password: [••••••••••••••••]       │
│                                      │
│  💡 You'll get a discriminator       │
│     like Discord (e.g., alice#123456)│
│                                      │
│  [Register] ────────────────────────►│
└─────────────────────────────────────┘

After registration:
┌─────────────────────────────────────┐
│  ✅ Registration Successful!         │
│                                      │
│  Your username: alice#123456         │
│                                      │
│  ⚠️ SAVE THIS!                       │
│  You need the full username          │
│  (with #123456) to login!            │
└─────────────────────────────────────┘
```

### Login Screen
```
┌─────────────────────────────────────┐
│  Login                               │
├─────────────────────────────────────┤
│  Full Username: [alice#123456__]    │
│  Password:      [••••••••••••••]    │
│                                      │
│  💡 Use your FULL username           │
│     with discriminator               │
│                                      │
│  [Login] ───────────────────────────►│
└─────────────────────────────────────┘
```

## 🔢 Discriminator Options

### 4-digit (Discord style)
```
Range: #0000 to #9999
Total: 10,000 variants per username
Brute force time: 16.7 minutes
Recommendation: Good for small apps
```

### 6-digit (Recommended)
```
Range: #000000 to #999999
Total: 1,000,000 variants per username
Brute force time: 27.7 hours
Recommendation: Good for production
```

### 8-digit (Maximum security)
```
Range: #00000000 to #99999999
Total: 100,000,000 variants per username
Brute force time: 115 days
Recommendation: Overkill for most cases
```

## 📊 Storage Impact

**Before:**
```
Username: "alice" (unique)
Storage: username → leaf mapping needed
Problem: Collision detection required
```

**After:**
```
Username: "alice#123456" (unique by design)
Storage: No mapping needed (leaf is self-contained)
Benefit: No collision detection, simpler code
```

## ✅ Benefits

1. **No username collisions** - 1M variants per base username
2. **Better privacy** - Attacker must guess discriminator
3. **Familiar UX** - Users understand Discord model
4. **Simpler code** - No collision detection needed
5. **Scalable** - Supports millions of users with same base name

## ⚠️ User Education

**Important messages:**
- "Save your full username (alice#123456) - you need it to login"
- "The discriminator is random and cannot be changed"
- "If you forget your discriminator, you cannot recover your account"

**Best practices:**
- Show discriminator prominently after registration
- Allow users to copy full username to clipboard
- Suggest saving in password manager
- Consider email confirmation with full username (if not fully anonymous)
