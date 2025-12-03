# WASM Client Build Instructions

## Prerequisites

```powershell
# Install Rust toolchain
rustup target add wasm32-unknown-unknown

# Install wasm-bindgen-cli (MUST match version in Cargo.toml: 0.2.95)
cargo install wasm-bindgen-cli --version 0.2.95
```

## Build Steps

### Option 1: Simple Build (Recommended)

```powershell
cd wasm-client
.\build_simple.ps1
```

### Option 2: Manual Build

```powershell
cd wasm-client

# Step 1: Build WASM binary
cargo build --lib --target wasm32-unknown-unknown --release

# Step 2: Generate JS bindings
wasm-bindgen target/wasm32-unknown-unknown/release/legion_wasm_client.wasm `
    --out-dir pkg `
    --target web

# Step 3: Serve locally
python serve.py
# OR
python -m http.server 8000
```

## Common Issues & Fixes

### Issue 1: `wasm-bindgen` version mismatch
**Error**: "wasm-bindgen version mismatch"
**Fix**: 
```powershell
cargo install wasm-bindgen-cli --version 0.2.95 --force
```

### Issue 2: Missing `halo2_proofs` or `halo2_gadgets`
**Error**: "could not find halo2_proofs"
**Fix**: The prover crate needs `legacy-circuit` feature enabled (already set in Cargo.toml)

### Issue 3: Build hangs or takes too long
**Cause**: ZK circuit compilation is CPU-intensive
**Expected**: 2-5 minutes for release build
**Fix**: Use `--release` flag (already in scripts)

### Issue 4: Memory issues during build
**Fix**: 
```powershell
$env:CARGO_BUILD_JOBS="2"  # Limit parallel jobs
cargo build --target wasm32-unknown-unknown --release
```

### Issue 5: `getrandom` errors
**Error**: "getrandom not supported"
**Fix**: Already configured with `features = ["js"]` in Cargo.toml

## Verify Build Success

After building, check:
```powershell
ls pkg/
# Should contain:
# - legion_wasm_client_bg.wasm
# - legion_wasm_client.js
# - legion_wasm_client.d.ts
# - package.json
```

## Test the Build

```powershell
# Start server (terminal 1)
cd ../legion-server
cargo run --release --features redis

# Serve WASM client (terminal 2)
cd ../wasm-client
python serve.py

# Open browser
# Navigate to: http://localhost:8000
```

## Build Output Size

Expected sizes:
- Debug: ~15-20 MB
- Release: ~3-5 MB (with LTO optimization)

## Troubleshooting

If build fails, try:
```powershell
# Clean build
cargo clean
rm -r pkg/

# Rebuild
cargo build --target wasm32-unknown-unknown --release --verbose
```

Check specific error messages and compare against issues above.
