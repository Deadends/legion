# Build WASM (single-threaded, no atomics issues)
Write-Host 'Building WASM (single-threaded)...' -ForegroundColor Cyan

rustup target add wasm32-unknown-unknown

# Build with stable Rust (no build-std, no IndexMap issues)
cargo build --lib --target wasm32-unknown-unknown --release

# Generate JS bindings
if (-not (Get-Command wasm-bindgen -ErrorAction SilentlyContinue)) {
    cargo install wasm-bindgen-cli
}
wasm-bindgen target/wasm32-unknown-unknown/release/legion_wasm_client.wasm --out-dir pkg --target web

Write-Host 'Build complete!' -ForegroundColor Green
