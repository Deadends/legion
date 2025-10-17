# Build WASM with multithreading support
Write-Host "Building WASM with atomics..." -ForegroundColor Green
cargo build --release --target wasm32-unknown-unknown

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Running wasm-bindgen with reference-types..." -ForegroundColor Green
wasm-bindgen target\wasm32-unknown-unknown\release\legion_wasm_client.wasm `
    --out-dir pkg `
    --target web `
    --no-typescript `
    --reference-types

if ($LASTEXITCODE -ne 0) {
    Write-Host "wasm-bindgen failed!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Build complete! Multithreading enabled" -ForegroundColor Green
Write-Host "Server headers: COOP/COEP enabled via serve.py" -ForegroundColor Cyan
