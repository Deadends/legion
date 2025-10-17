Write-Host "Building WASM with atomics..." -ForegroundColor Green
cargo build --release --target wasm32-unknown-unknown

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Running wasm-bindgen with --target no-modules..." -ForegroundColor Green
wasm-bindgen target/wasm32-unknown-unknown/release/legion_wasm_client.wasm `
    --out-dir pkg `
    --target no-modules `
    --no-typescript

if ($LASTEXITCODE -ne 0) {
    Write-Host "wasm-bindgen failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build complete!" -ForegroundColor Green
