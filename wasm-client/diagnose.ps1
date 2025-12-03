# Diagnostic script to identify WASM build issues

Write-Host "=== Legion WASM Client Build Diagnostics ===" -ForegroundColor Cyan
Write-Host ""

# Check Rust installation
Write-Host "[1/7] Checking Rust installation..." -ForegroundColor Yellow
if (Get-Command rustc -ErrorAction SilentlyContinue) {
    $rustVersion = rustc --version
    Write-Host "  ✓ Rust: $rustVersion" -ForegroundColor Green
} else {
    Write-Host "  ✗ Rust not found! Install from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Check wasm32 target
Write-Host "[2/7] Checking wasm32-unknown-unknown target..." -ForegroundColor Yellow
$targets = rustup target list --installed
if ($targets -match "wasm32-unknown-unknown") {
    Write-Host "  ✓ wasm32-unknown-unknown target installed" -ForegroundColor Green
} else {
    Write-Host "  ✗ wasm32-unknown-unknown target missing" -ForegroundColor Red
    Write-Host "  → Run: rustup target add wasm32-unknown-unknown" -ForegroundColor Cyan
    exit 1
}

# Check wasm-bindgen
Write-Host "[3/7] Checking wasm-bindgen-cli..." -ForegroundColor Yellow
if (Get-Command wasm-bindgen -ErrorAction SilentlyContinue) {
    $wasmBindgenVersion = wasm-bindgen --version
    Write-Host "  ✓ wasm-bindgen: $wasmBindgenVersion" -ForegroundColor Green
    
    # Check version match
    if ($wasmBindgenVersion -match "0\.2\.95") {
        Write-Host "  ✓ Version matches Cargo.toml (0.2.95)" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Version mismatch! Expected 0.2.95" -ForegroundColor Yellow
        Write-Host "  → Run: cargo install wasm-bindgen-cli --version 0.2.95 --force" -ForegroundColor Cyan
    }
} else {
    Write-Host "  ✗ wasm-bindgen-cli not found" -ForegroundColor Red
    Write-Host "  → Run: cargo install wasm-bindgen-cli --version 0.2.95" -ForegroundColor Cyan
    exit 1
}

# Check Cargo.toml
Write-Host "[4/7] Checking Cargo.toml configuration..." -ForegroundColor Yellow
if (Test-Path "Cargo.toml") {
    Write-Host "  ✓ Cargo.toml exists" -ForegroundColor Green
    
    $cargoContent = Get-Content "Cargo.toml" -Raw
    if ($cargoContent -match 'crate-type.*cdylib') {
        Write-Host "  ✓ crate-type = cdylib configured" -ForegroundColor Green
    } else {
        Write-Host "  ✗ Missing crate-type = cdylib" -ForegroundColor Red
    }
    
    if ($cargoContent -match 'legion-prover.*features.*wasm.*legacy-circuit') {
        Write-Host "  ✓ legion-prover features configured" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ Check legion-prover features" -ForegroundColor Yellow
    }
} else {
    Write-Host "  ✗ Cargo.toml not found!" -ForegroundColor Red
    exit 1
}

# Check prover dependency
Write-Host "[5/7] Checking legion-prover dependency..." -ForegroundColor Yellow
if (Test-Path "../prover/Cargo.toml") {
    Write-Host "  ✓ ../prover exists" -ForegroundColor Green
    
    $proverCargo = Get-Content "../prover/Cargo.toml" -Raw
    if ($proverCargo -match 'halo2_proofs') {
        Write-Host "  ✓ halo2_proofs dependency found" -ForegroundColor Green
    } else {
        Write-Host "  ✗ halo2_proofs missing in prover" -ForegroundColor Red
    }
} else {
    Write-Host "  ✗ ../prover not found!" -ForegroundColor Red
    exit 1
}

# Check previous build artifacts
Write-Host "[6/7] Checking build artifacts..." -ForegroundColor Yellow
if (Test-Path "target/wasm32-unknown-unknown/release/legion_wasm_client.wasm") {
    $wasmSize = (Get-Item "target/wasm32-unknown-unknown/release/legion_wasm_client.wasm").Length / 1MB
    Write-Host "  ✓ Previous WASM build found ($([math]::Round($wasmSize, 2)) MB)" -ForegroundColor Green
} else {
    Write-Host "  ℹ No previous build found (first build)" -ForegroundColor Cyan
}

if (Test-Path "pkg/legion_wasm_client.js") {
    Write-Host "  ✓ JS bindings exist in pkg/" -ForegroundColor Green
} else {
    Write-Host "  ℹ No JS bindings yet" -ForegroundColor Cyan
}

# Check disk space
Write-Host "[7/7] Checking disk space..." -ForegroundColor Yellow
$drive = (Get-Location).Drive.Name
$freeSpace = (Get-PSDrive $drive).Free / 1GB
if ($freeSpace -gt 5) {
    Write-Host "  ✓ Free space: $([math]::Round($freeSpace, 2)) GB" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Low disk space: $([math]::Round($freeSpace, 2)) GB" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Diagnostics Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Fix any issues marked with ✗" -ForegroundColor White
Write-Host "  2. Run: .\build_simple.ps1" -ForegroundColor White
Write-Host "  3. If build fails, share the error message" -ForegroundColor White
Write-Host ""
