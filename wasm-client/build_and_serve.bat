@echo off
echo ========================================
echo Legion WASM Client - Build and Serve
echo ========================================
echo.

echo [1/4] Cleaning previous build...
cargo clean
if %errorlevel% neq 0 (
    echo ERROR: cargo clean failed
    pause
    exit /b 1
)

echo.
echo [2/4] Building WASM (this takes 2-5 minutes)...
cargo build --lib --target wasm32-unknown-unknown --release
if %errorlevel% neq 0 (
    echo ERROR: cargo build failed
    pause
    exit /b 1
)

echo.
echo [3/4] Generating JS bindings...
wasm-bindgen target\wasm32-unknown-unknown\release\legion_wasm_client.wasm --out-dir pkg --target web
if %errorlevel% neq 0 (
    echo ERROR: wasm-bindgen failed
    pause
    exit /b 1
)

echo.
echo [4/4] Starting Python server...
echo.
echo ========================================
echo Build complete! Starting server...
echo ========================================
echo.
python serve_simple.py
