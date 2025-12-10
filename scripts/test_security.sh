#!/bin/bash

echo "🔬 LEGION SECURITY TEST SUITE"
echo "================================"
echo ""

# Build WASM client
echo "📦 Building WASM client..."
cd wasm-client
wasm-pack build --target web --release
if [ $? -ne 0 ]; then
    echo "❌ WASM build failed"
    exit 1
fi
echo "✅ WASM built successfully"
echo ""

# Build server
echo "📦 Building server..."
cd ../legion-server
cargo build --release --features redis
if [ $? -ne 0 ]; then
    echo "❌ Server build failed"
    exit 1
fi
echo "✅ Server built successfully"
echo ""

echo "🎯 TEST PLAN:"
echo "1. Start Redis"
echo "2. Start Legion server"
echo "3. Register user 'alice'"
echo "4. Login as 'alice' (should succeed)"
echo "5. Try concurrent session access (should fail)"
echo "6. Wait 5 seconds and retry (should succeed)"
echo "7. Verify device commitment is unique per session"
echo ""
echo "Press ENTER to start tests..."
read

# Check Redis
echo "🔍 Checking Redis..."
redis-cli ping > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Redis not running. Start with: redis-server"
    exit 1
fi
echo "✅ Redis is running"
echo ""

# Start server in background
echo "🚀 Starting Legion server..."
cd ../legion-server
RUST_LOG=info cargo run --release --features redis &
SERVER_PID=$!
sleep 3
echo "✅ Server started (PID: $SERVER_PID)"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "🧹 Cleaning up..."
    kill $SERVER_PID 2>/dev/null
    echo "✅ Server stopped"
}
trap cleanup EXIT

echo "📝 Open http://localhost:8000 in your browser"
echo "   Then open DevTools Console to see security logs"
echo ""
echo "Press CTRL+C to stop server"
wait $SERVER_PID
