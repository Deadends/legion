#!/bin/bash
set -e

echo "🛡️  Legion ZK Auth - One-Command Installer"
echo "=========================================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Install from: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Install from: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker found"
echo "✅ Docker Compose found"
echo ""

# Build and start
echo "🚀 Starting Legion (Redis + Server + Frontend)..."
docker compose up -d --build

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5

# Wait for health checks
for i in {1..30}; do
    if docker compose ps | grep -q "healthy"; then
        echo "✅ Services are healthy!"
        break
    fi
    echo -n "."
    sleep 2
done

echo ""
echo "=========================================="
echo "✅ Legion is running!"
echo ""
echo "📍 Frontend:  http://localhost"
echo "📍 API:       http://localhost:3001"
echo "📍 Health:    http://localhost:3001/health"
echo ""
echo "🔧 Useful commands:"
echo "   docker compose logs -f          # View logs"
echo "   docker compose down             # Stop services"
echo "   docker compose restart          # Restart services"
echo ""
echo "🎯 Open http://localhost in your browser to start!"
echo "=========================================="
