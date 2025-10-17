#!/bin/bash
set -e

echo "🛡️  Legion ZK Auth - Quick Deploy Script"
echo "========================================"

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found. Install: https://docs.docker.com/get-docker/"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "❌ Docker Compose not found."; exit 1; }

echo "✅ Prerequisites check passed"

# Build production images
echo ""
echo "📦 Building production images..."
docker-compose build --no-cache

# Start services
echo ""
echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be healthy
echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 10

# Check health
echo ""
echo "🔍 Checking service health..."
if curl -f http://localhost/health >/dev/null 2>&1; then
    echo "✅ Server is healthy"
else
    echo "❌ Server health check failed"
    docker-compose logs legion-server
    exit 1
fi

# Show status
echo ""
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "✅ Deployment complete!"
echo ""
echo "🌐 Access your application:"
echo "   Frontend: http://localhost"
echo "   API: http://localhost/api"
echo "   Health: http://localhost/health"
echo ""
echo "📝 View logs:"
echo "   docker-compose logs -f legion-server"
echo ""
echo "🛑 Stop services:"
echo "   docker-compose down"
echo ""
echo "🔄 Update deployment:"
echo "   git pull && docker-compose up -d --build"
