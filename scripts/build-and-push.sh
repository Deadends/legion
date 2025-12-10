#!/bin/bash
set -e

echo "🛡️  Legion ZK Auth - Build & Push Script"
echo "========================================"
echo ""

# Configuration
REGISTRY="docker.io"
USERNAME="deadends"
IMAGE_NAME="legion-server"
VERSION="1.0.0"

# Full image names
IMAGE_VERSIONED="${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"
IMAGE_LATEST="${REGISTRY}/${USERNAME}/${IMAGE_NAME}:latest"

echo "📦 Building Legion Server..."
echo "   Image: ${IMAGE_NAME}"
echo "   Version: ${VERSION}"
echo ""

# Build with Podman
podman build -t ${IMAGE_VERSIONED} -t ${IMAGE_LATEST} -f Dockerfile .

echo ""
echo "✅ Build complete!"
echo ""
echo "🏷️  Tagged images:"
echo "   - ${IMAGE_VERSIONED}"
echo "   - ${IMAGE_LATEST}"
echo ""

# Ask for confirmation before pushing
read -p "Push to Docker Hub? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔐 Logging in to Docker Hub..."
    podman login docker.io
    
    echo ""
    echo "⬆️  Pushing images..."
    podman push ${IMAGE_VERSIONED}
    podman push ${IMAGE_LATEST}
    
    echo ""
    echo "✅ Successfully pushed to Docker Hub!"
    echo ""
    echo "📦 Users can now pull with:"
    echo "   podman pull ${IMAGE_LATEST}"
    echo "   docker pull ${IMAGE_LATEST}"
else
    echo ""
    echo "⏭️  Skipping push. Images are available locally."
fi

echo ""
echo "🎯 Next steps:"
echo "   1. Update docker-compose.yml to use: ${IMAGE_LATEST}"
echo "   2. Test: podman-compose up -d"
echo "   3. Update README.md with Docker Hub instructions"
echo ""
