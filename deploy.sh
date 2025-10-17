#!/bin/bash
# Production deployment script

set -e

echo "🚀 Legion Deployment Script"
echo "============================"

# Configuration
ENVIRONMENT=${1:-production}
REGISTRY=${DOCKER_REGISTRY:-docker.io}
IMAGE_NAME=${IMAGE_NAME:-legion-auth}
VERSION=${VERSION:-latest}

echo "📋 Configuration:"
echo "  Environment: $ENVIRONMENT"
echo "  Registry: $REGISTRY"
echo "  Image: $IMAGE_NAME:$VERSION"
echo ""

# Build image
echo "🔨 Building Docker image..."
podman build -t $REGISTRY/$IMAGE_NAME:$VERSION -f Containerfile .
podman tag $REGISTRY/$IMAGE_NAME:$VERSION $REGISTRY/$IMAGE_NAME:latest

# Run tests
echo "🧪 Running tests..."
cargo test --workspace --release

# Push to registry
if [ "$ENVIRONMENT" = "production" ]; then
    echo "📤 Pushing to registry..."
    podman push $REGISTRY/$IMAGE_NAME:$VERSION
    podman push $REGISTRY/$IMAGE_NAME:latest
fi

# Deploy
echo "🚢 Deploying..."
case $ENVIRONMENT in
    local)
        echo "Starting local deployment..."
        podman-compose down
        podman-compose up -d
        ;;
    production)
        echo "Deploying to Kubernetes..."
        kubectl apply -f k8s/
        kubectl rollout restart deployment/legion-backend -n legion
        kubectl rollout status deployment/legion-backend -n legion
        ;;
    *)
        echo "Unknown environment: $ENVIRONMENT"
        exit 1
        ;;
esac

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📊 Status:"
if [ "$ENVIRONMENT" = "local" ]; then
    podman-compose ps
else
    kubectl get pods -n legion
fi
