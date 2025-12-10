# Legion ZK Auth - Build & Push Script (Windows/PowerShell)

Write-Host "🛡️  Legion ZK Auth - Build & Push Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$REGISTRY = "docker.io"
$USERNAME = "deadends"
$IMAGE_NAME = "legion-server"
$VERSION = "1.0.0"

# Full image names
$IMAGE_VERSIONED = "${REGISTRY}/${USERNAME}/${IMAGE_NAME}:${VERSION}"
$IMAGE_LATEST = "${REGISTRY}/${USERNAME}/${IMAGE_NAME}:latest"

Write-Host "📦 Building Legion Server..." -ForegroundColor Yellow
Write-Host "   Image: $IMAGE_NAME"
Write-Host "   Version: $VERSION"
Write-Host ""

# Build with Podman
podman build -t $IMAGE_VERSIONED -t $IMAGE_LATEST -f Dockerfile .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "✅ Build complete!" -ForegroundColor Green
Write-Host ""
Write-Host "🏷️  Tagged images:" -ForegroundColor Cyan
Write-Host "   - $IMAGE_VERSIONED"
Write-Host "   - $IMAGE_LATEST"
Write-Host ""

# Ask for confirmation before pushing
$response = Read-Host "Push to Docker Hub? (y/n)"

if ($response -eq "y" -or $response -eq "Y") {
    Write-Host ""
    Write-Host "🔐 Logging in to Docker Hub..." -ForegroundColor Yellow
    podman login docker.io
    
    Write-Host ""
    Write-Host "⬆️  Pushing images..." -ForegroundColor Yellow
    podman push $IMAGE_VERSIONED
    podman push $IMAGE_LATEST
    
    Write-Host ""
    Write-Host "✅ Successfully pushed to Docker Hub!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📦 Users can now pull with:" -ForegroundColor Cyan
    Write-Host "   podman pull $IMAGE_LATEST"
    Write-Host "   docker pull $IMAGE_LATEST"
} else {
    Write-Host ""
    Write-Host "⏭️  Skipping push. Images are available locally." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎯 Next steps:" -ForegroundColor Cyan
Write-Host "   1. Update docker-compose.yml to use: $IMAGE_LATEST"
Write-Host "   2. Test: podman-compose up -d"
Write-Host "   3. Update README.md with Docker Hub instructions"
Write-Host ""
