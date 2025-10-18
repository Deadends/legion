# Build Legion with Podman (with stability fixes)

Write-Host "🛡️  Building Legion with Podman (Stable Mode)" -ForegroundColor Cyan
Write-Host ""

# Increase Podman machine resources
Write-Host "1. Stopping Podman machine..." -ForegroundColor Yellow
podman machine stop

Write-Host "2. Increasing resources (4 CPUs, 8GB RAM)..." -ForegroundColor Yellow
podman machine set --cpus 4 --memory 8192

Write-Host "3. Starting Podman machine..." -ForegroundColor Yellow
podman machine start

Start-Sleep -Seconds 5

# Fix DNS again (it resets on restart)
Write-Host "4. Configuring DNS..." -ForegroundColor Yellow
podman machine ssh "echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf && echo 'nameserver 1.1.1.1' | sudo tee -a /etc/resolv.conf"

Write-Host ""
Write-Host "5. Building Legion Server (this may take 10-15 minutes)..." -ForegroundColor Yellow
Write-Host ""

# Build with more verbose output and no cache to avoid issues
podman build `
    --no-cache `
    --format docker `
    -t docker.io/deadends/legion-server:1.0.0 `
    -t docker.io/deadends/legion-server:latest `
    -f Dockerfile .

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Build successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📦 Images created:" -ForegroundColor Cyan
    podman images | Select-String "legion-server"
} else {
    Write-Host ""
    Write-Host "❌ Build failed. Try Docker Desktop instead:" -ForegroundColor Red
    Write-Host "   https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
}
