# Fix Podman Network/DNS Issues on Windows

Write-Host "🔧 Fixing Podman Network Configuration..." -ForegroundColor Cyan
Write-Host ""

# Stop the Podman machine
Write-Host "1. Stopping Podman machine..." -ForegroundColor Yellow
podman machine stop

Start-Sleep -Seconds 3

# Start with fresh network settings
Write-Host "2. Starting Podman machine..." -ForegroundColor Yellow
podman machine start

Start-Sleep -Seconds 5

# Test connection
Write-Host ""
Write-Host "3. Testing Docker Hub connection..." -ForegroundColor Yellow
podman pull hello-world

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "✅ Network fixed! Podman can now reach Docker Hub." -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "❌ Still having issues. Try manual fix:" -ForegroundColor Red
    Write-Host ""
    Write-Host "Option 1: Restart WSL" -ForegroundColor Yellow
    Write-Host "   wsl --shutdown" -ForegroundColor Gray
    Write-Host "   podman machine start" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Option 2: Use Docker Desktop instead" -ForegroundColor Yellow
    Write-Host "   Install from: https://www.docker.com/products/docker-desktop/" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Option 3: Configure DNS manually" -ForegroundColor Yellow
    Write-Host "   podman machine ssh" -ForegroundColor Gray
    Write-Host "   echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf" -ForegroundColor Gray
}

Write-Host ""
