# Start Redis in Podman
Write-Host "🚀 Starting Redis in Podman..." -ForegroundColor Cyan

podman run -d `
  --name legion-redis `
  -p 6379:6379 `
  redis:7-alpine

Write-Host "✅ Redis started on port 6379" -ForegroundColor Green
Write-Host "📊 Check status: podman ps" -ForegroundColor Yellow
Write-Host "🛑 Stop: podman stop legion-redis" -ForegroundColor Yellow
Write-Host "🗑️  Remove: podman rm legion-redis" -ForegroundColor Yellow
