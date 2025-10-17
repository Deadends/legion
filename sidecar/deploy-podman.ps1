# Legion Podman Deployment - Windows PowerShell
param(
    [string]$Action = "help"
)

$ErrorActionPreference = "Stop"

function Build-Legion {
    Write-Host "Building Legion with Podman..." -ForegroundColor Green
    podman build --format=oci --layers --tag=localhost/legion-sidecar:latest --file=Containerfile .
}

function Deploy-Legion {
    Write-Host "Deploying Legion..." -ForegroundColor Green
    
    # Create secrets directory if it doesn't exist
    if (!(Test-Path "secrets")) {
        New-Item -ItemType Directory -Path "secrets"
        Write-Host "Created secrets directory" -ForegroundColor Yellow
    }
    
    # Generate TLS certificates if they don't exist
    if (!(Test-Path "secrets\server.crt")) {
        Write-Host "Generating TLS certificates..." -ForegroundColor Yellow
        .\generate_certs.ps1
    }
    
    # Deploy with compose
    podman-compose -f compose.yml up -d
    
    Write-Host "Legion deployed successfully!" -ForegroundColor Green
    Write-Host "Access at: https://localhost:8443" -ForegroundColor Cyan
}

function Test-Legion {
    Write-Host "Testing Legion deployment..." -ForegroundColor Green
    
    # Wait for services to start
    Start-Sleep -Seconds 10
    
    # Test health endpoint
    try {
        $response = Invoke-WebRequest -Uri "https://localhost:8443/health" -SkipCertificateCheck
        Write-Host "Health check: $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "Health check failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Status {
    Write-Host "Legion Container Status:" -ForegroundColor Green
    podman ps --filter "name=legion"
    
    Write-Host "`nLegion Logs:" -ForegroundColor Green
    podman logs legion-sidecar --tail 20
}

function Stop-Legion {
    Write-Host "Stopping Legion..." -ForegroundColor Yellow
    podman-compose -f compose.yml down
}

function Clean-Legion {
    Write-Host "Cleaning up Legion..." -ForegroundColor Yellow
    podman-compose -f compose.yml down -v
    podman system prune -f --volumes
}

switch ($Action.ToLower()) {
    "build" { Build-Legion }
    "deploy" { Deploy-Legion }
    "test" { Test-Legion }
    "status" { Show-Status }
    "stop" { Stop-Legion }
    "clean" { Clean-Legion }
    "full" { 
        Build-Legion
        Deploy-Legion
        Test-Legion
    }
    default {
        Write-Host "Legion Podman Deployment" -ForegroundColor Cyan
        Write-Host "Usage: .\deploy-podman.ps1 [action]" -ForegroundColor White
        Write-Host ""
        Write-Host "Actions:" -ForegroundColor Yellow
        Write-Host "  build   - Build Legion container image"
        Write-Host "  deploy  - Deploy Legion with compose"
        Write-Host "  test    - Test deployment"
        Write-Host "  status  - Show container status and logs"
        Write-Host "  stop    - Stop Legion services"
        Write-Host "  clean   - Clean up containers and volumes"
        Write-Host "  full    - Build, deploy, and test"
    }
}