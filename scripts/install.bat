@echo off
setlocal enabledelayedexpansion

echo.
echo ========================================
echo 🛡️  Legion ZK Auth - One-Command Installer
echo ========================================
echo.

REM Check Docker
docker --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker not found. Install from: https://docs.docker.com/get-docker/
    exit /b 1
)

REM Check Docker Compose
docker compose version >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose not found. Install from: https://docs.docker.com/compose/install/
    exit /b 1
)

echo ✅ Docker found
echo ✅ Docker Compose found
echo.

REM Build and start
echo 🚀 Starting Legion (Redis + Server + Frontend)...
docker compose up -d --build

echo.
echo ⏳ Waiting for services to be healthy...
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo ✅ Legion is running!
echo.
echo 📍 Frontend:  http://localhost
echo 📍 API:       http://localhost:3001
echo 📍 Health:    http://localhost:3001/health
echo.
echo 🔧 Useful commands:
echo    docker compose logs -f          # View logs
echo    docker compose down             # Stop services
echo    docker compose restart          # Restart services
echo.
echo 🎯 Open http://localhost in your browser to start!
echo ========================================
echo.
pause
