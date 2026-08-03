# VACE One-Click Launcher for Windows
# Usage: .\launch.ps1

param(
    [switch]$NoOpen  # Add -NoOpen flag to skip opening browser
)

$ErrorActionPreference = "Stop"

Write-Host "[*] Starting VACE..." -ForegroundColor Cyan

# Check if Docker is running
Write-Host "[*] Checking Docker..." -ForegroundColor Yellow
try {
    docker ps > $null 2>&1
}
catch {
    Write-Host "[!] Docker is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Start Docker Compose
# Explicit service list rather than a bare "up -d": the postgres service is
# commented out in docker-compose.yml (host port 5432 sits in a persistent
# Windows dynamic port-exclusion range on this machine) in favor of
# vace-postgres-verify, the same image/data on port 15432 instead.
Write-Host "[*] Starting Docker containers..." -ForegroundColor Yellow
docker-compose up -d vace-postgres-verify sonarqube-db sonarqube redis zap mobsf
Write-Host "[+] Docker containers started" -ForegroundColor Green

# Wait for services to be healthy (max 30 seconds)
Write-Host "[*] Waiting for services to be ready..." -ForegroundColor Yellow
$maxWait = 30
$waited = 0
while ($waited -lt $maxWait) {
    try {
        $response = curl.exe -s http://localhost:15432 2>&1
        break
    }
    catch {
        Start-Sleep -Seconds 1
        $waited++
    }
}

# Start backend
Write-Host "[*] Starting backend..." -ForegroundColor Yellow
$backendPath = ".\backend"
if (-Not (Test-Path $backendPath)) {
    Write-Host "[!] Backend directory not found" -ForegroundColor Red
    exit 1
}

# Activate venv and start uvicorn in background
$backendProcess = Start-Process -NoNewWindow -PassThru `
    -FilePath "powershell.exe" `
    -ArgumentList "-NoExit -Command `"cd '$backendPath'; .\venv\Scripts\activate; uvicorn app.main:app --reload --port 8001`""

Write-Host "[+] Backend started (PID: $($backendProcess.Id))" -ForegroundColor Green

# Start frontend
Write-Host "[*] Starting frontend..." -ForegroundColor Yellow
$frontendPath = ".\frontend"
if (-Not (Test-Path $frontendPath)) {
    Write-Host "[!] Frontend directory not found" -ForegroundColor Red
    $backendProcess.Kill()
    exit 1
}

$frontendProcess = Start-Process -NoNewWindow -PassThru `
    -FilePath "powershell.exe" `
    -ArgumentList "-NoExit -Command `"cd '$frontendPath'; npm run dev`""

Write-Host "[+] Frontend started (PID: $($frontendProcess.Id))" -ForegroundColor Green

# Wait for frontend to be ready
Write-Host "[*] Waiting for frontend to be ready..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Open browser
if (-Not $NoOpen) {
    Write-Host "[*] Opening browser..." -ForegroundColor Yellow
    Start-Process "http://localhost:5173/login"
}

Write-Host "[+] VACE is running!" -ForegroundColor Green
Write-Host ""
Write-Host "Frontend: http://localhost:5173" -ForegroundColor Cyan
Write-Host "Backend API: http://localhost:8001" -ForegroundColor Cyan
Write-Host "Docker: vace-postgres-verify (port 15432), redis, zap, mobsf, sonarqube" -ForegroundColor Cyan
Write-Host ""
Write-Host "Login with: admin / password" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to stop all services..."

# Graceful shutdown on exit
$null = $Host.UI.RawUI.ReadKey("IncludeKeyDown")

Write-Host ""
Write-Host "[*] Shutting down..." -ForegroundColor Yellow
$backendProcess.Kill()
$frontendProcess.Kill()
docker-compose down
Write-Host "[+] VACE stopped" -ForegroundColor Green