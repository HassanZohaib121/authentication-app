param(
    [string]$ProjectName = "my-tauri-app"
)

$ErrorActionPreference = "Stop"

$Repo = "https://github.com/HassanZohaib121/tauri-auth-starter.git"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "        Tauri Authentication Starter" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

if (Test-Path $ProjectName) {
    Write-Host "Directory '$ProjectName' already exists." -ForegroundColor Red
    exit 1
}

Write-Host "[1/7] Creating project..." -ForegroundColor Yellow
git clone $Repo $ProjectName

Set-Location $ProjectName

Write-Host "[2/7] Removing starter Git history..." -ForegroundColor Yellow
Remove-Item -Recurse -Force .git

Write-Host "[3/7] Installing dependencies..." -ForegroundColor Yellow
npm install

Write-Host "[4/7] Initializing Git repository..." -ForegroundColor Yellow
git init

Write-Host "[5/7] Creating initial commit..." -ForegroundColor Yellow
git add .
git commit -m "Initial project from Tauri Auth Starter"

Write-Host "[6/7] Removing setup scripts..." -ForegroundColor Yellow

if (Test-Path ".\setup.ps1") {
    Remove-Item ".\setup.ps1" -Force
}

if (Test-Path ".\setup.sh") {
    Remove-Item ".\setup.sh" -Force
}

Write-Host "[7/7] Done!" -ForegroundColor Green
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "       Project created successfully!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Project: $ProjectName"
Write-Host ""
Write-Host "Run:"
Write-Host ""
Write-Host "  cd $ProjectName" -ForegroundColor Cyan
Write-Host "  npm run tauri dev" -ForegroundColor Cyan
Write-Host ""