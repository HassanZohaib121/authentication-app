#!/usr/bin/env bash

set -e

PROJECT_NAME="${1:-my-tauri-app}"
REPO="https://github.com/HassanZohaib121/tauri-auth-starter.git"

echo ""
echo "============================================"
echo "        Tauri Authentication Starter"
echo "============================================"
echo ""

if [ -d "$PROJECT_NAME" ]; then
    echo "Directory '$PROJECT_NAME' already exists."
    exit 1
fi

echo "[1/7] Creating project..."
git clone "$REPO" "$PROJECT_NAME"

cd "$PROJECT_NAME"

echo "[2/7] Removing starter Git history..."
rm -rf .git

echo "[3/7] Installing dependencies..."
npm install

echo "[4/7] Removing setup scripts..."

rm -f setup.sh
rm -f setup.ps1

echo "[5/7] Initializing Git repository..."
git init

echo "[6/7] Creating initial commit..."
git add .
git commit -m "Initial project from Tauri Auth Starter"

echo "[7/7] Done!"

echo ""
echo "============================================"
echo "       Project created successfully!"
echo "============================================"
echo ""
echo "Project: $PROJECT_NAME"
echo ""
echo "Run:"
echo ""
echo "  cd $PROJECT_NAME"
echo "  npm run tauri dev"
echo ""
