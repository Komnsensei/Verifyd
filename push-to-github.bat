@echo off
REM Verifyd one-shot GitHub push.
REM Run this AFTER you have gh CLI installed and authed (gh auth login).

cd /d "%~dp0"
echo === Verifyd: Push to GitHub ===
echo.

if not exist .git (
  echo [1/4] Initializing git repo...
  git init
  git branch -M main
)

echo [2/4] Adding files...
git add .
git status --short

echo.
echo [3/4] Committing...
git commit -m "Verifyd v1.0 — initial ship with citations registry" || echo (nothing new to commit)

echo.
echo [4/4] Creating GitHub repo + pushing...
where gh >nul 2>&1
if errorlevel 1 (
  echo.
  echo gh CLI not found. Install it first:
  echo   winget install --id GitHub.cli
  echo Then run: gh auth login
  echo Then re-run this script.
  pause
  exit /b 1
)

gh repo create verifyd --public --source=. --push --description "Tamper-evident audit receipts for AI decisions. VALF-1 protocol. Zero deps."

echo.
echo === Done. Repo is live at: https://github.com/komnsensei/verifyd ===
echo Open Codex (chatgpt.com/codex), select 'verifyd' repo, give it BUILD.md as the task.
pause
