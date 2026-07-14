@echo off
title SENTINEL - AI Phishing Triage
echo.
echo ================================================================
echo   SENTINEL - AI-Powered Phishing Triage Intelligence
echo ================================================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

REM Check/create virtual environment
if not exist "venv" (
    echo [SETUP] Creating virtual environment...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo [SETUP] Installing dependencies...
    pip install -r requirements.txt
    echo.
    echo [SETUP] Setup complete!
    echo.
) else (
    call venv\Scripts\activate.bat
)

REM Check .env file
if not exist ".env" (
    echo [ERROR] .env file not found. Copy .env.example to .env and configure it.
    pause
    exit /b 1
)

echo [START] Starting SENTINEL server...
echo [START] Dashboard: http://localhost:8000/dashboard
echo [START] Landing:   http://localhost:8000/
echo [START] Marketing: http://localhost:8000/marketing
echo [START] API Docs:  http://localhost:8000/docs
echo [START] Press Ctrl+C to stop.
echo.
python app.py
