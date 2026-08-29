@echo off
setlocal enabledelayedexpansion

echo =========================================================================
echo   NTRO Cyber Threat Detection System - Live Showcase Demo
echo =========================================================================
echo.

cd /d "%~dp0"

:: 1. Activate Virtual Environment
if exist ".\venv\Scripts\activate.bat" (
    echo [INFO] Activating virtual environment...
    call ".\venv\Scripts\activate.bat"
) else (
    echo [WARNING] venv not detected at .\venv, using system python...
)

:: Ensure storage directory exists
if not exist "storage" mkdir storage

:: 2. Launch FastAPI Backend in Background
echo [INFO] Starting Backend API & WebSocket Streamer on http://127.0.0.1:8000 ...
start /B "NTRO-Backend" python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000

:: 3. Wait for server startup
echo [INFO] Waiting for API server to become ready...
timeout /t 3 /nobreak >nul

:: 4. Open Default Web Browser
echo [INFO] Opening SOC Dashboard in default web browser...
start http://localhost:8000

:: 5. Launch Live PCAP Replay Orchestrator
echo.
echo =========================================================================
echo   Replaying Curated Multi-Threat Attack Scenario (samples\demo\mixed_attacks.pcap)
echo   Watch live alerts stream into your browser in real time!
echo =========================================================================
echo.

python -m pipeline.orchestrator --mode replay --pcap "samples\demo\mixed_attacks.pcap" --rate 10mbps

echo.
echo [INFO] Replay completed. Server remains active.
echo Press Ctrl+C in this terminal when finished to exit.
pause >nul
