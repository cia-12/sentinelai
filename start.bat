@echo off
REM SentinelAI Quick Start for Windows

echo.
echo 🛡 Starting SentinelAI...
echo.

REM Kill any hanging Python processes
taskkill /F /IM python.exe 2>nul

echo Backend starting on port 8000...
cd backend
start "SentinelAI Backend" python -m uvicorn main:app --host 0.0.0.0 --port 8000 --log-level info

timeout /t 3 /nobreak

echo Frontend starting on port 3000...
cd ..\frontend
start "SentinelAI Frontend" npm run dev

echo.
echo ✅ Services started:
echo    • Frontend: http://localhost:3000
echo    • Backend API: http://localhost:8000
echo    • API Docs: http://localhost:8000/docs
echo.
echo NOTE: Close the terminal windows to stop services.
echo.
pause
