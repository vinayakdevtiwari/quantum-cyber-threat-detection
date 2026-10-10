@echo off
REM ===================================================================
REM  QDS Demo Launcher
REM  Runs the preflight check, then starts the phone backend and the
REM  analytics dashboard together.
REM
REM  Usage:  run_demo.bat          (normal)
REM          run_demo.bat --check  (preflight only, then exit)
REM ===================================================================

setlocal
cd /d "%~dp0"

set PY=.venv\Scripts\python.exe

REM --- Prefer the project venv; fall back to system Python -------------
if not exist "%PY%" (
    echo [WARN] No .venv found -- using system Python.
    echo [WARN] To create one:  python -m venv .venv
    echo [WARN] Then:           .venv\Scripts\pip install -r requirements.txt
    echo.
    set PY=python
)

echo ===================================================================
echo  QDS DEMO LAUNCHER
echo ===================================================================
echo.

REM --- Step 1: preflight ------------------------------------------------
echo [1/3] Running preflight checks...
echo.
"%PY%" preflight.py
if errorlevel 1 (
    echo.
    echo [FAIL] Preflight returned an error. Fix the issues above first.
    goto :failed
)

if /i "%~1"=="--check" (
    echo.
    echo Preflight only, as requested. Exiting.
    goto :done
)

REM --- Step 2: free the ports if something is already bound -------------
echo.
echo [2/3] Freeing ports 5000 and 8501 if occupied...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5000" ^| findstr LISTENING') do (
    echo    stopping PID %%p on port 5000
    taskkill /F /PID %%p >nul 2>&1
)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8501" ^| findstr LISTENING') do (
    echo    stopping PID %%p on port 8501
    taskkill /F /PID %%p >nul 2>&1
)
timeout /t 2 /nobreak >nul

REM --- Step 3: phone backend -------------------------------------------
echo.
echo [3/3] Starting phone demo backend (server.py)...
start "QDS Phone Backend" cmd /k "%PY% server.py"
timeout /t 6 /nobreak >nul

REM --- Step 4: analytics dashboard -------------------------------------
echo.
echo Starting analytics dashboard (app.py)...
start "QDS Dashboard" cmd /k "%PY% -m streamlit run app.py --server.port 8501"
timeout /t 8 /nobreak >nul

REM --- Step 5: open both ------------------------------------------------
start "" http://localhost:5000
start "" http://localhost:8501

echo.
echo ===================================================================
echo  BOTH SERVERS STARTED
echo ===================================================================
echo.
echo  Dashboard      http://localhost:8501
echo  Phone demo     http://localhost:5000
echo.
"%PY%" network.py
echo.
echo  Phones must be on the SAME network as this laptop.
echo  Use the 192.168.137.x address if they joined THIS laptop's hotspot.
echo.
echo  Close the two console windows to stop everything.
echo.
goto :done

:failed
echo.
echo Launch aborted. See the messages above.
exit /b 1

:done
endlocal