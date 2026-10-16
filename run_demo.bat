@echo off
REM ===================================================================
REM  QDS Demo Launcher -- three windows, nothing else
REM
REM    Window 1  VICTIM      http://192.168.137.1:5000/room
REM    Window 2  ATTACKER    http://192.168.137.1:5000/attack
REM    Window 3  DASHBOARD   http://localhost:8501
REM
REM  Two apps total. The victim and attacker are routes on the SAME Flask
REM  backend (server.py): /room and /attack. The dashboard is Streamlit
REM  (app.py) on 8501.
REM
REM  HOST is the address the PHONES use. It is auto-detected below from the
REM  live network interfaces (hotspot first, same order as network.py), so a
REM  venue Wi-Fi change cannot leave the windows pointing at a stale IP.
REM  Override one-off from a terminal with:  set HOST=x.x.x.x  The laptop
REM  itself can always use localhost.
REM
REM  Usage:  run_demo.bat          (normal)
REM          run_demo.bat --check  (preflight only, then exit)
REM ===================================================================

setlocal EnableDelayedExpansion
cd /d "%~dp0"

REM HOST is auto-detected after Python is resolved; keep any value the caller
REM exported before launching.

set PY=.venv\Scripts\python.exe
if not exist "%PY%" (
    echo [WARN] No .venv found -- using system Python.
    echo [WARN] To create one:  python -m venv .venv
    echo [WARN] Then:           .venv\Scripts\pip install -r requirements.txt
    echo.
    set PY=python
)

REM --- Auto-detect the phone-facing address ------------------------------
REM Reuse network.py's ordering (hotspot adapter first) instead of a frozen
REM IP, so the browser windows below and the phones always agree. If the
REM detection fails for any reason, fall back to localhost, which the
REM laptop can always reach.
if not defined HOST (
    for /f "delims=" %%a in ('%PY% -c "import network; print(network.primary_address())"') do set "HOST=%%a"
)
if not defined HOST set HOST=127.0.0.1
echo    Phone-facing address: %HOST% -- laptop windows use this; dashboard stays on localhost

where curl.exe >nul 2>&1
if errorlevel 1 (set HAVE_CURL=0) else (set HAVE_CURL=1)

set FAILED=0

echo ===================================================================
echo  QDS DEMO LAUNCHER
echo ===================================================================
echo.

REM --- Step 1: preflight ------------------------------------------------
echo [1/5] Running preflight checks...
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

REM --- Step 2: free the ports -------------------------------------------
echo.
echo [2/5] Freeing ports 5000 and 8501 if occupied...
call :free_port 5000 server.py
call :free_port 8501 app.py
>nul 2>&1 ping -n 2 127.0.0.1

REM --- Step 3: Flask backend (victim + attacker) ------------------------
REM Both roles live here, so this must be up before anything opens.
echo.
echo [3/5] Starting room backend (server.py) on port 5000...
start "QDS Room Backend" cmd /k "%PY% server.py"
call :wait_for "http://localhost:5000/room" "room backend" 45
if errorlevel 1 (
    echo    [FAIL] The room backend did not come up. See its console window.
    set FAILED=1
) else (
    echo    Room backend is answering.
)

REM --- Step 4: dashboard ------------------------------------------------
echo.
echo [4/5] Starting dashboard (app.py) on port 8501...
start "QDS Dashboard" cmd /k "%PY% -m streamlit run app.py --server.port 8501"
call :wait_for "http://localhost:8501/_stcore/health" "dashboard" 60
if errorlevel 1 (
    echo    [FAIL] The dashboard did not come up. See its console window.
    set FAILED=1
) else (
    echo    Dashboard is answering.
)

REM --- Step 5: three browser windows ------------------------------------
echo.
echo [5/5] Opening three windows...
start "" http://%HOST%:5000/room
start "" http://%HOST%:5000/attack
start "" http://localhost:8501
echo    Done.

echo.
echo ===================================================================
if "%FAILED%"=="0" (
    echo  ALL SERVICES STARTED AND RESPONDING
) else (
    echo  LAUNCHED, BUT ONE OR MORE SERVICES DID NOT COME UP
)
echo ===================================================================
echo.
echo  Window 1  VICTIM      http://%HOST%:5000/room
echo  Window 2  ATTACKER    http://%HOST%:5000/attack
echo  Window 3  DASHBOARD   http://localhost:8501
echo.
echo  Enter the same room code in the victim and attacker windows.
echo  Phones must be on the SAME network as this laptop.
echo.
"%PY%" network.py
echo.
if not "%FAILED%"=="0" (
    echo [WARN] One service failed its health check. Check the console
    echo        window that reported [FAIL] for the traceback.
    echo.
)
echo  Close the two console windows to stop everything.
echo.
if "%FAILED%"=="0" (goto :done) else (goto :partial)

REM ===================================================================
REM  Subroutines
REM ===================================================================

REM --- Free one port, but only if this project is what is holding it -----
REM Killing whatever is on the port is how an unrelated app gets killed
REM twenty minutes before a demo. Ask the OS what the command line is
REM first and only kill a match.
:free_port
set "PORT=%~1"
set "TOKEN=%~2"
set "HIT=0"
for /f "tokens=5" %%p in ('netstat -ano ^| findstr "LISTENING" ^| findstr ":%PORT% "') do (
    set /a HIT+=1
    call :reap_pid %%p %TOKEN% %PORT%
)
if "%HIT%"=="0" echo    Port %PORT% is free.
exit /b 0

:reap_pid
REM %1 = PID, %2 = expected token in the command line, %3 = port
set "RPID=%~1"
set "RTOKEN=%~2"
set "RPORT=%~3"
set "MATCH="
for /f "usebackq delims=" %%m in (`powershell -NoProfile -Command "try { $p = Get-CimInstance Win32_Process -Filter 'ProcessId=%RPID%' -ErrorAction Stop; if ($p.CommandLine -like '*%RTOKEN%*') { 'MATCH' } else { 'NOMATCH' } } catch { 'GONE' }"`) do set "MATCH=%%m"
if /i "!MATCH!"=="MATCH" (
    echo       stopping PID %RPID% on port %RPORT% ^(it is a %RTOKEN% process^)
    taskkill /F /PID %RPID% >nul 2>&1
) else if /i "!MATCH!"=="GONE" (
    echo       PID %RPID% already exited.
) else (
    echo       [WARN] PID %RPID% holds port %RPORT% but is not a %RTOKEN%
    echo              process. Leaving it alone -- stop it yourself if the
    echo              port is needed.
)
exit /b 0

REM --- Block until a URL answers, then move on --------------------------
REM Fixed sleeps were the real bug: the launcher used to wait a fixed 6s
REM and open the browser regardless, so a slow start looked exactly like
REM a dead dashboard. Poll the real endpoint instead.
:wait_for
set "URL=%~1"
set "LABEL=%~2"
set /a MAXWAIT=%~3
set /a TRIES=0
:wait_loop
if "%HAVE_CURL%"=="1" (
    curl.exe -s -o NUL --max-time 3 "%URL%" >nul 2>&1
) else (
    powershell -NoProfile -Command "try { if ((Invoke-WebRequest -UseBasicParsing -Uri '%URL%' -TimeoutSec 3).StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }" >nul 2>&1
)
if not errorlevel 1 exit /b 0
set /a TRIES+=1
if %TRIES% geq %MAXWAIT% exit /b 1
>nul 2>&1 ping -n 2 127.0.0.1
goto :wait_loop

:done
endlocal & exit /b 0

:partial
endlocal & exit /b 1

:failed
echo.
echo Launch aborted. See the messages above.
echo.
endlocal & exit /b 1