@echo off
echo Removing auto-start...
echo.

set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

del "%STARTUP%\network-scanner.vbs" 2>nul
del "%STARTUP%\redteam-assistant.vbs" 2>nul
del "%STARTUP%\network-scanner.bat" 2>nul
del "%STARTUP%\redteam-assistant.bat" 2>nul

echo Done! Apps will no longer auto-start.
echo.
pause
