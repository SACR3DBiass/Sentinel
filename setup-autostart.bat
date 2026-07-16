@echo off
echo Setting up silent auto-start...
echo.

set "STARTUP=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

(
    echo Set WshShell = CreateObject^("WScript.Shell"^)
    echo WshShell.Run "node server.js", 0, False
) > "%STARTUP%\network-scanner.vbs"

(
    echo Set WshShell = CreateObject^("WScript.Shell"^)
    echo WshShell.CurrentDirectory = "C:\Users\conno\OneDrive\Documents\New OpenCode Project\redteam-assistant"
    echo WshShell.Run "node server.js", 0, False
) > "%STARTUP%\redteam-assistant.vbs"

(
    echo Set WshShell = CreateObject^("WScript.Shell"^)
    echo WshShell.CurrentDirectory = "C:\Users\conno\OneDrive\Documents\New OpenCode Project\network-scanner"
    echo WshShell.Run "node server.js", 0, False
) > "%STARTUP%\network-scanner.vbs"

del "%STARTUP%\network-scanner.bat" 2>nul
del "%STARTUP%\redteam-assistant.bat" 2>nul

echo Done! Apps will run silently in background on startup.
echo.
echo Network Scanner: http://localhost:3000
echo Red Team Assistant: http://localhost:3001
echo.
echo No terminal windows will appear.
echo.
pause
