@echo off
setlocal
cd /d "%~dp0"

".venv\Scripts\python.exe" -m pip install -e .[live,build]

".venv\Scripts\pyinstaller.exe" ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --name AntiSniffer ^
  --paths src ^
  --add-data "config\default.toml;config" ^
  app.py

echo.
echo EXE: %CD%\dist\AntiSniffer\AntiSniffer.exe
endlocal
