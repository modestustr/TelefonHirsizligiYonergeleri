@echo off
setlocal
cd /d "%~dp0"

py -3 app.py
if not errorlevel 1 goto :eof

python app.py
if not errorlevel 1 goto :eof

echo.
echo Python bulunamadi veya uygulama baslatilamadi.
echo Python 3.11 veya 3.12 yukleyip PATH'e ekleyin.
pause
