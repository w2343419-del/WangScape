@echo off
cd /d "%~dp0"
REM 从.env文件加载环境变量
for /f "tokens=1,2 delims==" %%a in ('type .env ^| findstr /v "^#" ^| findstr /v "^$"') do (
    set "%%a=%%b"
)
REM 启动WSwriter
WSwriter.exe
pause
