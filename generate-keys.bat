@echo off
chcp 65001 >nul
REM WangScape Writer 密钥生成脚本 (Windows PowerShell版本)
REM 用于Windows系统生成部署所需的密钥和哈希值

echo =========================================
echo WangScape Writer 密钥生成工具 (Windows)
echo =========================================
echo.

REM 检查PowerShell是否可用
powershell -Command "exit 0" >nul 2>&1
if errorlevel 1 (
    echo 错误: 需要PowerShell来运行此脚本
    echo 请安装PowerShell或使用Linux/Mac上的 generate-keys.sh
    pause
    exit /b 1
)

echo [1/3] 生成JWT密钥...
for /f "tokens=*" %%A in ('powershell -Command "[System.Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))"') do set JWT_SECRET=%%A
echo ✓ JWT_SECRET: %JWT_SECRET%
echo.

echo [2/3] 生成SMTP加密密钥...
for /f "tokens=*" %%B in ('powershell -Command "[System.Convert]::ToHexString([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16))"') do set SMTP_ENCRYPTION_KEY=%%B
echo ✓ SMTP_ENCRYPTION_KEY: %SMTP_ENCRYPTION_KEY%
echo.

echo [3/3] 生成管理员密码哈希...
echo 请输入管理员密码:
set /p ADMIN_PASSWORD="密码: "

echo.
echo 确认密码:
set /p ADMIN_PASSWORD_CONFIRM="密码: "

if not "%ADMIN_PASSWORD%"=="%ADMIN_PASSWORD_CONFIRM%" (
    echo.
    echo ✗ 密码不匹配！
    pause
    exit /b 1
)

echo.
echo 计算SHA-256哈希...
for /f "tokens=*" %%C in ('powershell -Command "$text = '%ADMIN_PASSWORD%'; $bytes = [System.Text.Encoding]::UTF8.GetBytes($text); $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes); [System.BitConverter]::ToString($hash).Replace('-','').ToLower()"') do set ADMIN_PASSWORD_HASH=%%C
echo ✓ ADMIN_PASSWORD_HASH: %ADMIN_PASSWORD_HASH%
echo.

echo =========================================
echo 生成的密钥配置
echo =========================================
echo.
echo 将以下内容添加到 .env 文件:
echo.
echo # JWT配置
echo JWT_SECRET=%JWT_SECRET%
echo.
echo # 邮件配置
echo SMTP_ENCRYPTION_KEY=%SMTP_ENCRYPTION_KEY%
echo.
echo # 管理员密码配置 (二选一)
echo # 方式1: 明文密码
echo # ADMIN_PASSWORD=%ADMIN_PASSWORD%
echo.
echo # 方式2: 哈希密码 (推荐用于生产环境)
echo ADMIN_PASSWORD_HASH=%ADMIN_PASSWORD_HASH%
echo.

REM 保存到文件
setlocal enabledelayedexpansion
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do (set mydate=%%c%%a%%b)
for /f "tokens=1-2 delims=/:" %%a in ('time /t') do (set mytime=%%a%%b)
set OUTPUT_FILE=generated-keys-%mydate%-%mytime%.txt

(
echo WangScape Writer - 生成的密钥配置
echo 生成时间: %date% %time%
echo.
echo JWT_SECRET=%JWT_SECRET%
echo.
echo SMTP_ENCRYPTION_KEY=%SMTP_ENCRYPTION_KEY%
echo.
echo ADMIN_PASSWORD_HASH=%ADMIN_PASSWORD_HASH%
echo.
echo 使用说明:
echo 1. 将上述值添加到 .env 文件
echo 2. 生产环境强烈建议使用 ADMIN_PASSWORD_HASH 而不是明文密码
echo 3. 定期更换 JWT_SECRET 和 SMTP_ENCRYPTION_KEY (建议每30天一次)
echo.
echo TLS/HTTPS证书生成:
echo 对于Windows，建议:
echo   1. 使用云提供商的证书 (AWS ACM, Azure Key Vault等)
echo   2. 或使用 Certbot (需要WSL2): https://certbot.eff.org/instructions?os=windows
echo   3. 或使用自签名证书用于测试 (不推荐用于生产)
) > "!OUTPUT_FILE!"

echo ✓ 详细信息已保存到: %OUTPUT_FILE%
echo.
echo =========================================
echo 下一步:
echo 1. 复制 .env.example 为 .env
echo 2. 编辑 .env 文件，添加上述生成的密钥
echo 3. 启动应用程序
echo =========================================
echo.
pause
