# WSwriter 启动脚本 (密码模式)
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "Yw20070616@"
$env:JWT_SECRET = "118FDF747256BD77D36D58C9AD24DF69C45BE80710B76D5FCE18D56AC044860F"

Write-Host "WSwriter 启动中..."
Write-Host "访问地址: http://localhost:8080"
Write-Host "用户名: admin"
Write-Host "密码: Yw20070616@"

# 启动WSwriter
& "$PSScriptRoot\WSwriter.exe"
