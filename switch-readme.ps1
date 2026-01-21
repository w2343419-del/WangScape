param(
    [string]$lang = "zh"
)

$zh = "README.md"
$en = "README.en.md"
$tmp = "README.tmp.md"

if ($lang -eq "en") {
    if (Test-Path $zh -and Test-Path $en) {
        Rename-Item $zh $tmp -Force
        Rename-Item $en $zh -Force
        Rename-Item $tmp $en -Force
        Write-Host "已切换为英文版 README (README.md)"
    } else {
        Write-Host "README 文件不存在，无法切换。"
    }
} elseif ($lang -eq "zh") {
    if (Test-Path $zh -and Test-Path $en) {
        Rename-Item $zh $tmp -Force
        Rename-Item $en $zh -Force
        Rename-Item $tmp $en -Force
        Write-Host "已切换为中文版 README (README.md)"
    } else {
        Write-Host "README 文件不存在，无法切换。"
    }
} else {
    Write-Host "参数错误。用法: ./switch-readme.ps1 zh 或 ./switch-readme.ps1 en"
}
