# WINDOWS 420 — установщик для Windows 10/11. Подробности: README.md
param([switch]$Yes,[switch]$DryRun,[switch]$WithNetwork,[switch]$Dev,[switch]$Build,[switch]$NoShortcut,[switch]$WithTts,[switch]$AcceptXttsLicense)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
function Say($m){ Write-Host "[W420] $m" -ForegroundColor Green }
function Run($cmd){
  if($DryRun){ Write-Host "  [dry-run] $cmd"; return }
  $global:LASTEXITCODE = 0
  Invoke-Expression $cmd
  if($LASTEXITCODE -ne 0){ throw "Команда завершилась с ошибкой: $cmd" }
}
function Winget($id,$extra=''){
  if(-not $DryRun){ winget list --id $id -e *> $null; if($LASTEXITCODE -eq 0){ Say "уже установлено: $id"; return } }
  Run "winget install --id $id -e --accept-source-agreements --accept-package-agreements $extra"
}
function RefreshPath(){
  $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User') + ";$env:USERPROFILE\.cargo\bin"
}
function MakeShortcut(){
  $app = Join-Path $PSScriptRoot 'app'
  $exe = Join-Path $app 'src-tauri\target\release\w420.exe'
  $ico = Join-Path $app 'src-tauri\icons\icon.ico'
  if(-not (Test-Path $exe)){ Write-Host '[W420] приложение ещё не собрано: ярлык запустит режим разработки. Для автономного ярлыка: install.bat -Build' -ForegroundColor Yellow }
  foreach($dir in @([Environment]::GetFolderPath('Desktop'), [Environment]::GetFolderPath('Programs'))){
    $lnk = Join-Path $dir 'Windows 420.lnk'
    if($DryRun){ Write-Host "  [dry-run] shortcut $lnk"; continue }
    $s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
    if(Test-Path $exe){ $s.TargetPath = $exe; $s.WorkingDirectory = Split-Path $exe }
    else { $s.TargetPath = Join-Path $PSScriptRoot 'launch.bat'; $s.WorkingDirectory = $PSScriptRoot }
    if(Test-Path $ico){ $s.IconLocation = $ico }
    $s.Description = 'WINDOWS 420 - AGI OS'
    $s.Save()
  }
}
function RunArgs($exe){
  $a = $args
  if($DryRun){ Write-Host "  [dry-run] $exe $($a -join ' ')"; return }
  $global:LASTEXITCODE = 0
  & $exe @a
  if($LASTEXITCODE -ne 0){ throw "Команда завершилась с ошибкой: $exe $($a -join ' ')" }
}
function SetupTts(){
  Say 'голосовой движок XTTS: понадобится 3-7 ГБ на диске'
  Winget 'Python.Python.3.12'
  RefreshPath
  $venv = Join-Path $PSScriptRoot 'tts-server\.venv'
  $vpy  = Join-Path $venv 'Scripts\python.exe'
  if(Get-Command py -ErrorAction SilentlyContinue){ RunArgs 'py' '-3.12' '-m' 'venv' $venv } else { RunArgs 'python' '-m' 'venv' $venv }
  RunArgs $vpy '-m' 'pip' 'install' '--upgrade' 'pip'
  $idx = 'https://download.pytorch.org/whl/cpu'
  if(Get-Command nvidia-smi -ErrorAction SilentlyContinue){ $idx = 'https://download.pytorch.org/whl/cu128'; Say 'найдена видеокарта NVIDIA: PyTorch с CUDA' }
  else { Say 'видеокарты NVIDIA нет: PyTorch для процессора (озвучка медленнее реального времени)' }
  if($env:W420_TORCH_INDEX){ $idx = $env:W420_TORCH_INDEX }
  RunArgs $vpy '-m' 'pip' 'install' 'torch>=2.2,<2.9' 'torchaudio>=2.2,<2.9' '--index-url' $idx
  RunArgs $vpy '-m' 'pip' 'install' '-r' (Join-Path $PSScriptRoot 'tts-server\requirements.txt')
  RunArgs $vpy '-c' "import TTS, torch; print('XTTS OK, CUDA:', torch.cuda.is_available())"
  $cfg = @{ python = $vpy; dir = (Join-Path $PSScriptRoot 'tts-server'); port = 8420 } | ConvertTo-Json
  $dir = Join-Path $env:USERPROFILE '.w420'
  if($DryRun){ Write-Host "  [dry-run] write $dir\tts.json" }
  else {
    New-Item -ItemType Directory -Force $dir | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $dir 'tts.json'), $cfg, (New-Object System.Text.UTF8Encoding($false)))
  }
  if($AcceptXttsLicense){
    Say 'скачиваю модель XTTS-v2 (лицензия CPML принята параметром -AcceptXttsLicense)'
    $env:COQUI_TOS_AGREED = '1'
    try { RunArgs $vpy '-c' "from TTS.api import TTS; TTS('tts_models/multilingual/multi-dataset/xtts_v2', progress_bar=True)" } finally { Remove-Item Env:COQUI_TOS_AGREED -ErrorAction SilentlyContinue }
  } else { Say 'модель скачается при первом запуске движка в приложении (после подтверждения лицензии)' }
}
if(-not (Get-Command winget -ErrorAction SilentlyContinue)){ throw 'winget не найден. Обнови "Установщик приложений" из Microsoft Store и запусти снова.' }

Write-Host @"
План:
  1. Visual Studio Build Tools (C++), WebView2 Runtime
  2. Rust (rustup, toolchain stable-msvc)
  3. Node.js LTS
  4. $(if($WithNetwork){'Tailscale (Tor на Windows поставь вручную позже)'}else{'сеть пропущена: добавь -WithNetwork'})
  5. конфиги: w420.config.json, rust-toolchain.toml, .gitignore
  6. npm install и генерация иконок
  7. ярлыки на рабочем столе и в меню Пуск
  8. голосовой движок XTTS (только с -WithTts: Python, PyTorch<2.9, coqui-tts, 3-7 ГБ; -AcceptXttsLicense принимает лицензию CPML (только некоммерческое использование) и скачивает модель 1,8 ГБ)
Установка Build Tools покажет запрос UAC и займёт несколько гигабайт.
"@
if(-not $Yes -and -not $DryRun){ if((Read-Host 'Продолжить? [y/N]') -notmatch '^[Yy]$'){ exit 0 } }

Say '1/6 Build Tools и WebView2'
Winget 'Microsoft.VisualStudio.2022.BuildTools' '--override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"'
Winget 'Microsoft.EdgeWebView2Runtime'
Say '2/6 Rust'
Winget 'Rustlang.Rustup'
RefreshPath
Run 'rustup toolchain install stable-msvc --profile minimal'
Run 'rustup default stable-msvc'
if(-not $DryRun){ $v=(rustc --version).Split(' ')[1]; if([version]($v -replace '-.*','') -lt [version]'1.90.0'){ throw "Rust слишком старый ($v), нужен 1.90+. Выполни: rustup update stable-msvc" } }
Say '3/6 Node.js'
Winget 'OpenJS.NodeJS.LTS'
RefreshPath
Say '4/6 сеть'
if($WithNetwork){ Winget 'Tailscale.Tailscale' } else { Say 'пропущено' }

Say '5/6 конфиги'
$map = @{ 'config\w420.config.json'='app\w420.config.json'; 'config\rust-toolchain.toml'='app\src-tauri\rust-toolchain.toml'; 'config\gitignore'='app\.gitignore' }
foreach($k in $map.Keys){
  if(Test-Path $map[$k]){ Say "уже есть: $($map[$k]) (не трогаю)" }
  elseif($DryRun){ Write-Host "  [dry-run] copy $k -> $($map[$k])" }
  else { Copy-Item $k $map[$k] }
}

Say '6/6 зависимости и иконки'
Say 'встроенные движки моста: sing-box (проверка SHA-256)'
Run 'node tools/fetch-sidecars.mjs'
Push-Location app
try{
  Run 'npm install --no-fund --no-audit'
  if(-not (Test-Path 'src-tauri\icons\icon.ico')){ Run 'npx tauri icon ..\assets\app-icon.png' }
  if($Build){ Say 'сборка (несколько минут)'; Run 'npm run tauri build' }
} finally { Pop-Location }
if($WithTts -or $AcceptXttsLicense){ SetupTts }
if(-not $NoShortcut){ Say 'ярлыки'; MakeShortcut }
if($Dev){ Push-Location app; try{ Run 'npm run tauri dev' } finally { Pop-Location } }
elseif($Build){ Say 'готово: ярлык ведёт на собранное приложение' }
else { Say 'готово. Запуск: ярлык "Windows 420" на рабочем столе (или install.bat -Dev)' }
