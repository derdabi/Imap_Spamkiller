param(
    [int]$BackendPort = 8080,
    [int]$FrontendPort = 5173,
    [string]$RspamdUrl = "http://localhost:11333",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

function Require-Command($Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command '$Name' was not found in PATH."
    }
}

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backend = Join-Path $Root "backend"
$Frontend = Join-Path $Root "frontend"
$DataDir = Join-Path $Root ".debug-data"
$Venv = Join-Path $Root ".venv"
$PythonExe = Join-Path $Venv "Scripts\python.exe"
$PipExe = Join-Path $Venv "Scripts\pip.exe"

Require-Command "python"
Require-Command "npm"

if (-not (Test-Path -LiteralPath $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir | Out-Null
}

if (-not (Test-Path -LiteralPath $Venv)) {
    python -m venv $Venv
}

if (-not $SkipInstall) {
    & $PythonExe -m pip install --upgrade pip
    & $PipExe install -r (Join-Path $Backend "requirements.txt")

    if (-not (Test-Path -LiteralPath (Join-Path $Frontend "node_modules"))) {
        npm --prefix $Frontend install
    }
}

$env:APP_SECRET = if ($env:APP_SECRET) { $env:APP_SECRET } else { "local-debug-change-me" }
$env:DATA_DIR = $DataDir
$env:STATIC_DIR = Join-Path $Frontend "dist"
$env:RSPAMD_URL = $RspamdUrl
$env:CORS_ALLOW_ORIGINS = "http://127.0.0.1:$FrontendPort,http://localhost:$FrontendPort"
$env:PYTHONPATH = $Backend

$BackendCommand = @"
`$env:APP_SECRET = '$($env:APP_SECRET)'
`$env:DATA_DIR = '$DataDir'
`$env:STATIC_DIR = '$($env:STATIC_DIR)'
`$env:RSPAMD_URL = '$RspamdUrl'
`$env:CORS_ALLOW_ORIGINS = 'http://127.0.0.1:$FrontendPort,http://localhost:$FrontendPort'
`$env:PYTHONPATH = '$Backend'
Set-Location -LiteralPath '$Backend'
& '$PythonExe' -m uvicorn spamkiller.main:app --host 127.0.0.1 --port $BackendPort --reload --log-level debug
"@

$FrontendCommand = @"
Set-Location -LiteralPath '$Frontend'
npm run dev -- --host 127.0.0.1 --port $FrontendPort
"@

Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $BackendCommand
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $FrontendCommand

Write-Host "Debug backend:  http://127.0.0.1:$BackendPort"
Write-Host "Debug frontend: http://127.0.0.1:$FrontendPort"
Write-Host "Rspamd URL:     $RspamdUrl"
Write-Host "Data directory: $DataDir"
Write-Host ""
Write-Host "Open the frontend URL. The Vite proxy forwards /api to the backend."
Write-Host "Use -SkipInstall on later runs to start faster."
