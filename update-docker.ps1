param(
    [switch]$Prune
)

$ErrorActionPreference = "Stop"

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    Write-Host "`n==> $Message" -ForegroundColor Cyan
    & $Command
}

$composeFile = Join-Path $PSScriptRoot "docker-compose.yml"
$envFile = Join-Path $PSScriptRoot ".env"

if (-not (Test-Path -LiteralPath $composeFile)) {
    throw "docker-compose.yml was not found next to this script."
}

if (-not (Test-Path -LiteralPath $envFile)) {
    throw ".env was not found. Copy .env.example to .env and set APP_SECRET first."
}

Set-Location -LiteralPath $PSScriptRoot

Invoke-Step "Checking Docker Compose" {
    docker compose version
}

Invoke-Step "Pulling upstream images" {
    docker compose pull --ignore-buildable
}

Invoke-Step "Building IMAP SpamKiller image" {
    docker compose build --pull app worker
}

Invoke-Step "Recreating containers" {
    docker compose up -d --remove-orphans
}

Invoke-Step "Current container status" {
    docker compose ps
}

if ($Prune) {
    Invoke-Step "Removing unused Docker images" {
        docker image prune -f
    }
}

Write-Host "`nDocker update complete. Open http://localhost:8080 or your NAS IP on port 8080." -ForegroundColor Green
