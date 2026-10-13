# Launch MTGA Tracker backend.
# Usage: .\run.ps1

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $here 'backend')

$venv = Join-Path (Get-Location) '.venv'
if (-not (Test-Path $venv)) {
    Write-Host 'Creating venv...'
    python -m venv .venv
    & (Join-Path $venv 'Scripts\python.exe') -m pip install --upgrade pip
    & (Join-Path $venv 'Scripts\python.exe') -m pip install -r requirements.txt
}

& (Join-Path $venv 'Scripts\python.exe') server.py
