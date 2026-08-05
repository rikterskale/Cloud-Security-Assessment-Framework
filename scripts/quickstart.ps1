# Safe source-checkout bootstrap for the offline CSAF demo.
[CmdletBinding()]
param([string]$Python = "py")
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root
& $Python -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-lock.txt
& .\.venv\Scripts\python.exe -m pip install --no-deps .
& .\.venv\Scripts\python.exe invoke_assessment.py --self-check --output-dir out
if ($LASTEXITCODE -eq 2) {
  Write-Host 'Self-check is intentionally INCOMPLETE (exit 2): one control is left untested. Setup succeeded.'
  exit 0
}
exit $LASTEXITCODE
