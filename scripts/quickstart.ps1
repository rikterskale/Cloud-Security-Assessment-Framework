# Delegate to the cross-platform installer.
[CmdletBinding()]
param(
  [string]$Python = "py",
  [Parameter(ValueFromRemainingArguments = $true)]
  [string[]]$InstallArgs
)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script = Join-Path $Root 'scripts\install.py'
if ($InstallArgs) {
  & $Python -3 $script @InstallArgs
} else {
  & $Python -3 $script
}
exit $LASTEXITCODE
