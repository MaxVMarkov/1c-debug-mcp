# Start the 1c-debug MCP server (HTTP) in its own window.
# ASCII only - see the note in status.ps1.
param(
    [int]$Port = 8123,
    [switch]$Foreground
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$server = Join-Path (Split-Path -Parent $here) 'server\debug_mcp_http.py'
if (-not (Test-Path $server)) { Write-Output "not found: $server"; exit 1 }

$python = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $python) { Write-Output 'python is not on PATH'; exit 1 }

if ($Foreground) {
    & $python $server --port $Port
    exit $LASTEXITCODE
}

$proc = Start-Process -FilePath $python -ArgumentList @($server, '--port', $Port) -PassThru -WindowStyle Minimized
Write-Output "started pid=$($proc.Id) -> http://127.0.0.1:$Port/mcp"
Write-Output "stop it with: Stop-Process -Id $($proc.Id)"
