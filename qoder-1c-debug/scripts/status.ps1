# Check whether the 1c-debug MCP server is up and whether dbgs.exe answers.
# Exit code: 0 = server up and dbgs alive, 1 = server up but dbgs down, 2 = server not running.
# ASCII only: Windows PowerShell 5.1 reads a UTF-8 file without BOM as ANSI and Cyrillic
# literals break the parser.
param(
    [int]$Port = 8123,
    [int]$DbgPort = 1550
)

function Test-TcpPort([string]$h, [int]$p, [int]$ms) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $wait = $client.BeginConnect($h, $p, $null, $null)
        if ($wait.AsyncWaitHandle.WaitOne($ms)) { return $client.Connected }
        return $false
    } catch { return $false } finally { $client.Close() }
}

$mcpUp = $false
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -UseBasicParsing -TimeoutSec 5
    $json = $resp.Content | ConvertFrom-Json
    $mcpUp = [bool]$json.tools
    Write-Output ("mcp      : up, server=" + $json.server.name + " " + $json.server.version +
                  ", tools=" + $json.tools.Count)
} catch {
    Write-Output "mcp      : NOT running (start with scripts/start-server.ps1)"
}

$dbgs = Test-TcpPort '127.0.0.1' $DbgPort 2000
Write-Output ("dbgs:" + $DbgPort + " : " + $(if ($dbgs) { 'listening' } else { 'no listener (is ragent started with -debug?)' }))

if (-not $mcpUp) { exit 2 }
if (-not $dbgs) { exit 1 }
exit 0
