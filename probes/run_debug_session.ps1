# Launch a thin-client session in DEBUG mode so it registers itself as a debug target
# with the debug server (1cv8c.exe understands /DEBUG and /DEBUGGERURL; the strings are
# in 1cv8c.exe/1cv8.exe, and rserver.dll has _$Debug$_.DebugTargetAttach).
#
# Credentials come from HKCU\Environment (V8_DB_USER / V8_DB_PASS) and are never echoed:
# only the masked command line and the PID are printed.
#
# -Base  connection string, e.g. "srv01/mydb" or a file path; default $env:V8_BASE
# -Exe   1cv8c.exe path; default $env:V8_CLIENT_EXE or the 8.5 default install path
param(
    [switch] $NoDebug,
    [string] $ExtraArgs = '',
    [string] $Base = $(if ($env:V8_BASE) { $env:V8_BASE } else { 'localhost/demo-base' }),
    [string] $Exe = $(if ($env:V8_CLIENT_EXE) { $env:V8_CLIENT_EXE } else { 'C:\Program Files\1cv8\8.5.1.1529\bin\1cv8c.exe' })
)
$ErrorActionPreference = 'Stop'

function Get-EnvReg([string]$name) {
    $line = reg query 'HKCU\Environment' /v $name 2>$null |
            Select-String -Pattern ('^\s*' + [regex]::Escape($name) + '\s+REG_SZ\s+(.*)$')
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    return $null
}

$user = Get-EnvReg 'V8_DB_USER'
$pass = Get-EnvReg 'V8_DB_PASS'
if (-not $user -or -not $pass) {
    Write-Output 'V8_DB_USER / V8_DB_PASS not found in HKCU\Environment'
    exit 1
}

$exe    = $Exe
# /DEBUG alone selects the TCP debugger engine, which dbgs.exe does not speak
# (error: «на сервере - http, в запускаемом приложении - tcp»). The engine is
# chosen by the scheme inside /DebuggerURL - see the "TCP protocol / StartDebugger
# / DebuggerURL / HTTP" string block in 1cv8c.exe.
$dbgUrl = if ($env:DEBUGGER_URL) { $env:DEBUGGER_URL } else { 'http://127.0.0.1:15999' }
$v8args = @('/S', $Base, "/N$user", "/P$pass")
if (-not $NoDebug) { $v8args += @('/DEBUG', "/DebuggerURL=$dbgUrl") }
if ($ExtraArgs) { $v8args += $ExtraArgs }

$p = Start-Process -FilePath $exe -ArgumentList $v8args -PassThru
Write-Output ('started: ' + ($p.StartInfo.Arguments -replace '/P\S+', '/P<masked>'))
Write-Output ("pid = {0}" -f $p.Id)
