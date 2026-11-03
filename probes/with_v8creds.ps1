# Запуск команды с учётными данными 1С в окружении дочернего процесса.
# Значения читаются из HKCU\Environment и НИКОГДА не печатаются: наружу идёт только
# имя переменной. Сам разговор с базой (Basic-auth в OData/HTTP-сервисе) делает дочерний
# процесс, поэтому пароль не попадает ни в командную строку, ни в вывод.
#
# usage: powershell -File probes/with_v8creds.ps1 C:\Python314\python.exe probes\http_target_watch.py
$env:PYTHONIOENCODING = 'utf-8'
$ErrorActionPreference = 'Stop'

function Get-EnvReg([string]$name) {
    $line = reg query 'HKCU\Environment' /v $name 2>$null |
            Select-String -Pattern ('^\s*' + [regex]::Escape($name) + '\s+REG_SZ\s+(.*)$')
    if ($line) { return $line.Matches[0].Groups[1].Value.Trim() }
    return $null
}

foreach ($name in 'V8_DB_USER', 'V8_DB_PASS') {
    $value = Get-EnvReg $name
    if (-not $value) { Write-Output "в HKCU\Environment нет $name"; exit 1 }
    Set-Item -Path ("env:" + $name) -Value $value
    Write-Output "${name} подставлен (длина $($value.Length))"
}

if ($args.Count -eq 0) { Write-Output 'не указано, что запускать'; exit 1 }
& $args[0] @($args[1..($args.Count - 1)])
exit $LASTEXITCODE
