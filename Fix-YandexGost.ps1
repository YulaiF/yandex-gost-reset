#requires -Version 5.1
<#
.SYNOPSIS
Сбрасывает сохранённые отказы от ГОСТ TLS в профилях текущего пользователя.
.PARAMETER Site
Точные имена хостов или HTTP(S)-адреса. Без параметра сбрасываются все записи.
.PARAMETER Profile
Имя папки профиля, например Default или Profile 1. По умолчанию проверяются все профили.
.PARAMETER WaitSeconds
Сколько секунд ждать завершения процессов после принудительного закрытия.
.PARAMETER ForceClose
Принудительно завершает Яндекс Браузер текущего пользователя в текущем сеансе.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [string[]] $Site,
    [string] $Profile,
    [switch] $ForceClose,
    [ValidateRange(1, 600)]
    [int] $WaitSeconds = 5
)

$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false, $true)

function ConvertTo-SiteHost {
    param([string] $Value)

    $valueText = $Value.Trim()
    if ($valueText -notmatch '^https?://') {
        if ($valueText -match '[/\\?#@: ]') { throw "Укажите имя хоста или URL с http:// либо https://." }
        $valueText = 'https://' + $valueText
    }
    $uri = $null
    if ($valueText -match '[\\\x00-\x20]' -or
        -not [Uri]::TryCreate($valueText, [UriKind]::Absolute, [ref] $uri) -or
        $uri.UserInfo -or $uri.HostNameType -notin @('Dns', 'IPv4', 'IPv6')) {
        throw 'Не удалось распознать хост. Укажите имя хоста или HTTP(S)-адрес.'
    }
    $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
}

function Get-JsonPropertyToken {
    param($Tokens, [int] $ObjectIndex, [string] $Name)

    $depth = 0
    $found = -1
    for ($i = $ObjectIndex + 1; $i -lt $Tokens.Count; $i++) {
        $token = $Tokens[$i].Value
        if ($token -in @('}', ']')) {
            if ($depth -eq 0) { break }
            $depth--
        } elseif ($token -in @('{', '[')) {
            $depth++
        } elseif ($depth -eq 0 -and $token.StartsWith('"') -and $Tokens[$i + 1].Value -eq ':') {
            # Decode escaped keys before comparing the exact property name.
            $key = $token.Substring(1, $token.Length - 2)
            if ($key.Contains('\')) { $key = ('{"key":' + $token + '}' | ConvertFrom-Json).key }
            if ($key -ceq $Name) {
                if ($found -ge 0) { throw "В Preferences несколько свойств $Name на одном уровне." }
                $found = $i + 2
            }
        }
    }
    $found
}

function Get-PreferencesChange {
    param([string] $Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $json = $utf8.GetString($bytes)
    if ($json.StartsWith([string] [char] 0xFEFF, [StringComparison]::Ordinal)) { $json = $json.Substring(1) }
    $config = ConvertFrom-Json -InputObject $json -ErrorAction Stop
    if ($json -notmatch '^\s*\{') { throw 'Ожидался JSON-объект Preferences.' }
    $gost = $config.PSObject.Properties | Where-Object Name -CEQ 'tlsgost'
    if (!$gost) { return }
    if ($gost.Value -isnot [pscustomobject]) { throw 'Свойство tlsgost имеет неизвестный формат.' }
    $list = $gost.Value.PSObject.Properties | Where-Object Name -CEQ 'bad_hosts'
    if (!$list) { return }
    if ($list.Value -isnot [array]) { throw 'Свойство tlsgost.bad_hosts должно быть массивом.' }

    $remaining = [Collections.Generic.List[string]]::new()
    foreach ($entry in $list.Value) {
        if ($entry -isnot [string]) { throw 'Массив tlsgost.bad_hosts содержит значение неизвестного формата.' }
        if ($targets.Count -eq 0) { continue }
        try { $entryHost = ConvertTo-SiteHost $entry } catch { $entryHost = $null }
        if (!$entryHost -or !$targets.Contains($entryHost)) {
            $remaining.Add($entry)
        }
    }
    $removedCount = $list.Value.Count - $remaining.Count
    if ($removedCount -eq 0) { return }

    # Locate the array in the original text so other settings retain their exact JSON representation.
    $tokens = [regex]::Matches($json, '"(?:[^"\\]|\\.)*"|[{}\[\]:,]')
    $gostIndex = Get-JsonPropertyToken $tokens 0 'tlsgost'
    if ($gostIndex -lt 0 -or $tokens[$gostIndex].Value -ne '{') { throw 'Не удалось найти объект tlsgost в JSON.' }
    $listIndex = Get-JsonPropertyToken $tokens $gostIndex 'bad_hosts'
    if ($listIndex -lt 0 -or $tokens[$listIndex].Value -ne '[') { throw 'Не удалось найти массив bad_hosts в JSON.' }
    $first = $tokens[$listIndex].Index
    $endToken = $tokens[$listIndex + 2 * $list.Value.Count]
    if ($endToken.Value -ne ']') { throw 'Не удалось определить границу массива bad_hosts.' }
    $newList = ConvertTo-Json -InputObject ($remaining.ToArray()) -Compress
    $updated = $json.Substring(0, $first) + $newList + $json.Substring($endToken.Index + 1)
    $null = ConvertFrom-Json -InputObject $updated -ErrorAction Stop

    [pscustomobject] @{ Text = $updated; Original = $bytes; RemovedCount = $removedCount }
}

function Test-BrowserRunning {
    param([switch] $OtherSessionsOnly)

    $runningBrowsers = @(Get-Process -Name browser -ErrorAction SilentlyContinue)
    if ($OtherSessionsOnly) { $runningBrowsers = @($runningBrowsers | Where-Object SessionId -NE $sessionId) }
    if (!$runningBrowsers) { return $false }
    if ($runningBrowsers.SessionId -contains $sessionId) { return $true }

    try {
        $otherSessions = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'browser.exe'")
    } catch {
        # An unidentified process in another session may belong to the same account.
        return $true
    }
    foreach ($process in $otherSessions) {
        if ($process.SessionId -eq $sessionId) {
            if ($OtherSessionsOnly) { continue }
            return $true
        }
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0 -or !$owner.Sid -or $owner.Sid -eq $userSid) { return $true }
        } catch {
            if (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue) { return $true }
        }
    }
    $false
}

function Stop-CurrentYandexBrowser {
    $verified = @(foreach ($process in Get-Process -Name browser -ErrorAction SilentlyContinue | Where-Object SessionId -EQ $sessionId) {
        try {
            # Keep the process handle open while verifying its identity and stopping it.
            $null = $process.Handle
            $instance = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)"
            if ($process.HasExited) { continue }
            $owner = Invoke-CimMethod -InputObject $instance -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $userSid -or
                $instance.SessionId -ne $sessionId -or
                $instance.ExecutablePath -notmatch '\\Yandex\\YandexBrowser\\Application\\(?:[^\\]+\\)?browser\.exe$') {
                throw "Не удалось подтвердить, что PID $($process.Id) принадлежит Яндекс Браузеру этого пользователя."
            }
            $process
        } catch {
            if (!$process.HasExited) { throw }
        }
    })
    foreach ($process in $verified) {
        try { $process.Kill() } catch { if (!$process.HasExited) { throw } }
    }
}

try {
    $targets = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($value in $Site) { [void] $targets.Add((ConvertTo-SiteHost $value)) }

    $userData = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Yandex\YandexBrowser\User Data'
    if (!(Test-Path -LiteralPath $userData -PathType Container)) { throw "Папка профилей Яндекс Браузера не найдена для $env:USERNAME." }
    $preferences = @(Get-ChildItem -LiteralPath $userData -Directory | Where-Object {
        !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (!$Profile -or $_.Name -ieq $Profile)
    } | ForEach-Object {
        $path = Join-Path $_.FullName 'Preferences'
        if (Test-Path -LiteralPath $path -PathType Leaf) { Get-Item -LiteralPath $path }
    } | Where-Object { !($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
    if (!$preferences) { throw 'Подходящие файлы Preferences не найдены. Проверьте имя папки профиля в browser://version.' }

    $failed = $false
    $matchesFound = @(foreach ($file in $preferences) {
        try {
            $change = Get-PreferencesChange $file.FullName
            if ($change) {
                Write-Host "$($file.Directory.Name) · найдено записей: $($change.RemovedCount)" -ForegroundColor Yellow
                $file
            }
        } catch {
            $failed = $true
            Write-Warning "$($file.Directory.Name) · $($_.Exception.Message)"
        }
    })
    if (!$matchesFound) {
        if ($failed) { exit 1 }
        Write-Host 'Подходящих записей для сброса нет.'
        exit 0
    }

    $approved = @($matchesFound | Where-Object {
        $PSCmdlet.ShouldProcess($_.Directory.Name, 'Сбросить найденные отказы от ГОСТ')
    })
    if (!$approved) { exit ([int] $failed) }

    $sessionId = (Get-Process -Id $PID).SessionId
    $userSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if (Test-BrowserRunning) {
        if (!$ForceClose) { Write-Warning 'Браузер работает. Выйдите через Ctrl+Shift+Q и повторите запуск.'; exit 2 }
        if (Test-BrowserRunning -OtherSessionsOnly) { Write-Warning 'Браузер работает в другом сеансе или владелец процесса неизвестен. Сброс отложен.'; exit 2 }
        Stop-CurrentYandexBrowser
        $timer = [Diagnostics.Stopwatch]::StartNew()
        while (($running = Test-BrowserRunning) -and $timer.Elapsed.TotalSeconds -lt $WaitSeconds) {
            Start-Sleep -Milliseconds 200
        }
        if ($running) { Write-Warning 'Браузер ещё работает. Проверьте фоновый режим и запустите скрипт снова.'; exit 2 }
    }

    $changed = $false
    $deferred = $false
    foreach ($file in $approved) {
        $lock = $null
        $temporary = $null
        try {
            $lock = [IO.FileStream]::new(($file.FullName + '.gost.lock'), [IO.FileMode]::CreateNew,
                [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
            $change = Get-PreferencesChange $file.FullName
            if (!$change) {
                Write-Host "$($file.Directory.Name) · сохранённых отказов больше нет."
                continue
            }

            $id = [Guid]::NewGuid().ToString('N')
            $temporary = $file.FullName + ".gost-$id.tmp"
            $backup = $file.FullName + ('.gost-{0:yyyyMMdd-HHmmss}-{1}.bak' -f (Get-Date), $id)
            [IO.File]::WriteAllText($temporary, $change.Text, $utf8)
            if (Test-BrowserRunning) {
                Write-Warning 'Браузер запущен. Для оставшихся профилей сброс отложен.'
                $deferred = $true
                break
            }
            $latest = [IO.File]::ReadAllBytes($file.FullName)
            if (![Collections.StructuralComparisons]::StructuralEqualityComparer.Equals($latest, $change.Original)) {
                throw 'Preferences изменился во время работы. Повторите запуск.'
            }
            [IO.File]::Replace($temporary, $file.FullName, $backup)
            Write-Host "$($file.Directory.Name) · сброшено записей: $($change.RemovedCount)" -ForegroundColor Green
            Write-Verbose "Резервная копия: $backup"
            $changed = $true
        } catch {
            $failed = $true
            Write-Warning "$($file.Directory.Name) · $($_.Exception.Message)"
        } finally {
            if ($lock) { $lock.Dispose() }
            if ($temporary) { Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue }
        }
    }
    if ($changed) { Write-Host 'Откройте сайт в нужном профиле и подтвердите подключение по ГОСТ.' }
    if ($failed) { exit 1 }
    if ($deferred) { exit 2 }
    exit 0
} catch {
    Write-Warning $_.Exception.Message
    exit 1
}
