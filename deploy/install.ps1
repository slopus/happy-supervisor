# Installs happy-supervisor for this Windows user and joins it to a control plane. The supervisor
# runs as you and starts when you log on. Run in an elevated PowerShell (as administrator, signed
# in as the user it should run as): the sandbox's accounts and firewall filters need it once.
#
#   $env:HAPPY_JOIN_URL='<join url>'; $env:HAPPY_JOIN_TOKEN='<token>'
#   irm https://get.happy.engineering/install.ps1 | iex
#
# HAPPY_JOIN_URL is the full join endpoint the control plane handed out with the token;
# $env:HAPPY_NODE_NAME optionally names the computer. Windows has no workload user: commands run
# as you, sandboxed ones as the sandbox's accounts (docs/policy.md).
#
# Run it again without HAPPY_JOIN_TOKEN to upgrade a joined computer in place. That also runs
# install-sandbox again, which a release with a new sandbox install record needs.
# Uninstall (removes the task, the sandbox, the state and the binary):
#
#   $env:HAPPY_UNINSTALL='1'; irm https://get.happy.engineering/install.ps1 | iex
#
# Optional: HAPPY_SUPERVISOR_VERSION (default: the latest release), HAPPY_INSTALL_BASE. Before
# anything is written outside a temporary directory, the release's SHA256SUMS is checked against
# the release key below with a pinned minisign 0.12 release (its archive hash is fixed here), and
# the binary against SHA256SUMS.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Fail($message) { throw "happy-supervisor install: $message" }

# The release signing key (minisign key ID 349DDAD36F92423A).
$minisignKey = 'RWQ6QpJv09qdNGB9/hp7j8OjguWGLTtuvAO/d34LiFGJPzFtF2bkY1Lr'
$minisignUrl = 'https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-win64.zip'
$minisignSha256 = '37b600344e20c19314b2e82813db2bfdcc408b77b876f7727889dbd46d539479'
$base = if ($env:HAPPY_INSTALL_BASE) { $env:HAPPY_INSTALL_BASE } else { 'https://get.happy.engineering' }
$task = 'happy-supervisor'
$dir = Join-Path $env:ProgramFiles 'Happy'
$bin = Join-Path $dir 'happy-supervisor.exe'
$state = Join-Path $env:LOCALAPPDATA 'happy-supervisor'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run this in an elevated PowerShell (as administrator): the sandbox needs it once'
}

function Stop-Supervisor {
    if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    }
    Get-Process -Name 'happy-supervisor' -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -eq $bin } | Stop-Process -Force
}

if ($env:HAPPY_UNINSTALL -eq '1') {
    Stop-Supervisor
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $bin) {
        & $bin install-sandbox --uninstall
        if ($LASTEXITCODE -ne 0) { Fail "removing the sandbox failed ($LASTEXITCODE)" }
        Remove-Item -Force $bin
    }
    Remove-Item -Recurse -Force $state -ErrorAction SilentlyContinue
    Write-Host 'happy-supervisor uninstalled'
    return
}

$upgrade = Test-Path (Join-Path $state 'private\credentials.json')
if ($upgrade) {
    if ($env:HAPPY_JOIN_TOKEN) { Fail 'this computer has already joined; run this without HAPPY_JOIN_TOKEN to upgrade it, or uninstall first to join again' }
} else {
    if (-not $env:HAPPY_JOIN_URL) { Fail 'set $env:HAPPY_JOIN_URL to the join URL the control plane gave you (https://...)' }
    if (-not $env:HAPPY_JOIN_TOKEN) { Fail 'set $env:HAPPY_JOIN_TOKEN to the join token the control plane gave you' }
}
if ([Environment]::Is64BitOperatingSystem -ne $true -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    Fail "unsupported architecture $env:PROCESSOR_ARCHITECTURE"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$work = Join-Path ([IO.Path]::GetTempPath()) ("happy-supervisor-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $version = $env:HAPPY_SUPERVISOR_VERSION
    if (-not $version) {
        $version = (Invoke-RestMethod -UseBasicParsing "$base/releases/latest").ToString().Trim()
    }
    if ($version -notmatch '^[0-9A-Za-z.+-]+$') { Fail "bad version '$version'" }
    $file = 'happy-supervisor-windows-x86_64.exe'
    Write-Host "downloading happy-supervisor $version (windows-x86_64)"
    Invoke-WebRequest -UseBasicParsing "$base/releases/$version/SHA256SUMS" -OutFile (Join-Path $work 'SHA256SUMS')
    Invoke-WebRequest -UseBasicParsing "$base/releases/$version/SHA256SUMS.minisig" -OutFile (Join-Path $work 'SHA256SUMS.minisig')
    Invoke-WebRequest -UseBasicParsing "$base/releases/$version/$file" -OutFile (Join-Path $work $file)
    $archive = Join-Path $work 'minisign.zip'
    Invoke-WebRequest -UseBasicParsing $minisignUrl -OutFile $archive
    if ((Get-FileHash -Algorithm SHA256 $archive).Hash.ToLower() -ne $minisignSha256) { Fail 'checksum mismatch for minisign' }
    Expand-Archive -Path $archive -DestinationPath (Join-Path $work 'minisign')
    $minisign = Join-Path $work 'minisign\minisign-win64\x86_64\minisign.exe'
    & $minisign -Vqm (Join-Path $work 'SHA256SUMS') -x (Join-Path $work 'SHA256SUMS.minisig') -P $minisignKey
    if ($LASTEXITCODE -ne 0) { Fail 'SHA256SUMS is not signed by the release key' }
    $expected = $null
    foreach ($line in Get-Content (Join-Path $work 'SHA256SUMS')) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $file) { $expected = $parts[0].ToLower() }
    }
    if (-not $expected) { Fail "release $version has no Windows build" }
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $work $file)).Hash.ToLower()
    if ($actual -ne $expected) { Fail "checksum mismatch for $file" }

    # Verified: only now does anything reach Program Files.
    Stop-Supervisor
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -Force (Join-Path $work $file) $bin

    # Every run, so an upgrade brings the sandbox to the release's install record.
    & $bin install-sandbox
    if ($LASTEXITCODE -ne 0) { Fail "install-sandbox failed ($LASTEXITCODE)" }
    if (-not $upgrade) {
        # join reads the token from $env:HAPPY_JOIN_TOKEN, not the arguments, which anyone can list.
        $join = @('join', '--url', $env:HAPPY_JOIN_URL, '--state-dir', $state)
        if ($env:HAPPY_NODE_NAME) { $join += @('--name', $env:HAPPY_NODE_NAME) }
        & $bin @join
        if ($LASTEXITCODE -ne 0) { Fail "join failed ($LASTEXITCODE)" }
    }

    # Runs as this user at logon, not elevated, hidden, and restarts after a failure.
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $bin -Argument "run --state-dir `"$state`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Settings $settings `
        -Principal $taskPrincipal -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    if ($upgrade) { Write-Host "happy-supervisor upgraded to $version" }
    else { Write-Host "happy-supervisor $version is installed and running" }
}
finally {
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}
