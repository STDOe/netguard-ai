#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'
Set-PSDebug -Off

function Show-Usage {
    'Usage: netguard.ps1 {install|start|stop|restart|status|logs|doctor}'
    'Commands use the installation next to this script. Set NETGUARD_PORT in .env to change the port.'
}

# Capture Docker output because configuration and build failures can contain secrets.
function Invoke-Docker {
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $output = @(& $docker @args 2>$null)
    @{ Code = $LASTEXITCODE; Output = ($output -join "`n").TrimEnd() }
}

function Invoke-Compose {
    Invoke-Docker compose --project-directory $root --env-file $envFile -f $composeFile @args
}

function Test-PrivateConfig {
    $file = Get-Item -LiteralPath $envFile -Force
    if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw '.env must be a regular file in the installation directory.'
    }
    $security = Get-Acl -LiteralPath $envFile
    if ($security.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $user.Value) {
        throw 'Set the .env owner to your Windows account and restrict its ACL.'
    }
    foreach ($rule in $security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @($user.Value, 'S-1-5-18')) {
            throw 'Restrict .env access to your Windows account and SYSTEM. See docs/easy-install.md.'
        }
    }
}

function Read-Config {
    Test-PrivateConfig
    $values = @{}
    foreach ($line in [IO.File]::ReadAllLines($envFile)) {
        if ($line -match '^\s*($|#)') { continue }
        if ($line -cnotmatch '^(NETGUARD_[A-Z0-9_]+)=(.*)$') {
            throw 'Invalid .env syntax. Use one literal NETGUARD_NAME=value per line.'
        }
        $key = $Matches[1]
        $value = $Matches[2]
        if ($values.ContainsKey($key) -or $value -match '[$#]|^[\s"'' ]|\s$') {
            throw 'Invalid or duplicate .env setting. Use literal values without expansion or inline comments.'
        }
        $values[$key] = $value
    }
    if ($values.NETGUARD_ADMIN_TOKEN -cnotmatch '^[A-Za-z0-9_-]{43,128}$' -or
        $values.NETGUARD_VIEWER_TOKEN -cnotmatch '^[A-Za-z0-9_-]{43,128}$' -or
        $values.NETGUARD_ADMIN_TOKEN -ceq $values.NETGUARD_VIEWER_TOKEN) {
        throw '.env requires distinct, valid Admin and Viewer tokens.'
    }
    if ($values.NETGUARD_DEMO_MODE -and $values.NETGUARD_DEMO_MODE -cne 'true') {
        throw 'NETGUARD_DEMO_MODE must be true.'
    }
    if ($values.NETGUARD_PORT -and ($values.NETGUARD_PORT -cnotmatch '^[1-9][0-9]{0,4}$' -or
        [int]$values.NETGUARD_PORT -gt 65535)) {
        throw 'NETGUARD_PORT must be an integer from 1 to 65535.'
    }
    if ((Invoke-Compose config --quiet).Code -ne 0) {
        throw 'Docker Compose rejected the configuration. Check .env and docker-compose.yml.'
    }
    $values
}

function New-Token {
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        [BitConverter]::ToString($bytes).Replace('-', '').ToLowerInvariant()
    } finally { $rng.Dispose() }
}

function New-Config {
    $staging = Join-Path $root ('.env.' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        # No secrets are written until the staging directory has a private ACL.
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetOwner($user)
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($principal in @($user, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $staging -AclObject $acl
        $tokens = @{
            NETGUARD_ADMIN_TOKEN = New-Token
            NETGUARD_VIEWER_TOKEN = New-Token
            NETGUARD_HONEYPOT_SECRET = New-Token
        }
        if (@($tokens.Values | Sort-Object -Unique).Count -ne 3) {
            throw 'Could not generate independent installation tokens.'
        }
        $content = foreach ($line in [IO.File]::ReadAllLines($template)) {
            if ($line -cmatch '^(NETGUARD_(ADMIN_TOKEN|VIEWER_TOKEN|HONEYPOT_SECRET))=$') {
                $Matches[1] + '=' + $tokens[$Matches[1]]
            } else { $line }
        }
        $privateFile = Join-Path $staging 'config'
        [IO.File]::WriteAllLines($privateFile, [string[]]$content, [Text.UTF8Encoding]::new($false))
        # Protect the ACL explicitly so the file retains it when moved.
        $fileAcl = Get-Acl -LiteralPath $privateFile
        $fileAcl.SetOwner($user)
        $fileAcl.SetAccessRuleProtection($true, $true)
        Set-Acl -LiteralPath $privateFile -AclObject $fileAcl
        [IO.File]::Move($privateFile, $envFile)
    } catch {
        throw 'Could not create a private .env. Use a writable NTFS directory or retry if another installer ran.'
    } finally { [IO.Directory]::Delete($staging, $true) }
}

function Test-OwnPort {
    (Invoke-Compose port netguard-app 8000).Output -ceq "127.0.0.1:${port}"
}

function Test-Port {
    if (Test-OwnPort) { return $true }
    $socket = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $port)
    $socket.ExclusiveAddressUse = $true
    try {
        $socket.Start()
        return $true
    } catch [Net.Sockets.SocketException] { return $false }
    finally { $socket.Stop() }
}

function Test-Image {
    $image = Invoke-Compose config --images netguard-app
    if ($image.Code -ne 0 -or -not $image.Output) { return $false }
    (Invoke-Docker image inspect $image.Output).Code -eq 0
}

function Show-Status {
    $id = Invoke-Compose ps -a -q netguard-app
    if ($id.Code -ne 0) { throw 'Could not inspect the NetGuard container.' }
    $parts = @('absent', 'none', '0', 'unknown')
    if ($id.Output) {
        $result = Invoke-Docker inspect --format '{{.State.Status}}/{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}/{{.State.ExitCode}}' $id.Output
        if ($result.Code -ne 0) { throw 'Could not inspect the NetGuard container.' }
        # Avoid embedded quotes in native arguments under Windows PowerShell 5.1.
        $label = Invoke-Docker inspect --format '{{json .Config.Labels}}' $id.Output
        $appVersion = 'unknown'
        if ($label.Code -eq 0) {
            $labels = ConvertFrom-Json -InputObject $label.Output
            if ($labels.'org.opencontainers.image.version' -match '^[0-9]+\.[0-9]+\.[0-9]+$') {
                $appVersion = $labels.'org.opencontainers.image.version'
            }
        }
        $parts = @($result.Output -split '/') + @($appVersion)
    }
    $state, $health, $exitCode, $appVersion = $parts
    if ($state -eq 'running' -and $health -eq 'healthy' -and -not (Test-OwnPort)) {
        $health = 'port mismatch'
    }
    Write-Host "Container: $state (exit code $exitCode)"
    Write-Host "API readiness: $health"
    Write-Host "Application version: $appVersion"
    Write-Host "Dashboard: http://127.0.0.1:${port}/"
    Write-Host 'Demo Mode: true'
    return ($state -eq 'running' -and $health -eq 'healthy')
}

function Assert-Port { if (-not (Test-Port)) { throw "Port $port is in use. Stop the listener or change NETGUARD_PORT in .env." } }
function Stop-NetGuard {
    if ((Invoke-Compose stop netguard-app).Code -ne 0) { throw 'Could not stop NetGuard.' }
}

function Start-NetGuard($mode) {
    Assert-Port
    $result = Invoke-Compose up $mode --pull never --wait --wait-timeout 60 netguard-app
    $healthy = Show-Status
    if ($result.Code -ne 0 -or -not $healthy) {
        throw 'NetGuard did not become ready. Run logs to check build, migration, or startup errors.'
    }
}

$exitCode = 0
$inherited = @{}
try {
    $action = $args[0]
    if ($args.Count -eq 0 -or $action -cin @('-h', '--help')) { Show-Usage; exit 0 }
    if ($action -cnotin @('install','start','stop','restart','status','logs','doctor')) {
        Show-Usage
        throw 'Unknown command.'
    }
    if ($args.Count -ne 1) { throw 'This command takes no arguments.' }
    if ($env:OS -ne 'Windows_NT') { throw 'Use Windows PowerShell 5.1 or newer, or netguard.sh on Linux.' }
    $root = $PSScriptRoot
    $envFile = Join-Path $root '.env'
    $template = Join-Path $root '.env.example'
    $composeFile = Join-Path $root 'docker-compose.yml'
    if (-not [IO.File]::Exists($template) -or -not [IO.File]::Exists($composeFile)) {
        throw 'Run the script from a complete NetGuard checkout.'
    }

    foreach ($item in Get-ChildItem Env:) {
        if ($item.Name -match '^(NETGUARD_|COMPOSE_)') {
            $inherited[$item.Name] = $item.Value
            [Environment]::SetEnvironmentVariable($item.Name, $null, 'Process')
        }
    }
    $docker = (Get-Command docker -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $docker) { throw 'Install Docker Desktop with Linux containers and Compose v2, then retry.' }
    if ((Invoke-Docker --version).Code -ne 0) { throw 'Docker CLI failed. Repair the Docker installation.' }
    $composeVersion = Invoke-Docker compose version --short
    if ($composeVersion.Code -ne 0 -or $composeVersion.Output -notmatch '^v?2\.' -or
        (Invoke-Docker compose up --help).Output -notmatch '--wait-timeout') {
        throw 'Docker Compose v2 with --wait support is required.'
    }
    $endpoint = $env:DOCKER_HOST
    if (-not $endpoint -or $env:DOCKER_CONTEXT) {
        $endpoint = (Invoke-Docker context inspect --format '{{.Endpoints.docker.Host}}').Output
    }
    if ($endpoint -notmatch '^npipe:////\./pipe/') { throw 'Select a local Docker context.' }
    $daemon = Invoke-Docker info --format '{{.OSType}}'
    if ($daemon.Code -ne 0) { throw 'Docker daemon is unavailable. Start Docker and check your permissions.' }
    if ($daemon.Output -ne 'linux') { throw 'Docker must run Linux containers.' }
    if ($action -in @('status','doctor')) {
        "Platform: Windows"
        'Docker: available'
        "Compose: $($composeVersion.Output)"
    }

    $user = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $port = 8000
    if (-not (Test-Path -LiteralPath $envFile) -and
        -not (Get-Item -LiteralPath $envFile -Force -ErrorAction SilentlyContinue)) {
        switch ($action) {
            'install' {
                if (-not (Test-Port)) { throw 'Port 8000 is in use. Stop the listener before installing.' }
                New-Config
            }
            { $_ -in @('status','doctor') } {
                'Configuration: missing. Run install first.'
                'Image: unknown without configuration.'
                exit 1
            }
            default { throw 'Configuration is missing. Run install first.' }
        }
    }
    $config = Read-Config
    if ($config.NETGUARD_PORT) { $port = [int]$config.NETGUARD_PORT }

    switch ($action) {
        'install' {
            $mode = if (Test-Image) { '--no-build' } else { '--build' }
            Start-NetGuard $mode
            'For first sign-in, copy NETGUARD_ADMIN_TOKEN from your private .env in a local editor.'
        }
        { $_ -in @('start','restart') } {
            if (-not (Test-Image)) { throw 'NetGuard image is missing locally. Run install with registry access to build it.' }
            if ($action -eq 'restart') { Assert-Port; Stop-NetGuard }
            Start-NetGuard '--no-build'
        }
        'stop' {
            Stop-NetGuard
            'NetGuard stopped. SQLite data was retained.'
        }
        'status' { if (-not (Show-Status)) { $exitCode = 1 } }
        'logs' {
            $previousPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            $PSNativeCommandUseErrorActionPreference = $false
            try {
                $output = @(& $docker compose --project-directory $root --env-file $envFile -f $composeFile logs --no-color --tail 100 netguard-app 2>&1) -join "`n"
                if ($LASTEXITCODE -ne 0) { throw 'Could not read NetGuard logs.' }
            } finally { $ErrorActionPreference = $previousPreference }
            foreach ($key in $config.Keys) {
                if ($key -match 'TOKEN|SECRET|KEY|PASSWORD' -and $config[$key]) {
                    $output = $output.Replace($config[$key], '[REDACTED]')
                }
            }
            $output -creplace '(ngw\.)?[A-Za-z0-9_-]{43,}', '[REDACTED]'
        }
        'doctor' {
            'Configuration: valid'
            'Secrets: owner-only permissions'
            if (Test-Port) { "Port ${port}: available or in use by NetGuard" }
            else { "Port ${port}: occupied. Stop the listener or change NETGUARD_PORT in .env."; $exitCode = 1 }
            if (Test-Image) { 'Image: available locally' }
            else { 'Image: missing. Run install with registry access to build it.'; $exitCode = 1 }
            if (-not (Show-Status)) { 'Run start if stopped, or logs if startup failed.'; $exitCode = 1 }
        }
    }
} catch {
    [Console]::Error.WriteLine('Error: ' + $_.Exception.Message)
    $exitCode = 1
} finally {
    foreach ($name in $inherited.Keys) {
        [Environment]::SetEnvironmentVariable($name, $inherited[$name], 'Process')
    }
}
exit $exitCode
