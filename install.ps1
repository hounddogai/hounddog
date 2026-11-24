# Installs the HoundDog.ai CLI on Windows from its GitHub releases, or from HoundDog.ai's copy of them on Google Cloud
# when GitHub does not answer, in PowerShell. The latest release:
#
#   irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1 | iex
#
# Or a version, which then stays: it turns the CLI's automatic updates off, and installing the latest release turns
# them on again:
#
#   $Script = irm https://raw.githubusercontent.com/hounddogai/hounddog/main/install.ps1
#   & ([scriptblock]::Create($Script)) -Version 4.0.0
#
# The CLI installs to %LOCALAPPDATA%\hounddog\bin, or to HOUNDDOG_INSTALL_DIR, and the folder goes first on the user's
# PATH. A folder named bin also keeps each version in versions\<version> beside it and names the current one in
# bin\current, the layout that `hounddog update` keeps current; another folder holds just the binary. Run as an
# administrator, the script installs the CLI for every user, in %ProgramFiles%\hounddog\bin, first on the system's
# PATH, and that CLI never updates itself: running this script again as an administrator upgrades it. An
# administrator's install in a folder outside Program Files, as HOUNDDOG_INSTALL_DIR may name, is installed as a user's is.
# Releases have builds for Windows on amd64 and arm64, named hounddog-windows-<arch>.exe, and a SHA256SUMS file that
# each download must match before it replaces the installed CLI. Linux and macOS install with install.sh instead.
#
# HOUNDDOG_RELEASES_URL replaces https://github.com/hounddogai/hounddog/releases, and HOUNDDOG_RELEASES_MIRROR_URL the
# copy, https://storage.googleapis.com/hounddog-releases. Each serves the same paths, as a test's server does:
# <url>/latest/download/<file> and <url>/download/<version>/<file>.

# The installation runs in a script block of its own, so that iex leaves no variables or preferences behind in the
# session that runs it.
& {
    param([object[]]$Arguments)

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    # The progress bar slows downloads in Windows PowerShell several times over.
    $ProgressPreference = 'SilentlyContinue'

    $Scripts = 'https://raw.githubusercontent.com/hounddogai/hounddog/main'
    $Version = ''
    $IsVersionGiven = $false
    for ($Index = 0; $Index -lt $Arguments.Count; $Index++) {
        $Argument = [string]$Arguments[$Index]
        if ($Argument -in @('-Version', '-v', '--version')) {
            if ($Index + 1 -ge $Arguments.Count) {
                throw "$Argument needs a version, such as $Argument 1.2.3."
            }
            $Index++
            $Version = [string]$Arguments[$Index]
            $IsVersionGiven = $true
        } elseif ($Argument -in @('-Help', '-h', '--help')) {
            Write-Host "Usage: & ([scriptblock]::Create((irm $Scripts/install.ps1))) [-Version <version>]"
            Write-Host ''
            Write-Host '  -v, -Version <version>  Install a specific version, such as 1.2.3 or 1.2.3-beta.1,'
            Write-Host '                          and turn automatic updates off. Without it, the script'
            Write-Host '                          installs the latest release.'
            Write-Host '  -h, -Help               Show this help.'
            return
        } else {
            throw "Unknown option: $Argument`nRun with -Help to see the options."
        }
    }
    # Bold marks the title and the commands to copy, in a console that shows it.
    $Bold = ''
    $Reset = ''
    if (-not [Console]::IsOutputRedirected -and $Host.UI.SupportsVirtualTerminal -and -not $env:NO_COLOR) {
        $Bold = "$([char]27)[1m"
        $Reset = "$([char]27)[0m"
    }
    # A version is a release's tag, such as 1.2.3 or 1.2.3-beta.1. \z ends the match at the very end, where $ would
    # also allow a line break.
    if ($IsVersionGiven -and $Version -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?\z') {
        throw "$Version is not a version of HoundDog.ai CLI.`nA version looks like 1.2.3 or 1.2.3-beta.1."
    }
    if ($env:OS -ne 'Windows_NT') {
        $Command = "curl -fsSL $Scripts/install.sh | sh"
        if ($Version) {
            $Command += " -s -- --version $Version"
        }
        throw "This script installs HoundDog.ai CLI on Windows.`nOn Linux and macOS, run:`n  $Command"
    }
    # A 32-bit PowerShell on 64-bit Windows finds the computer's architecture in PROCESSOR_ARCHITEW6432.
    $Machine = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $Arch = switch ($Machine) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { throw "HoundDog.ai CLI runs on AMD64 and ARM64.`nThis computer is $Machine." }
    }
    $Releases = 'https://github.com/hounddogai/hounddog/releases'
    if ($env:HOUNDDOG_RELEASES_URL) {
        $Releases = $env:HOUNDDOG_RELEASES_URL.TrimEnd('/')
    }
    $Mirror = 'https://storage.googleapis.com/hounddog-releases'
    if ($env:HOUNDDOG_RELEASES_MIRROR_URL) {
        $Mirror = $env:HOUNDDOG_RELEASES_MIRROR_URL.TrimEnd('/')
    }
    if ($Version) {
        $Folder = "download/$Version"
        $Release = "HoundDog.ai CLI $Version"
    } else {
        $Folder = 'latest/download'
        $Release = 'the latest HoundDog.ai CLI release'
    }
    $Asset = "hounddog-windows-$Arch.exe"

    # Downloads SHA256SUMS to $Sums, and this computer's build to $Download, from the releases at $Source. Answers
    # nothing when both arrive, or else the HTTP status of the first that did not, 0 when no server answered, its name,
    # and the error. A server error or a timeout is tried again, three times, waiting a second, then two, then four,
    # since GitHub sometimes answers with one for a moment, and Windows PowerShell's Invoke-WebRequest cannot retry.
    function Get-Release([string]$Source) {
        foreach ($Name in @('SHA256SUMS', $Asset)) {
            $Path = if ($Name -eq 'SHA256SUMS') { $Sums } else { $Download }
            for ($Attempt = 1; ; $Attempt++) {
                try {
                    Invoke-WebRequest -Uri "$Source/$Folder/$Name" -OutFile $Path -UseBasicParsing
                    break
                } catch {
                    $Response = $_.Exception.PSObject.Properties['Response']
                    $Status = if ($Response -and $Response.Value) { [int]$Response.Value.StatusCode } else { 0 }
                    $IsTransient = ($Status -eq 0) -or ($Status -eq 408) -or ($Status -eq 429) -or ($Status -ge 500)
                    if (-not $IsTransient -or $Attempt -gt 3) {
                        return [pscustomobject]@{ Status = $Status; Name = $Name; Message = $_.Exception.Message }
                    }
                    Start-Sleep -Seconds ([math]::Pow(2, $Attempt - 1))
                }
            }
        }
    }

    $Identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $IsAdministrator = $Identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $Directory = $env:HOUNDDOG_INSTALL_DIR
    if (-not $Directory -and $IsAdministrator) {
        $Directory = Join-Path $env:ProgramFiles 'hounddog\bin'
    } elseif (-not $Directory) {
        $Directory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'hounddog\bin'
    }
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    $Directory = (Resolve-Path -LiteralPath $Directory).ProviderPath
    # A drive's root keeps its separator, since C: alone names the drive's current folder.
    if ($Directory -notmatch '^[A-Za-z]:\\$') {
        $Directory = $Directory.TrimEnd('\')
    }
    # A semicolon splits a PATH's folders, and Windows reads %NAME% in one as a variable.
    if ($Directory -match '[;%]') {
        throw "The install folder cannot contain a semicolon or a percent sign because it goes on your PATH:`n" +
            "  $Directory`nSet HOUNDDOG_INSTALL_DIR to another folder."
    }
    # Windows PowerShell, and PowerShell before 7.1, read the file a download goes to as a wildcard pattern, in which
    # brackets stand for one of the characters between them, so the download would find no file to write. No Windows
    # user name has brackets, so the default folders never do. Downloading into memory instead, to write the file with
    # .NET, would hold several copies of the CLI in memory at once.
    if ($Directory -match '[\[\]]') {
        throw "The install folder cannot contain square brackets:`n" +
            "  $Directory`nSet HOUNDDOG_INSTALL_DIR to another folder."
    }
    $Binary = Join-Path $Directory 'hounddog.exe'
    # One installation into the folder at a time, so none deletes the files another is using. The lock file goes when
    # its handle closes, also when PowerShell ends.
    try {
        # Typed arguments, since PowerShell would read the options as a Boolean and pick another constructor.
        $Lock = [IO.FileStream]::new((Join-Path $Directory '.hounddog.lock'), [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None, 1, [IO.FileOptions]::DeleteOnClose)
    } catch {
        $Cause = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
        # 32 is ERROR_SHARING_VIOLATION: another installation holds the lock.
        if (($Cause.HResult -band 0xFFFF) -eq 32) {
            throw "Another installation of HoundDog.ai CLI into $Directory is running.`nRun this again once that installation ends."
        }
        throw
    }
    # Download beside the destination and rename, so a failed download never replaces a working CLI.
    $Download = Join-Path $Directory ".hounddog-$([Guid]::NewGuid().ToString('N')).exe"
    $Sums = Join-Path $Directory ".hounddog-$([Guid]::NewGuid().ToString('N')).sums"
    # Windows PowerShell offers servers only TLS 1.0 and older unless the system's settings say otherwise, and GitHub
    # refuses them, so TLS 1.2 is offered too while the CLI downloads. The system's default, 0, which older .NET
    # releases have no name for and PowerShell 7 uses, offers it already.
    $Protocols = [Net.ServicePointManager]::SecurityProtocol
    try {
        if ([int]$Protocols -ne 0) {
            [Net.ServicePointManager]::SecurityProtocol = $Protocols -bor [Net.SecurityProtocolType]::Tls12
        }
        # What an earlier installation left: a CLI that was running as it was replaced, or a download it did not finish.
        Get-ChildItem -LiteralPath $Directory -Filter '.hounddog-*' -Force |
            Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "${Bold}Installing HoundDog.ai CLI...$Reset"
        Write-Host ''
        $Source = $Releases
        $Failure = Get-Release $Releases
        # Both files come from one place, so they belong to the same release. GitHub answering that a file is missing
        # settles it, and any other failure turns to the copy.
        if ($Failure -and $Failure.Status -ne 404) {
            Write-Host 'Could not download from GitHub. Trying the mirror on Google Cloud instead.'
            Write-Host ''
            $Source = $Mirror
            $Failure = Get-Release $Mirror
        }
        if ($Failure -and $Failure.Status -eq 404 -and $Failure.Name -eq 'SHA256SUMS') {
            throw "Cannot find $Release.`nSee releases at:`n  $Releases"
        }
        if ($Failure -and $Failure.Status -eq 404) {
            throw "There is no build for Windows on $Arch in $Release.`nSee releases at:`n  $Releases"
        }
        if ($Failure) {
            throw "Cannot download:`n  $Source/$Folder/$($Failure.Name)`n$($Failure.Message)"
        }
        # SHA256SUMS lists each file as <checksum>  <name>, or <checksum> *<name> in binary mode.
        $Expected = $null
        foreach ($Line in Get-Content -LiteralPath $Sums) {
            if ($Line -match '^([0-9A-Fa-f]{64}) [ *](.+)$' -and $Matches[2] -ceq $Asset) {
                $Expected = $Matches[1]
                break
            }
        }
        if (-not $Expected) {
            throw "SHA256SUMS of $Release has no checksum for $Asset."
        }
        # -ne compares regardless of case, since Get-FileHash answers in upper case.
        if ((Get-FileHash -LiteralPath $Download -Algorithm SHA256).Hash -ne $Expected) {
            throw "The download of $Asset does not match its checksum in SHA256SUMS.`n" +
                "The installed CLI is unchanged.`n" +
                'Run this again. If it keeps failing, something on the network may be changing downloads.'
        }
        # Windows cannot replace a program while it runs, such as the CLI a coding agent runs as its MCP server, but it
        # can rename it. The running CLI moves aside, and the next installation deletes it.
        $Previous = $null
        if (Test-Path -LiteralPath $Binary) {
            $Previous = Join-Path $Directory ".hounddog-$([Guid]::NewGuid().ToString('N')).old"
            Move-Item -LiteralPath $Binary -Destination $Previous
        }
        try {
            Move-Item -LiteralPath $Download -Destination $Binary
        } catch {
            if ($Previous) {
                Move-Item -LiteralPath $Previous -Destination $Binary
            }
            throw
        }
        if ($Previous) {
            Remove-Item -LiteralPath $Previous -Force -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item -LiteralPath $Download, $Sums -Force -ErrorAction SilentlyContinue
        [Net.ServicePointManager]::SecurityProtocol = $Protocols
        $Lock.Dispose()
    }
    # The release a download of the latest one is, as the CLI tells it, such as `4.0.0`.
    if (-not $Version) {
        try {
            $Told = @(& $Binary --version 2> $null)
            if ($Told.Count -gt 0 -and "$($Told[0])" -match '(\S+)\s*$') {
                $Version = $Matches[1]
            }
        } catch {
            # A CLI that does not run on this computer tells no release, and the summary names the latest instead.
        }
    }
    $Cli = if ($Version) { "HoundDog.ai CLI $Version" } else { 'the latest HoundDog.ai CLI' }
    # A folder for every user, which only an administrator may change, never updates itself. ProgramData is not one: a
    # folder made there lets every user add files, so on the system's PATH it would run any program one put there.
    $IsShared = $false
    foreach ($Shared in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432)) {
        if ($Shared -and $Directory.StartsWith($Shared.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
            $IsShared = $true
        }
    }
    # The note on automatic updates for the summary.
    $Updates = $null
    # The layout `hounddog update` keeps current, beside a folder named bin: it copies a newer version into bin and
    # renames the running copy aside, as this script does.
    if (-not $IsShared -and $Version -match '^[0-9A-Za-z.-]+$' -and (Split-Path -Leaf $Directory) -eq 'bin') {
        $Kept = Join-Path (Join-Path (Split-Path -Parent $Directory) 'versions') $Version
        New-Item -ItemType Directory -Path $Kept -Force | Out-Null
        Copy-Item -LiteralPath $Binary -Destination (Join-Path $Kept 'hounddog.exe') -Force
        Set-Content -LiteralPath (Join-Path $Directory 'current') -Value $Version -NoNewline -Encoding ascii
        # A given version stays until the user asks for another, so it turns automatic updates off, and installing the
        # latest release turns them on again. A release too old to have automatic updates refuses the command.
        $Settings = Join-Path (Split-Path -Parent $Directory) 'settings.json'
        $Automatic = $null
        if ($IsVersionGiven) {
            $Automatic = 'off'
        } elseif ((Test-Path -LiteralPath $Settings -PathType Leaf) -and
            (Select-String -LiteralPath $Settings -SimpleMatch '"automatic": false' -Quiet)) {
            $Automatic = 'on'
        }
        if ($Automatic) {
            # Windows PowerShell stops at a program's error output while errors stop the script.
            $Preference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & $Binary update --auto $Automatic *> $null
                $IsSwitched = $LASTEXITCODE -eq 0
            } catch {
                $IsSwitched = $false
            } finally {
                $ErrorActionPreference = $Preference
            }
            if ($IsSwitched -and $Automatic -eq 'off') {
                $Updates = "Automatic updates are off. The CLI stays at $Version. To turn them on, run: hounddog update --auto on"
            } elseif ($IsSwitched) {
                $Updates = 'Automatic updates are on again.'
            }
        }
    } else {
        # A binary whose version is unknown must not pass for the one bin\current names.
        Remove-Item -LiteralPath (Join-Path $Directory 'current') -Force -ErrorAction SilentlyContinue
        if ($IsShared) {
            $Updates = 'It is installed for all users and does not update itself. To upgrade it, run this script again as an administrator.'
        }
    }
    # The folder as the summary names it, from %LOCALAPPDATA% when it is there, which reads shorter.
    $LocalAppData = [Environment]::GetFolderPath('LocalApplicationData').TrimEnd('\')
    $Shown = $Directory
    if ($Shown.StartsWith("$LocalAppData\", [StringComparison]::OrdinalIgnoreCase)) {
        $Shown = '%LOCALAPPDATA%' + $Shown.Substring($LocalAppData.Length)
    }
    Write-Host "Downloaded and verified $Cli for Windows ($Arch)."
    Write-Host "Installed binary at $(Join-Path $Shown 'hounddog.exe')."
    if ($Updates) {
        Write-Host $Updates
    }

    # The folder goes first on the PATH, the system's for a folder for every user and the user's otherwise, which the
    # registry holds with its variables unexpanded, such as %USERPROFILE%, and which they keep. Terminals opened from
    # now on find the CLI, and so does this session.
    $IsOther = { param($Entry) $Entry -and $Entry.TrimEnd('\') -ine $Directory.TrimEnd('\') }
    $Scope = if ($IsShared) { 'Machine' } else { 'User' }
    $Key = if ($IsShared) {
        [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment')
    } else {
        [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    }
    try {
        $StoredPath = [string]$Key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
        $NewPath = (@($Directory) + @($StoredPath.Split(';') | Where-Object { & $IsOther $_ })) -join ';'
        if ($NewPath -ne $StoredPath) {
            # A PATH stored as plain text stays plain, so a % in one of its folders' names keeps meaning a %.
            $Kind = if ($Key.GetValueNames() -contains 'Path') { $Key.GetValueKind('Path') } else { 'ExpandString' }
            $Key.SetValue('Path', $NewPath, $Kind)
            # Setting a variable through .NET tells running programs, such as Explorer, that the environment changed,
            # so the terminals they open read the new PATH.
            $Notice = "HOUNDDOG_$([Guid]::NewGuid().ToString('N'))"
            [Environment]::SetEnvironmentVariable($Notice, '1', $Scope)
            [Environment]::SetEnvironmentVariable($Notice, [NullString]::Value, $Scope)
            Write-Host "Added $Shown to your PATH."
        }
    } finally {
        $Key.Dispose()
    }
    $env:Path = (@($Directory) + @($env:Path.Split(';') | Where-Object { & $IsOther $_ })) -join ';'

    # This session finds the CLI too, so the next steps need no new terminal.
    Write-Host ''
    Write-Host 'HoundDog.ai CLI is installed. Next:'
    Write-Host ''
    Write-Host '  Scan a repository, from its root folder:'
    Write-Host ''
    Write-Host "     ${Bold}hounddog scan$Reset"
    Write-Host ''
    Write-Host '  To upload the results, set HOUNDDOG_API_KEY to a HoundDog.ai API key.'
} $args
