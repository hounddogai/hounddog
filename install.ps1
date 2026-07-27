#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Version = $env:HOUNDDOG_VERSION
)

# Stop the script on errors.
$ErrorActionPreference = 'Stop'
# Disable progress bar for faster downloads.
$ProgressPreference = 'SilentlyContinue'

# GitHub requires TLS 1.2, which is not always enabled by default in Windows PowerShell 5.1.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = 'latest'
}

function Test-HoundDogVersionFormat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate
    )

    return $Candidate -match '^\d+\.\d+\.\d+(-(alpha|beta))?$'
}

function Get-PathWithEntryFirst {
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PathValue,

        [Parameter(Mandatory = $true)]
        [string]$Entry
    )

    $PathSeparators = [char[]]@('\', '/')
    $NormalizedEntry = $Entry.Trim().TrimEnd($PathSeparators)
    $RemainingEntries = @()
    if (-not [string]::IsNullOrWhiteSpace($PathValue)) {
        $RemainingEntries = @(
            $PathValue.Split(';') | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_) -and
                $_.Trim().TrimEnd($PathSeparators) -ine $NormalizedEntry
            }
        )
    }

    return (@($Entry) + $RemainingEntries) -join ';'
}

# Check CPU architecture.
$ProcessorArchitecture = if ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}
$Arch = switch ($ProcessorArchitecture.ToUpperInvariant()) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw 'Unsupported CPU architecture. HoundDog CLI requires an AMD64 or ARM64 processor.' }
}
$ReleaseRootUrl = "https://github.com/hounddogai/hounddog/releases"
$Version = $Version.Trim()
if ($Version -ne 'latest' -and -not (Test-HoundDogVersionFormat -Candidate $Version)) {
    throw "Invalid version '$Version'. Use x.y.z, x.y.z-alpha, or x.y.z-beta (without a leading 'v')."
}

$TagsToTry = if ($Version -eq 'latest') {
    @('latest')
} else {
    @($Version, "v$Version")
}
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
$PendingInstallPath = $null
$BackupInstallPath = $null

try {
    # Determine if running with admin privileges.
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Set installation path and PATH scope based on privileges.
    if ($IsAdmin) {
        # Admin: Install to Program Files and update System PATH.
        $InstallPath = Join-Path $env:ProgramFiles "hounddog\bin"
        $PathScope = "Machine"
        Write-Host "Installing HoundDog CLI for all users..."
    } else {
        # Non-admin: Install to user's local app data and update User PATH.
        $InstallPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'hounddog\bin'
        $PathScope = "User"
        Write-Host "Installing HoundDog CLI for current user only..."
    }

    # Create a temporary directory for downloading the ZIP archive.
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    # Download the ZIP archive and checksum file.
    $ZipPath = Join-Path $TempDir 'hounddog.zip'
    $ChecksumPath = Join-Path $TempDir 'hounddog.zip.sha256'
    $ResolvedTag = $null
    foreach ($Tag in $TagsToTry) {
        if ($Tag -eq 'latest') {
            $BaseDownloadUrl = "$ReleaseRootUrl/latest/download"
        } else {
            $BaseDownloadUrl = "$ReleaseRootUrl/download/$Tag"
        }

        Remove-Item -Path $ZipPath, $ChecksumPath -Force -ErrorAction SilentlyContinue
        $DownloadUrl = "$BaseDownloadUrl/hounddog-windows-$Arch.zip"
        Write-Host "Downloading ZIP from $DownloadUrl ..."
        try {
            Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
            Invoke-WebRequest -Uri "$DownloadUrl.sha256" -OutFile $ChecksumPath -UseBasicParsing
            $ResolvedTag = $Tag
            break
        } catch {
            continue
        }
    }

    if (-not $ResolvedTag) {
        throw "Failed to download HoundDog CLI version '$Version'. Ensure the release exists and uses x.y.z, x.y.z-alpha, or x.y.z-beta."
    }

    # Download the SHA256 checksum file and verify the integrity of the binary.
    Write-Host "Verifying checksum ..."
    $ChecksumContent = (Get-Content -Path $ChecksumPath -Raw).Trim()
    if ($ChecksumContent -notmatch '^(?<Hash>[0-9a-fA-F]{64})(?:\s|$)') {
        throw 'The downloaded checksum file is invalid.'
    }
    $ExpectedHash = $Matches.Hash
    $ActualHash = Get-FileHash -Path $ZipPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    if ($ActualHash -ine $ExpectedHash) {
        throw 'Checksum verification failed.'
    }

    # Extract and validate the new executable before replacing an existing installation.
    $ExtractPath = Join-Path $TempDir 'extract'
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force
    $ExtractedBinary = Join-Path $ExtractPath 'hounddog.exe'
    if (-not (Test-Path -LiteralPath $ExtractedBinary -PathType Leaf)) {
        throw 'The release archive does not contain hounddog.exe.'
    }

    $StagedVersionOutput = @(& $ExtractedBinary --version)
    if ($LASTEXITCODE -ne 0) {
        throw 'The downloaded HoundDog CLI executable could not be run.'
    }
    $StagedVersion = ($StagedVersionOutput -join [Environment]::NewLine).Trim()
    if ([string]::IsNullOrWhiteSpace($StagedVersion)) {
        throw 'The downloaded HoundDog CLI executable did not report a version.'
    }

    # Replace only the CLI executable and leave any unrelated files in the directory intact.
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    $InstalledBinary = Join-Path $InstallPath 'hounddog.exe'
    $PendingInstallPath = Join-Path $InstallPath "hounddog-$([Guid]::NewGuid().ToString('N')).tmp"
    Copy-Item -LiteralPath $ExtractedBinary -Destination $PendingInstallPath
    if (Test-Path -LiteralPath $InstalledBinary -PathType Leaf) {
        $BackupInstallPath = Join-Path $InstallPath "hounddog-$([Guid]::NewGuid().ToString('N')).bak"
        [System.IO.File]::Replace($PendingInstallPath, $InstalledBinary, $BackupInstallPath)
    } else {
        [System.IO.File]::Move($PendingInstallPath, $InstalledBinary)
    }
    $PendingInstallPath = $null

    try {
        $InstalledVersionOutput = @(& $InstalledBinary --version)
        if ($LASTEXITCODE -ne 0) {
            throw 'The installed HoundDog CLI executable could not be run.'
        }
        $InstalledVersion = ($InstalledVersionOutput -join [Environment]::NewLine).Trim()
        if ($InstalledVersion -ne $StagedVersion) {
            throw 'The installed HoundDog CLI executable failed verification.'
        }
    } catch {
        if ($BackupInstallPath -and (Test-Path -LiteralPath $BackupInstallPath -PathType Leaf)) {
            Copy-Item -LiteralPath $BackupInstallPath -Destination $InstalledBinary -Force
        } else {
            Remove-Item -LiteralPath $InstalledBinary -Force -ErrorAction SilentlyContinue
        }
        throw
    }
    if ($BackupInstallPath) {
        Remove-Item -LiteralPath $BackupInstallPath -Force
        $BackupInstallPath = $null
    }

    # Prepend the installation directory in both the persistent and current-session PATH values.
    $CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', $PathScope)
    $NewPath = Get-PathWithEntryFirst -PathValue $CurrentPath -Entry $InstallPath
    if ($NewPath -ne $CurrentPath) {
        try {
            [Environment]::SetEnvironmentVariable('Path', $NewPath, $PathScope)
            Write-Host "Added HoundDog CLI to the beginning of the $PathScope PATH."
        } catch {
            throw "Failed to update the $PathScope PATH: $($_.Exception.Message)"
        }
    }
    $env:Path = Get-PathWithEntryFirst -PathValue $env:Path -Entry $InstallPath

    Write-Host "`nHoundDog CLI installed successfully."
    Write-Host "Installed version: $InstalledVersion"
    Write-Host "Run 'hounddog --help' to get started."
} catch {
    throw "$($_.Exception.Message) Aborting installation."
} finally {
    if ($PendingInstallPath -and (Test-Path -LiteralPath $PendingInstallPath)) {
        Remove-Item -LiteralPath $PendingInstallPath -Force -ErrorAction SilentlyContinue
    }
    if ($BackupInstallPath -and (Test-Path -LiteralPath $BackupInstallPath)) {
        Remove-Item -LiteralPath $BackupInstallPath -Force -ErrorAction SilentlyContinue
    }
    # Clean up the temporary directory.
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
