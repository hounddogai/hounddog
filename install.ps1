#Requires -Version 5.1

[CmdletBinding()]
param()

# Stop the script on errors.
$ErrorActionPreference = 'Stop'
# Disable progress bar for faster downloads.
$ProgressPreference = 'SilentlyContinue'

Write-Host "Installing HoundDog CLI..."

# Check CPU architecture.
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw 'Unsupported CPU architecture. HoundDog CLI requires a AMD64 or ARM64 processor.' }
}
$DownloadUrl = "https://github.com/hounddogai/hounddog/releases/latest/download/hounddog-windows-$Arch.zip"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())


try {
    # Set up the binary installation directory.
    $InstallPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HoundDog\bin'
    if (Test-Path $InstallPath) {
        Remove-Item -Path $InstallPath\* -Force -Recurse -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Create a temporary directory for downloading the ZIP archive.
    New-Item -ItemType Directory -Path $TempDir | Out-Null

    # Download and extract the ZIP archive to the installation directory.
    $ZipPath = Join-Path $TempDir 'hounddog.zip'
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    Expand-Archive -Path $ZipPath -DestinationPath $InstallPath -Force

    # Download the SHA256 checksum file and verify the integrity of the ZIP archive.
    $ChecksumPath = Join-Path $TempDir 'hounddog.zip.sha256'
    Invoke-WebRequest -Uri "$DownloadUrl.sha256" -OutFile $ChecksumPath -UseBasicParsing
    $ExpectedHash = Get-Content -Path $ChecksumPath
    $ActualHash = Get-FileHash -Path $ZipPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    if ($ActualHash -ne $ExpectedHash) {
        throw "Checksum verification failed."
    }

    # Update PATH environment variable (user).
    $UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $Paths = $UserPath -split ';' | Where-Object { $_ -and $_ -ne $InstallPath }
    $NewPath = ($Paths + $InstallPath) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')

    # Test installation.
    $env:Path = $NewPath
    if (Get-Command hounddog -ErrorAction SilentlyContinue) {
        Write-Host "`nHoundDog CLI installed successfully."
        Write-Host "Run 'hounddog --help' to get started. You may need to restart your terminal first."
    } else {
        throw "Cannot find 'hounddog' command in PATH."
    }
} catch {
    Write-Host "$_ Aborting installation." -ForegroundColor Red
    exit 1
} finally {
    # Clean up the temporary directory.
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
