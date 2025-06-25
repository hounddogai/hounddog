#Requires -Version 5.1

[CmdletBinding()]
param()

# Stop the script on errors.
$ErrorActionPreference = 'Stop'
# Disable progress bar for faster downloads.
$ProgressPreference = 'SilentlyContinue'

# Check CPU architecture.
$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    'x86' { 'amd64' }
    default { throw 'Unsupported CPU architecture. HoundDog CLI requires an AMD64, ARM64, or x86 processor.' }
}
$DownloadUrl = "https://github.com/hounddogai/hounddog/releases/latest/download/hounddog-windows-$Arch.zip"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

try {
    # Determine if running with admin privileges
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    # Set installation path and PATH scope based on privileges
    if ($IsAdmin) {
        # Admin: Install to Program Files and update System PATH
        $InstallPath = Join-Path $env:ProgramFiles "hounddog\bin"
        $PathScope = "Machine"
        Write-Host "Installing HoundDog CLI for all users..."
    } else {
        # Non-admin: Install to user's local app data and update User PATH
        $InstallPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'hounddog\bin'
        $PathScope = "User"
        Write-Host "Installing HoundDog CLI for current user only..."
    }

    # Create the installation directory if it doesn't exist
    if (Test-Path $InstallPath) {
        Remove-Item -Path "$InstallPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Create a temporary directory for downloading the ZIP archive.
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    # Download and extract the ZIP archive to the installation directory.
    $ZipPath = Join-Path $TempDir 'hounddog.zip'
    Write-Host "Downloading ZIP from $DownloadUrl ..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    Write-Host "Extracting ZIP to $InstallPath ..."
    Expand-Archive -Path $ZipPath -DestinationPath $InstallPath -Force

    # Verify the extracted file.
    $ExtractedFiles = Get-ChildItem -Path $InstallPath -ErrorAction SilentlyContinue
    if ($ExtractedFiles.Count -eq 0) {
        throw "No files found in $InstallPath after extraction."
    }
    if (-not (Test-Path (Join-Path $InstallPath 'hounddog.exe'))) {
        throw "hounddog.exe not found in $InstallPath after extraction."
    }

    # Download the SHA256 checksum file and verify the integrity of the binary.
    Write-Host "Verifying checksum ..."
    $ChecksumPath = Join-Path $TempDir 'hounddog.zip.sha256'
    Invoke-WebRequest -Uri "$DownloadUrl.sha256" -OutFile $ChecksumPath -UseBasicParsing
    $ExpectedHash = (Get-Content -Path $ChecksumPath).Split(' ')[0] # Get only the hash, sometimes files include filename
    $ActualHash = Get-FileHash -Path $ZipPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    if ($ActualHash -ne $ExpectedHash) {
        throw "Checksum verification failed."
    }

    # Update PATH based on admin status
    $CurrentPath = [System.Environment]::GetEnvironmentVariable('Path', $PathScope)

    # Only add the HoundDog installation path if it's not already in the PATH
    if ($CurrentPath -notlike "*$InstallPath*") {
        # Ensure PATH ends with semicolon before appending
        if ($CurrentPath -and -not $CurrentPath.EndsWith(';')) {
            $CurrentPath = "$CurrentPath;"
        }
        
        # Add the new path
        $NewPath = "$CurrentPath$InstallPath"
        
        try {
            [Environment]::SetEnvironmentVariable('Path', $NewPath, $PathScope)
            Write-Host "Added HoundDog CLI to $PathScope PATH."
        } catch {
            Write-Host "Failed to update $PathScope PATH: $_" -ForegroundColor Red
            exit 1
        }
    } else {
        $NewPath = $CurrentPath
    }

    # Update current session's PATH
    $env:Path = $NewPath

    # Test installation.
    if (Get-Command hounddog -ErrorAction SilentlyContinue) {
        Write-Host "`nHoundDog CLI installed successfully."
        Write-Host "Run 'hounddog --help' to get started."
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
