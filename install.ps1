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
    'x86' { 'amd64' }
    default { throw 'Unsupported CPU architecture. HoundDog CLI requires an AMD64, ARM64, or x86 processor.' }
}
$DownloadUrl = "https://github.com/hounddogai/hounddog/releases/latest/download/hounddog-windows-$Arch.zip"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())

try {
    # Set up the binary installation directory.
    $InstallPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HoundDog\bin'
    if (Test-Path $InstallPath) {
        Remove-Item -Path "$InstallPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    } else {
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Create a temporary directory for downloading the ZIP archive.
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

    # Download and extract the ZIP archive to the installation directory.
    $ZipPath = Join-Path $TempDir 'hounddog.zip'
    Write-Host "Downloading HoundDog CLI from $DownloadUrl ..."
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
    Write-Host "Checksum verification successful."

    # Get the current user PATH and split it by semicolon.
    # Filter out any empty entries and trim whitespace.
    # Use [System.Environment]::GetEnvironmentVariable with a safety check for null.
    $CurrentUserPaths = @()
    $RawUserPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
    if ($RawUserPath) {
        $CurrentUserPaths = $RawUserPath -split ';' | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }

    # Create a new array for the updated PATH.
    $UpdatedPathsArray = New-Object System.Collections.Generic.List[string]

    # Add existing unique paths to the list.
    foreach ($pathEntry in $CurrentUserPaths) {
        if (-not $UpdatedPathsArray.Contains($pathEntry)) {
            $UpdatedPathsArray.Add($pathEntry)
        }
    }

    # Add the HoundDog installation path if it's not already there.
    if (-not $UpdatedPathsArray.Contains($InstallPath)) {
        $UpdatedPathsArray.Add($InstallPath)
    }

    # Join the unique paths with a semicolon.
    $NewPath = ($UpdatedPathsArray | Where-Object { $_ -ne $null -and $_ -ne '' }) -join ';'

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
