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
    'x86' { 'amd64' } # Treat x86 as amd64 for download purposes
    default { throw 'Unsupported CPU architecture. HoundDog CLI requires an AMD64, ARM64, or x86 processor.' }
}
Write-Host "Detected architecture: $($env:PROCESSOR_ARCHITECTURE), using download architecture: $Arch"
$DownloadUrl = "https://github.com/hounddogai/hounddog/releases/latest/download/hounddog-windows-$Arch.zip"
Write-Host "Download URL: $DownloadUrl"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
Write-Host "Temporary directory: $TempDir"


try {
    # Set up the binary installation directory.
    $InstallPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HoundDog\bin'
    Write-Host "Installation path: $InstallPath"
    if (Test-Path $InstallPath) {
        Write-Host "Removing existing HoundDog binaries..."
        Remove-Item -Path "$InstallPath\*" -Force -Recurse -ErrorAction SilentlyContinue
    } else {
        Write-Host "Creating installation directory..."
        New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    }

    # Create a temporary directory for downloading the ZIP archive.
    Write-Host "Creating temporary download directory..."
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null # Added -Force just in case

    # Download and extract the ZIP archive to the installation directory.
    $ZipPath = Join-Path $TempDir 'hounddog.zip'
    Write-Host "Downloading ZIP from $DownloadUrl to $ZipPath..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
    Write-Host "Download complete. Extracting ZIP to $InstallPath..."
    Expand-Archive -Path $ZipPath -DestinationPath $InstallPath -Force

    Write-Host "Verifying extracted files in $InstallPath..."
    $ExtractedFiles = Get-ChildItem -Path $InstallPath -ErrorAction SilentlyContinue
    if ($ExtractedFiles.Count -eq 0) {
        throw "No files found in $InstallPath after extraction. ZIP structure might be unexpected or extraction failed."
    }
    Write-Host "Files found after extraction:"
    $ExtractedFiles | ForEach-Object { Write-Host "  $($_.Name)" }

    # Check specifically for hounddog.exe
    if (-not (Test-Path (Join-Path $InstallPath 'hounddog.exe'))) {
        throw "hounddog.exe not found directly in $InstallPath after extraction. Please check the ZIP file structure."
    }

    # Download the SHA256 checksum file and verify the integrity of the ZIP archive.
    $ChecksumPath = Join-Path $TempDir 'hounddog.zip.sha256'
    Write-Host "Downloading SHA256 checksum from $DownloadUrl.sha256 to $ChecksumPath..."
    Invoke-WebRequest -Uri "$DownloadUrl.sha256" -OutFile $ChecksumPath -UseBasicParsing
    $ExpectedHash = (Get-Content -Path $ChecksumPath).Split(' ')[0] # Get only the hash, sometimes files include filename
    $ActualHash = Get-FileHash -Path $ZipPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
    Write-Host "Expected Hash: $ExpectedHash"
    Write-Host "Actual Hash:   $ActualHash"
    if ($ActualHash -ne $ExpectedHash) {
        throw "Checksum verification failed. Downloaded file might be corrupted."
    }
    Write-Host "Checksum verification successful."

    # Update PATH environment variable (user).
    Write-Host "Updating User PATH environment variable..."

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

    # Add existing unique paths to the list
    foreach ($pathEntry in $CurrentUserPaths) {
        if (-not $UpdatedPathsArray.Contains($pathEntry)) {
            $UpdatedPathsArray.Add($pathEntry)
        }
    }

    # Add the HoundDog installation path if it's not already there
    if (-not $UpdatedPathsArray.Contains($InstallPath)) {
        $UpdatedPathsArray.Add($InstallPath)
    }

    # Join the unique paths with a semicolon
    $NewPath = ($UpdatedPathsArray | Where-Object { $_ -ne $null -and $_ -ne '' }) -join ';'

    [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
    Write-Host "User PATH updated. New Path: $NewPath"

    # Test installation.
    Write-Host "Updating current session's PATH for testing..."
    $env:Path = $NewPath
    Write-Host "Attempting to find 'hounddog' command..."
    if (Get-Command hounddog -ErrorAction SilentlyContinue) {
        Write-Host "`nHoundDog CLI installed successfully."
        Write-Host "Run 'hounddog --help' to get started. You may need to restart your terminal first."
    } else {
        throw "Cannot find 'hounddog' command in PATH. This indicates an issue with extraction or PATH update."
    }
} catch {
    Write-Host "$_ Aborting installation." -ForegroundColor Red
    exit 1
} finally {
    # Clean up the temporary directory.
    if (Test-Path $TempDir) {
        Write-Host "Cleaning up temporary directory: $TempDir"
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
