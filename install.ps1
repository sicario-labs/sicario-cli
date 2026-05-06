# Sicario CLI — Windows PowerShell installer
#
# Usage:
#   irm https://usesicario.xyz/install.ps1 | iex
#
# Environment variables (all optional):
#   $env:SICARIO_VERSION     — version to install, e.g. "v0.2.1"  (default: latest)
#   $env:SICARIO_INSTALL_DIR — directory to place the binary       (default: ~\.local\bin)
#
# Release asset: sicario-windows-amd64.zip
# Contains:      sicario-windows-amd64.exe
# Installed as:  sicario.exe

#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GITHUB_REPO = "sicario-labs/sicario-cli"
$ASSET_NAME  = "sicario-windows-amd64.zip"
$BIN_IN_ZIP  = "sicario-windows-amd64.exe"
$FINAL_NAME  = "sicario.exe"

# ── Helpers ────────────────────────────────────────────────────────────────────

function Write-Step  { param($msg) Write-Host "==> $msg" -ForegroundColor Green }
function Write-Info  { param($msg) Write-Host "    $msg" }
function Write-Warn  { param($msg) Write-Host "warn $msg" -ForegroundColor Yellow }
function Fail        { param($msg) Write-Host "error $msg" -ForegroundColor Red; exit 1 }

# ── Resolve version ────────────────────────────────────────────────────────────

function Resolve-Version {
  if ($env:SICARIO_VERSION) {
    Write-Step "Installing requested version: $($env:SICARIO_VERSION)"
    return $env:SICARIO_VERSION
  }

  Write-Step "Fetching latest release version..."

  # Use the GitHub releases/latest redirect — resolves to the most recent
  # non-prerelease, non-draft release without needing an API token.
  $latestUrl = "https://github.com/$GITHUB_REPO/releases/latest"

  try {
    $response = Invoke-WebRequest -Uri $latestUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
    # 302 redirect — Location header contains the tag URL
    $location = $response.Headers["Location"]
    if ($location) {
      $version = Split-Path $location -Leaf
      if ($version -and $version -ne "latest") {
        Write-Step "Latest version: $version"
        return $version
      }
    }
  }
  catch {
    # Redirect throws on some PS versions — extract from exception
    $location = $_.Exception.Response.Headers["Location"]
    if ($location) {
      $version = Split-Path $location -Leaf
      if ($version -and $version -ne "latest") {
        Write-Step "Latest version: $version"
        return $version
      }
    }
  }

  # Fallback: GitHub API
  try {
    $apiUrl  = "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    $resp    = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing -ErrorAction Stop
    $version = $resp.tag_name
    if ($version) {
      Write-Step "Latest version: $version"
      return $version
    }
  }
  catch { }

  Fail "Could not determine the latest release version. Set `$env:SICARIO_VERSION` explicitly and retry."
}

# ── Choose install directory ───────────────────────────────────────────────────

function Get-InstallDir {
  if ($env:SICARIO_INSTALL_DIR) {
    $dir = $env:SICARIO_INSTALL_DIR
    if (-not (Test-Path $dir)) {
      try { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
      catch { Fail "Could not create install directory '$dir': $_" }
    }
    return $dir
  }

  # Default: %LOCALAPPDATA%\sicario\bin  (no admin rights required)
  $dir = Join-Path $env:LOCALAPPDATA "sicario\bin"
  if (-not (Test-Path $dir)) {
    try { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    catch { Fail "Could not create install directory '$dir': $_" }
  }
  return $dir
}

# ── Download and install ───────────────────────────────────────────────────────

function Install-Binary {
  param($version, $installDir)

  $downloadUrl = "https://github.com/$GITHUB_REPO/releases/download/$version/$ASSET_NAME"
  $tmpDir      = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
  $tmpZip      = Join-Path $tmpDir $ASSET_NAME

  try { New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null }
  catch { Fail "Could not create temp directory: $_" }

  Write-Step "Downloading $ASSET_NAME ..."
  Write-Info  "From: $downloadUrl"

  try {
    Invoke-WebRequest `
      -Uri $downloadUrl `
      -OutFile $tmpZip `
      -UseBasicParsing `
      -ErrorAction Stop
  }
  catch {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Fail "Download failed: $_`nVerify the release exists at https://github.com/$GITHUB_REPO/releases/tag/$version"
  }

  if (-not (Test-Path $tmpZip) -or (Get-Item $tmpZip).Length -eq 0) {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Fail "Downloaded file is empty or missing. The release asset may not exist for this platform/version."
  }

  Write-Step "Extracting archive..."
  try {
    Expand-Archive -Path $tmpZip -DestinationPath $tmpDir -Force -ErrorAction Stop
  }
  catch {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Fail "Failed to extract archive: $_"
  }

  # Find the executable — try the expected name first, then any .exe
  $exePath = Join-Path $tmpDir $BIN_IN_ZIP
  if (-not (Test-Path $exePath)) {
    $found = Get-ChildItem -Path $tmpDir -Recurse -Filter "sicario*.exe" -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($found) {
      $exePath = $found.FullName
    }
    else {
      Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
      Fail "Could not find sicario executable inside the extracted archive."
    }
  }

  $dest = Join-Path $installDir $FINAL_NAME
  Write-Step "Installing to $dest ..."

  try {
    Copy-Item -Path $exePath -Destination $dest -Force -ErrorAction Stop
  }
  catch {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Fail "Could not copy binary to '$dest': $_"
  }

  Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
  return $dest
}

# ── Add to PATH ────────────────────────────────────────────────────────────────

function Add-ToUserPath {
  param($dir)

  $currentPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
  $dirs = $currentPath -split ";" | Where-Object { $_ -ne "" }

  if ($dirs -contains $dir) {
    Write-Info "$dir is already in your user PATH."
    return
  }

  $newPath = ($dirs + $dir) -join ";"
  try {
    # Permanently write to the User-scope registry key so the PATH persists
    # across all new terminal sessions (fixes ISSUE-008).
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, "User")

    # Also update the current session immediately so the user doesn't need
    # to restart their terminal to use sicario right away.
    $env:PATH = $env:PATH + ";" + $dir

    Write-Info "Added $dir to your user PATH (permanent)."
    Write-Info "sicario is available in this session and all future terminals."
  }
  catch {
    Write-Warn "Could not update PATH automatically: $_"
    Write-Warn "Add this directory to your PATH manually: $dir"
  }
}

# ── Verify installation ────────────────────────────────────────────────────────

function Confirm-Install {
  param($dest)

  if (-not (Test-Path $dest)) {
    Write-Warn "Binary not found at $dest — something went wrong."
    return
  }

  try {
    $installedVersion = & $dest --version 2>&1
  }
  catch {
    $installedVersion = "unknown"
  }

  Write-Host ""
  Write-Host "  " -NoNewline; Write-Host "✓ Sicario CLI installed successfully!" -ForegroundColor Green
  Write-Host "  " -NoNewline; Write-Host "✓ Version:  $installedVersion" -ForegroundColor Green
  Write-Host "  " -NoNewline; Write-Host "✓ Location: $dest" -ForegroundColor Green
  Write-Host ""
  Write-Host "  Quick start:" -ForegroundColor White
  Write-Host "    sicario scan .                  # scan current directory"
  Write-Host "    sicario scan . --publish        # scan and publish to dashboard"
  Write-Host "    sicario fix <file> --rule <id>  # apply a deterministic fix"
  Write-Host ""
  Write-Host "  Docs: https://usesicario.xyz/docs" -ForegroundColor Cyan
  Write-Host ""
}

# ── Main ───────────────────────────────────────────────────────────────────────

$version    = Resolve-Version
$installDir = Get-InstallDir
$dest       = Install-Binary -version $version -installDir $installDir
Add-ToUserPath -dir $installDir
Confirm-Install -dest $dest
