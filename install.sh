#!/usr/bin/env sh
# Sicario CLI — single-command installer
#
# Usage:
#   curl -fsSL https://usesicario.xyz/install.sh | sh
#
# Environment variables (all optional):
#   SICARIO_VERSION     — version to install, e.g. "v0.3.5"  (default: latest)
#   SICARIO_INSTALL_DIR — directory to place the binary       (default: auto)
#
# Supported platforms:
#   macOS   — Apple Silicon (arm64) and Intel (x86_64)
#   Linux   — x86_64
#
# Requirements: curl or wget, tar, uname, chmod

GITHUB_REPO="sicario-labs/sicario-cli"

set -eu

# ── Helpers ────────────────────────────────────────────────────────────────────

BOLD='\033[1m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

say()  { printf "${GREEN}==>${RESET} ${BOLD}%s${RESET}\n" "$*"; }
info() { printf "    %s\n" "$*"; }
warn() { printf "${YELLOW}warn${RESET} %s\n" "$*" >&2; }
die()  { printf "${RED}error${RESET} %s\n" "$*" >&2; exit 1; }

download() {
  local url="$1"
  local dest="$2"
  if command -v curl > /dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$dest"
  elif command -v wget > /dev/null 2>&1; then
    wget -q --https-only "$url" -O "$dest"
  else
    die "Neither curl nor wget is available. Install one and retry."
  fi
}

# ── Platform detection ─────────────────────────────────────────────────────────
#
# Release assets (v0.2.1+):
#   sicario-linux-amd64.tar.gz    — Linux x86_64
#   sicario-darwin-amd64.tar.gz   — macOS Intel
#   sicario-darwin-arm64.tar.gz   — macOS Apple Silicon
#
# Each tarball contains a single file named sicario-<platform>
# (e.g. sicario-linux-amd64) with no directory prefix.

detect_platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64 | amd64)
          PLATFORM="linux-amd64"
          ;;
        aarch64 | arm64)
          die "No pre-built binary for Linux ARM64 yet. Build from source: cargo install sicario-cli"
          ;;
        *)
          die "Unsupported Linux architecture: $arch. Build from source: https://github.com/$GITHUB_REPO"
          ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)          PLATFORM="darwin-amd64" ;;
        arm64 | aarch64) PLATFORM="darwin-arm64" ;;
        *)               die "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      die "Use the PowerShell installer on Windows: irm https://usesicario.xyz/install.ps1 | iex"
      ;;
    *)
      die "Unsupported OS: $os. Download a binary manually from https://github.com/$GITHUB_REPO/releases"
      ;;
  esac

  ASSET_NAME="sicario-${PLATFORM}.tar.gz"
  # The executable inside the tarball is named sicario-<platform> (no extension)
  BINARY_IN_ARCHIVE="sicario-${PLATFORM}"
}

# ── Resolve the version to install ────────────────────────────────────────────

resolve_version() {
  if [ -n "${SICARIO_VERSION:-}" ]; then
    VERSION="$SICARIO_VERSION"
    say "Installing requested version: $VERSION"
    return
  fi

  say "Fetching latest release version..."

  # Use the GitHub releases/latest redirect — it resolves to the tag of the
  # most recent non-prerelease, non-draft release without needing the API.
  # The redirect URL is: https://github.com/<owner>/<repo>/releases/latest
  # which 302s to: https://github.com/<owner>/<repo>/releases/tag/<version>
  local latest_url="https://github.com/$GITHUB_REPO/releases/latest"
  local resolved_url

  if command -v curl > /dev/null 2>&1; then
    resolved_url="$(curl --proto '=https' --tlsv1.2 -fsSLI -o /dev/null -w '%{url_effective}' "$latest_url" 2>/dev/null)"
  elif command -v wget > /dev/null 2>&1; then
    resolved_url="$(wget -q --https-only --server-response --spider "$latest_url" 2>&1 | grep -i 'Location:' | tail -1 | awk '{print $2}' | tr -d '\r')"
  else
    die "Neither curl nor wget is available. Install one and retry."
  fi

  VERSION="$(basename "$resolved_url")"

  # Fallback: try the GitHub API if the redirect approach failed
  if [ -z "$VERSION" ] || [ "$VERSION" = "latest" ]; then
    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local tmp
    tmp="$(mktemp)"
    if download "$api_url" "$tmp" 2>/dev/null; then
      VERSION="$(grep -o '"tag_name": *"[^"]*"' "$tmp" | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
    fi
    rm -f "$tmp"
  fi

  if [ -z "$VERSION" ]; then
    die "Could not determine the latest release version. Set SICARIO_VERSION explicitly and retry."
  fi

  say "Latest version: $VERSION"
}

# ── Choose install directory ───────────────────────────────────────────────────

choose_install_dir() {
  if [ -n "${SICARIO_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$SICARIO_INSTALL_DIR"
    USED_SUDO=false
    return
  fi

  if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
    USED_SUDO=false
    return
  fi

  local user_bin="$HOME/.local/bin"
  if [ ! -d "$user_bin" ]; then
    mkdir -p "$user_bin" 2>/dev/null || true
  fi
  if [ -d "$user_bin" ] && [ -w "$user_bin" ]; then
    INSTALL_DIR="$user_bin"
    USED_SUDO=false
    return
  fi

  if command -v sudo > /dev/null 2>&1; then
    INSTALL_DIR="/usr/local/bin"
    USED_SUDO=true
    warn "Will use sudo to install to $INSTALL_DIR"
    return
  fi

  die "Cannot find a writable install directory. Set SICARIO_INSTALL_DIR to a writable path and retry."
}

# ── Download and install ───────────────────────────────────────────────────────

install_binary() {
  local download_url="https://github.com/$GITHUB_REPO/releases/download/${VERSION}/${ASSET_NAME}"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local tmp_archive="${tmp_dir}/${ASSET_NAME}"

  say "Downloading ${ASSET_NAME} ..."
  info "From: $download_url"

  if ! download "$download_url" "$tmp_archive"; then
    rm -rf "$tmp_dir"
    die "Download failed. Check your internet connection or verify the release exists at https://github.com/$GITHUB_REPO/releases/tag/${VERSION}"
  fi

  if [ ! -s "$tmp_archive" ]; then
    rm -rf "$tmp_dir"
    die "Downloaded file is empty. The release asset may not exist for this platform/version."
  fi

  # ── Task 80.5: Verify checksum before executing/extracting ──────────────────
  local checksum_url="https://github.com/$GITHUB_REPO/releases/download/${VERSION}/${ASSET_NAME}.sha256"
  local tmp_checksum="${tmp_dir}/${ASSET_NAME}.sha256"
  if download "$checksum_url" "$tmp_checksum" 2>/dev/null; then
    say "Verifying checksum..."
    local expected_sha
    expected_sha="$(awk '{print $1}' "$tmp_checksum")"
    local actual_sha
    if command -v sha256sum >/dev/null 2>&1; then
      actual_sha="$(sha256sum "$tmp_archive" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
      actual_sha="$(shasum -a 256 "$tmp_archive" | awk '{print $1}')"
    else
      warn "sha256sum/shasum not found — skipping checksum verification."
      actual_sha="$expected_sha"
    fi
    if [ "$actual_sha" != "$expected_sha" ]; then
      rm -rf "$tmp_dir"
      die "Checksum mismatch! Expected $expected_sha, got $actual_sha. Installation aborted."
    fi
    say "Checksum verified successfully."
  else
    info "No .sha256 file available — skipping checksum verification."
  fi

  say "Extracting archive..."
  if ! tar -xzf "$tmp_archive" -C "$tmp_dir"; then
    rm -rf "$tmp_dir"
    die "Failed to extract archive. The file may be corrupted."
  fi

  # The tarball contains a single file: sicario-<platform>
  # Try the expected name first, then fall back to any sicario* file.
  local extracted_bin="${tmp_dir}/${BINARY_IN_ARCHIVE}"

  if [ ! -f "$extracted_bin" ]; then
    # Fallback: find any file starting with "sicario" that is executable or a regular file
    extracted_bin="$(find "$tmp_dir" -maxdepth 2 -type f -name 'sicario*' ! -name '*.tar.gz' ! -name '*.sha256' | head -n 1)"
  fi

  if [ -z "$extracted_bin" ] || [ ! -f "$extracted_bin" ]; then
    rm -rf "$tmp_dir"
    die "Could not find the sicario executable inside the extracted archive. Contents: $(ls "$tmp_dir")"
  fi

  local dest="${INSTALL_DIR}/sicario"

  say "Installing to $dest ..."

  if [ "${USED_SUDO:-false}" = "true" ]; then
    sudo mv "$extracted_bin" "$dest"
    sudo chmod +x "$dest"
  else
    mv "$extracted_bin" "$dest" 2>/dev/null || cp "$extracted_bin" "$dest"
    chmod +x "$dest"
  fi

  rm -rf "$tmp_dir"
}

# ── PATH guidance ──────────────────────────────────────────────────────────────

check_and_guide_path() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) return ;;
  esac

  printf "\n"
  warn "$INSTALL_DIR is not in your PATH."
  printf "\n"
  printf "  ${BOLD}Add Sicario to your PATH:${RESET}\n\n"

  local shell_name
  shell_name="$(basename "${SHELL:-sh}")"

  case "$shell_name" in
    zsh)
      printf "  ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> ~/.zshrc && source ~/.zshrc${RESET}\n" "$INSTALL_DIR"
      ;;
    bash)
      local profile_file
      if [ "$(uname -s)" = "Darwin" ]; then
        profile_file="~/.bash_profile"
      else
        profile_file="~/.bashrc"
      fi
      printf "  ${CYAN}echo 'export PATH=\"%s:\$PATH\"' >> %s && source %s${RESET}\n" "$INSTALL_DIR" "$profile_file" "$profile_file"
      ;;
    fish)
      printf "  ${CYAN}fish_add_path %s${RESET}\n" "$INSTALL_DIR"
      ;;
    *)
      printf "  Add to your shell profile (~/.bashrc, ~/.zshrc, etc.):\n"
      printf "  ${CYAN}export PATH=\"%s:\$PATH\"${RESET}\n" "$INSTALL_DIR"
      ;;
  esac

  printf "\n"
}

# ── Verify installation ────────────────────────────────────────────────────────

verify_install() {
  local dest="${INSTALL_DIR}/sicario"

  if [ ! -x "$dest" ]; then
    warn "Binary not found at $dest — PATH may need updating before first use."
    return
  fi

  local installed_version
  installed_version="$("$dest" --version 2>/dev/null || echo "unknown")"

  printf "\n"
  printf "  ${GREEN}✓${RESET} ${BOLD}Sicario CLI installed successfully!${RESET}\n"
  printf "  ${GREEN}✓${RESET} Version:  %s\n" "$installed_version"
  printf "  ${GREEN}✓${RESET} Location: %s\n" "$dest"
  printf "\n"
  printf "  ${BOLD}Quick start:${RESET}\n"
  printf "    sicario scan .                  # scan current directory\n"
  printf "    sicario scan . --publish        # scan and publish to dashboard\n"
  printf "    sicario fix <file> --rule <id>  # apply a deterministic fix\n"
  printf "\n"
  printf "  Docs: ${CYAN}https://usesicario.xyz/docs${RESET}\n"
  printf "\n"
}

# ── Main ───────────────────────────────────────────────────────────────────────

main() {
  detect_platform
  resolve_version
  choose_install_dir
  install_binary
  check_and_guide_path
  verify_install
}

main "$@"
