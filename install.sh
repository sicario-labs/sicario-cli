#!/usr/bin/env sh
# Sicario CLI — single-command installer
#
# Usage:
#   curl -fsSL https://usesicario.xyz/install.sh | sh
#
# Environment variables (all optional):
#   SICARIO_VERSION     — version to install, e.g. "v0.1.9"  (default: latest)
#   SICARIO_INSTALL_DIR — directory to place the binary       (default: auto)
#
# Supported platforms:
#   macOS   — Apple Silicon (arm64) and Intel (x86_64)
#   Linux   — x86_64 and aarch64/arm64
#   Windows — x86_64 (via Git Bash / MSYS2 / Cygwin)
#
# Requirements: curl or wget, tar/unzip, uname, chmod

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

detect_platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  BINARY_EXT=""
  ARCHIVE_EXT=".tar.gz"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64 | amd64)      PLATFORM="linux-amd64" ;;
        aarch64 | arm64)     PLATFORM="linux-arm64" ;;
        *)                   die "Unsupported Linux architecture: $arch. Please build from source: https://github.com/$GITHUB_REPO" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)              PLATFORM="darwin-amd64" ;;
        arm64 | aarch64)     PLATFORM="darwin-arm64" ;;
        *)                   die "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      PLATFORM="windows-amd64"
      BINARY_EXT=".exe"
      ARCHIVE_EXT=".zip"
      ;;
    *)
      die "Unsupported OS: $os. Download a binary manually from https://github.com/$GITHUB_REPO/releases"
      ;;
  esac
}

# ── Resolve the version to install ────────────────────────────────────────────

resolve_version() {
  if [ -n "${SICARIO_VERSION:-}" ]; then
    VERSION="$SICARIO_VERSION"
    say "Installing requested version: $VERSION"
    return
  fi

  say "Fetching latest release version..."
  local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
  local tmp
  tmp="$(mktemp)"

  download "$api_url" "$tmp"

  VERSION="$(grep -o '"tag_name": *"[^"]*"' "$tmp" | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  rm -f "$tmp"

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
  local asset_name="sicario-${PLATFORM}${ARCHIVE_EXT}"
  local expected_bin_name="sicario-${PLATFORM}${BINARY_EXT}"
  local download_url="https://github.com/$GITHUB_REPO/releases/download/${VERSION}/${asset_name}"
  
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local tmp_archive="${tmp_dir}/${asset_name}"

  say "Downloading $asset_name ..."
  info "From: $download_url"

  if ! download "$download_url" "$tmp_archive"; then
    rm -rf "$tmp_dir"
    die "Download failed. Check your internet connection or try setting SICARIO_VERSION to a known release tag."
  fi

  if [ ! -s "$tmp_archive" ]; then
    rm -rf "$tmp_dir"
    die "Downloaded file is empty. The release asset may not exist."
  fi

  say "Extracting archive..."
  if [ "$ARCHIVE_EXT" = ".tar.gz" ]; then
    tar -xzf "$tmp_archive" -C "$tmp_dir"
  elif [ "$ARCHIVE_EXT" = ".zip" ]; then
    unzip -q "$tmp_archive" -d "$tmp_dir"
  fi

  # Look for the exact file name (e.g. sicario-linux-amd64) or fallback to anything starting with sicario
  local extracted_bin="${tmp_dir}/${expected_bin_name}"
  
  if [ ! -f "$extracted_bin" ]; then
    extracted_bin=$(find "$tmp_dir" -type f -name "$expected_bin_name" | head -n 1)
  fi

  if [ -z "$extracted_bin" ] || [ ! -f "$extracted_bin" ]; then
    extracted_bin=$(find "$tmp_dir" -type f -name "sicario*" | head -n 1)
    if [ -z "$extracted_bin" ]; then
      rm -rf "$tmp_dir"
      die "Could not find sicario executable inside the extracted archive."
    fi
  fi

  local dest="${INSTALL_DIR}/sicario${BINARY_EXT}"

  say "Installing to $dest ..."

  if [ "${USED_SUDO:-false}" = "true" ]; then
    sudo mv "$extracted_bin" "$dest"
    sudo chmod +x "$dest"
  else
    if ! mv "$extracted_bin" "$dest" 2>/dev/null; then
      cp "$extracted_bin" "$dest"
    fi
    chmod +x "$dest"
  fi
  
  rm -rf "$tmp_dir"
}

# ── PATH guidance ──────────────────────────────────────────────────────────────

check_and_guide_path() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
      return
      ;;
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
      printf "  Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):\n"
      printf "  ${CYAN}export PATH=\"%s:\$PATH\"${RESET}\n" "$INSTALL_DIR"
      ;;
  esac

  printf "\n"
  printf "  Or run Sicario directly without modifying PATH:\n"
  printf "  ${CYAN}%s/sicario%s --version${RESET}\n" "$INSTALL_DIR" "${BINARY_EXT}"
  printf "\n"
}

# ── Verify installation ────────────────────────────────────────────────────────

verify_install() {
  local dest="${INSTALL_DIR}/sicario${BINARY_EXT}"

  if [ ! -x "$dest" ]; then
    warn "Binary not found at $dest — PATH may need updating before first use."
    return
  fi

  say "Verifying installation..."
  local installed_version
  installed_version="$("$dest" --version 2>/dev/null || echo "unknown")"

  printf "\n"
  printf "  ${GREEN}✓${RESET} ${BOLD}Sicario CLI installed successfully!${RESET}\n"
  printf "  ${GREEN}✓${RESET} Version: %s\n" "$installed_version"
  printf "  ${GREEN}✓${RESET} Location: %s\n" "$dest"
  printf "\n"
  printf "  ${BOLD}Quick start:${RESET}\n"
  printf "    sicario scan .                  # scan current directory\n"
  printf "    sicario scan . --publish        # scan and publish to dashboard\n"
  printf "    sicario fix <file> --rule <id>  # Deterministic AST fix\n"
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
