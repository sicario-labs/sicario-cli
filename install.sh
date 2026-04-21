#!/usr/bin/env sh
# Sicario CLI — single-command installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/EmmyCodes234/sicario-cli/main/install.sh | sh
#
# Environment variables (all optional):
#   SICARIO_VERSION   — version to install, e.g. "v0.1.0"  (default: latest)
#   SICARIO_INSTALL_DIR — directory to place the binary     (default: /usr/local/bin)
#
# Requirements: curl (or wget), tar/unzip, chmod, uname

set -eu

# ── Helpers ────────────────────────────────────────────────────────────────────

say()  { printf '\033[1;32m==> \033[0m%s\n' "$*"; }
warn() { printf '\033[1;33mWARN\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR\033[0m %s\n' "$*" >&2; exit 1; }

need_cmd() {
  if ! command -v "$1" > /dev/null 2>&1; then
    die "Required command not found: $1"
  fi
}

# Download a URL to a local file.  Tries curl first, then wget.
download() {
  local url="$1"
  local dest="$2"
  if command -v curl > /dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$url" -o "$dest"
  elif command -v wget > /dev/null 2>&1; then
    wget -q --https-only "$url" -O "$dest"
  else
    die "Neither curl nor wget is available. Please install one and retry."
  fi
}

# ── Platform detection ─────────────────────────────────────────────────────────

detect_platform() {
  local os arch

  os="$(uname -s)"
  arch="$(uname -m)"

  case "$os" in
    Linux)
      case "$arch" in
        x86_64 | amd64) PLATFORM="linux-x86_64" ;;
        aarch64 | arm64) die "Linux ARM64 binaries are not yet published. Please build from source: https://github.com/EmmyCodes234/sicario-cli" ;;
        *) die "Unsupported Linux architecture: $arch" ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64)          PLATFORM="macos-x86_64" ;;
        arm64 | aarch64) PLATFORM="macos-aarch64" ;;
        *) die "Unsupported macOS architecture: $arch" ;;
      esac
      ;;
    MINGW* | MSYS* | CYGWIN* | Windows_NT)
      # Running inside Git Bash / MSYS2 on Windows
      PLATFORM="windows-x86_64"
      BINARY_EXT=".exe"
      ;;
    *)
      die "Unsupported operating system: $os. Please download a binary manually from https://github.com/EmmyCodes234/sicario-cli/releases"
      ;;
  esac

  BINARY_EXT="${BINARY_EXT:-}"
}

# ── Resolve the version to install ────────────────────────────────────────────

resolve_version() {
  if [ -n "${SICARIO_VERSION:-}" ]; then
    VERSION="$SICARIO_VERSION"
    say "Installing requested version: $VERSION"
    return
  fi

  say "Fetching latest release version..."
  local api_url="https://api.github.com/repos/EmmyCodes234/sicario-cli/releases/latest"
  local tmp
  tmp="$(mktemp)"

  download "$api_url" "$tmp"

  # Extract the tag_name field from the JSON response without requiring jq.
  VERSION="$(grep -o '"tag_name": *"[^"]*"' "$tmp" | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  rm -f "$tmp"

  if [ -z "$VERSION" ]; then
    die "Could not determine the latest release version. Set SICARIO_VERSION explicitly and retry."
  fi

  say "Latest version: $VERSION"
}

# ── Download and install ───────────────────────────────────────────────────────

install_binary() {
  local asset_name="sicario-${PLATFORM}${BINARY_EXT}"
  local download_url="https://github.com/EmmyCodes234/sicario-cli/releases/download/${VERSION}/${asset_name}"
  local install_dir="${SICARIO_INSTALL_DIR:-/usr/local/bin}"
  local tmp_bin
  tmp_bin="$(mktemp)"

  say "Downloading $asset_name from $download_url ..."
  download "$download_url" "$tmp_bin"

  say "Installing to ${install_dir}/sicario${BINARY_EXT} ..."

  # Create the install directory if it does not exist (best-effort; may need sudo).
  if [ ! -d "$install_dir" ]; then
    mkdir -p "$install_dir" 2>/dev/null || true
  fi

  local dest="${install_dir}/sicario${BINARY_EXT}"

  # Try a direct move first; fall back to sudo if permission is denied.
  if mv "$tmp_bin" "$dest" 2>/dev/null; then
    chmod +x "$dest"
  elif command -v sudo > /dev/null 2>&1; then
    warn "Permission denied — retrying with sudo..."
    sudo mv "$tmp_bin" "$dest"
    sudo chmod +x "$dest"
  else
    rm -f "$tmp_bin"
    die "Cannot write to $install_dir. Re-run with SICARIO_INSTALL_DIR set to a writable path, e.g.:\n  SICARIO_INSTALL_DIR=\$HOME/.local/bin sh install.sh"
  fi

  say "Installed: $dest"
}

# ── PATH check ─────────────────────────────────────────────────────────────────

check_path() {
  local install_dir="${SICARIO_INSTALL_DIR:-/usr/local/bin}"
  case ":${PATH}:" in
    *":${install_dir}:"*) ;;
    *)
      warn "$install_dir is not in your PATH."
      warn "Add the following line to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
      warn "  export PATH=\"${install_dir}:\$PATH\""
      ;;
  esac
}

# ── Verify installation ────────────────────────────────────────────────────────

verify_install() {
  local install_dir="${SICARIO_INSTALL_DIR:-/usr/local/bin}"
  local dest="${install_dir}/sicario${BINARY_EXT:-}"

  if [ -x "$dest" ]; then
    say "Verifying binary..."
    "$dest" --version && say "Sicario CLI installed successfully."
  else
    warn "Binary not found at $dest — PATH may need updating before first use."
  fi
}

# ── Main ───────────────────────────────────────────────────────────────────────

main() {
  need_cmd uname

  detect_platform
  resolve_version
  install_binary
  check_path
  verify_install
}

main "$@"
