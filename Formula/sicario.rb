# typed: false
# frozen_string_literal: true

# Homebrew formula for Sicario CLI — a high-performance SAST tool written in Rust.
#
# To release a new version:
#   1. Update `version` below.
#   2. Update the sha256 digests for each bottle block.
#      Run: shasum -a 256 sicario-macos-x86_64 sicario-macos-aarch64 sicario-linux-x86_64
class Sicario < Formula
  desc "Ultra-fast SAST security scanner with AI-powered remediation"
  homepage "https://github.com/EmmyCodes234/sicario-cli"
  version "0.1.0"

  license "MIT"

  # ── macOS (Apple Silicon) ──────────────────────────────────────────────────
  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/EmmyCodes234/sicario-cli/releases/download/v#{version}/sicario-macos-aarch64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"

      def install
        bin.install "sicario-macos-aarch64" => "sicario"
      end
    else
      # ── macOS (Intel) ────────────────────────────────────────────────────
      url "https://github.com/EmmyCodes234/sicario-cli/releases/download/v#{version}/sicario-macos-x86_64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"

      def install
        bin.install "sicario-macos-x86_64" => "sicario"
      end
    end
  end

  # ── Linux (x86-64, statically linked musl) ────────────────────────────────
  on_linux do
    url "https://github.com/EmmyCodes234/sicario-cli/releases/download/v#{version}/sicario-linux-x86_64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000"

    def install
      bin.install "sicario-linux-x86_64" => "sicario"
    end
  end

  test do
    # Verify the binary runs and reports the expected version string.
    assert_match version.to_s, shell_output("#{bin}/sicario --version")
  end
end
