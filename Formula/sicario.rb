# typed: false
# frozen_string_literal: true

# Homebrew formula for Sicario CLI.
#
# This file is auto-updated by the release workflow via the homebrew-sicario-cli tap.
# Manual installs: brew install sicario-labs/sicario-cli/sicario
class Sicario < Formula
  desc "Fast SAST, SCA, and secret scanning with AI auto-remediation"
  homepage "https://usesicario.xyz"
  version "0.2.0"

  license "LicenseRef-FSL-1.1-ALv2"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"

      def install
        bin.install "sicario-darwin-arm64" => "sicario"
      end
    else
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER_AMD64_SHA256"

      def install
        bin.install "sicario-darwin-amd64" => "sicario"
      end
    end
  end

  on_linux do
    url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-linux-amd64.tar.gz"
    sha256 "PLACEHOLDER_LINUX_AMD64_SHA256"

    def install
      bin.install "sicario-linux-amd64" => "sicario"
    end
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sicario --version")
  end
end
