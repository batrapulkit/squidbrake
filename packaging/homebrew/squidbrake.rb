# Homebrew formula for Squidbrake. It lives in the tap repo github.com/batrapulkit/homebrew-tap as
# Formula/squidbrake.rb, so people install with:
#   brew install batrapulkit/tap/squidbrake
# On every release: update url and sha256 (the sdist on PyPI) and copy this file to the tap.
class Squidbrake < Formula
  desc "Change control for AI agents: agents propose, people approve"
  homepage "https://squidbrake.com"
  url "https://files.pythonhosted.org/packages/10/ca/2d41d31ae56aff1317b0a07150e9b02242f2a26c91e1ad9e5b36d2c62526/squidbrake-0.14.15.tar.gz"
  sha256 "137429fad32dfbd59448a700ea15a443c4e89fd6b83e7f4d27ec5e5577e75a20"
  license "Apache-2.0"

  depends_on "python@3.12"

  def install
    # shortcut: dependencies come from PyPI at install time, not pinned resource blocks; fine for our own tap,
    # run `brew update-python-resources` and pin them before submitting to homebrew-core
    system Formula["python@3.12"].opt_bin/"python3.12", "-m", "venv", libexec
    system libexec/"bin/python", "-m", "pip", "install", "--no-cache-dir", buildpath
    bin.install_symlink libexec/"bin/squidbrake"
  end

  def caveats
    <<~EOS
      Start it and connect every agent on this computer:
        squidbrake setup
      Or connect to your team's gateway:
        squidbrake connect all --url https://gateway.yourcompany.com --key gw_YOUR_AGENT_KEY
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/squidbrake --version")
  end
end
