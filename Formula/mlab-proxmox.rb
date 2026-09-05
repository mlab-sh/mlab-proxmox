class MlabProxmox < Formula
  desc "CLI over the Proxmox VE API, for passive infrastructure security work"
  homepage "https://github.com/mlab-sh/mlab-proxmox"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-proxmox/releases/download/v#{version}/mlab-proxmox-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "b3e1514d127d1ae3527b7ed6b68d45c44ef0c242ef25c0d2597cd0190a3182f2"
    else
      url "https://github.com/mlab-sh/mlab-proxmox/releases/download/v#{version}/mlab-proxmox-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "89b25ac31a5988c2e5e217a6fbdf1d03e7da80006d707f2fcc75a48eb80ec1c0"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mlab-sh/mlab-proxmox/releases/download/v#{version}/mlab-proxmox-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "5fdaeb9b50270bd6832d993fe39fc212ddd01b4e656cd13fc8d38ab94f02cf1c"
    elsif Hardware::CPU.arm?
      url "https://github.com/mlab-sh/mlab-proxmox/releases/download/v#{version}/mlab-proxmox-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "1716b107a56a254f023640d4081bbd3cc21d66c3b0ca4748f113cd7830b228bc"
    end
  end

  def install
    bin.install "mlab-proxmox"
  end

  test do
    assert_match "mlab-proxmox", shell_output("#{bin}/mlab-proxmox --version")
  end
end
