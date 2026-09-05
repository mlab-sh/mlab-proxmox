# Install

mlab-proxmox is a single Rust binary with no runtime dependencies. macOS and
Linux, x86_64 and arm64, from a package manager or as a tarball.

## Homebrew (macOS and Linux)

```bash
brew tap mlab-sh/mlab-proxmox https://github.com/mlab-sh/mlab-proxmox.git
brew install mlab-proxmox
```

## Debian and Ubuntu

Download the `.deb` for your architecture from the
[releases page](https://github.com/mlab-sh/mlab-proxmox/releases), then let apt
resolve it:

```bash
sudo apt install ./mlab-proxmox_1.0.0_amd64.deb
```

## Fedora, RHEL and rebuilds

The same with the `.rpm`:

```bash
sudo dnf install ./mlab-proxmox-1.0.0-1.x86_64.rpm
```

The payload is gzip rather than the zstd default, so rpm 4.14 (RHEL 8 and its
rebuilds) reads it too.

## Prebuilt binary

Tarballs for every target are on the same page:

```bash
tar -xzf mlab-proxmox-1.0.0-aarch64-apple-darwin.tar.gz
install -m 0755 mlab-proxmox-1.0.0-aarch64-apple-darwin/mlab-proxmox ~/.local/bin/
```

The Linux builds are linked against glibc 2.35, so they run on Debian 12,
Ubuntu 22.04 and anything newer.

## Checking what you downloaded

Nothing is signed, so every release carries a `SHA256SUMS` file covering all of
its assets:

```bash
sha256sum -c --ignore-missing SHA256SUMS
```

## From source

A recent Rust toolchain:

```bash
git clone https://github.com/mlab-sh/mlab-proxmox.git
cd mlab-proxmox
cargo build --release
```

The binary lands at `target/release/mlab-proxmox`. While working on the tool
itself, `cargo run --` takes the same arguments:

```bash
cargo run -- ping
cargo run -- audit --min high
```

## First run

Create the read-only role and token on the cluster first — four commands, see
[Token](Token) — then:

```bash
mlab-proxmox login --name lab --host 10.0.10.11 --token-id 'mlab@pve!audit'
mlab-proxmox ping
mlab-proxmox audit
```

`login` prompts for the token secret without echoing it, checks the connection,
records the certificate fingerprint it saw, and writes
`$HOME/.mlab/proxmox.conf` with mode 0600 in a 0700 directory.

## TLS

A fresh Proxmox install serves a certificate signed by the cluster's own CA,
which no system trust store knows. Verification is therefore **off by default**
for a profile, and `ping` says so on every run:

```
  tls  not verified
```

`login` records the fingerprint of the certificate it saw, and warns when it
changes on a later login — which is the part that actually detects an
interception, rather than the part that silently accepts one.

Pass `--secure` once the cluster serves a certificate your machine trusts
(Datacenter → ACME, or your own upload), and the profile keeps it.

## Requirements

Proxmox VE 7.x or later. Everything is built on the documented API, and routes
that only exist on newer versions — SDN fabrics, HA rules, the nftables
firewall options — are treated as absent rather than as failures when a node
404s on them.

Tested against 9.1.
