//! Config storage for the `mlab-proxmox` CLI.
//!
//! One file, `$HOME/.mlab/proxmox.conf` (JSON), holding any number of named
//! profiles plus the name of the default one. Written 0600 inside a 0700 dir:
//! it contains API token secrets.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Default port of the Proxmox VE API and web interface.
pub const DEFAULT_PORT: u16 = 8006;

/// Connection parameters for one Proxmox VE cluster.
///
/// A cluster, not a node: `pveproxy` forwards a request for another node's
/// path to whichever node owns it, so one host reaches the whole cluster.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    /// Hostname or IP of any node, optionally `host:port`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// Port, when the host does not carry one. Defaults to 8006.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Token identifier, `user@realm!tokenname`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_id: String,
    /// The UUID shown once when the token was created.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_secret: String,
    /// SHA-256 fingerprint of the certificate seen at login, so a later change
    /// can be reported. Recorded, not enforced: see [`Profile::insecure`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Tri-state: `None` means the default, which is to skip verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    /// `human` or `json`; `None` means the global default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Profile {
    /// Effective TLS behaviour. A fresh Proxmox install serves a certificate
    /// signed by the cluster's own CA, which no system trust store knows, so
    /// verification is off unless the profile turns it on.
    pub fn insecure(&self) -> bool {
        self.insecure.unwrap_or(true)
    }

    /// `host:port`, with the default port filled in.
    pub fn endpoint(&self) -> Result<String> {
        let host = normalize_host(&self.host)?;
        if host.contains(':') {
            return Ok(host);
        }
        Ok(format!("{host}:{}", self.port.unwrap_or(DEFAULT_PORT)))
    }

    /// Reject a profile that cannot produce a request.
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            bail!("host is missing (set --host, PROXMOX_HOST, or run `mlab-proxmox login`)");
        }
        normalize_host(&self.host)?;
        if self.token_id.is_empty() {
            bail!("token id is missing (set --token-id, PROXMOX_TOKEN_ID, or run `mlab-proxmox login`)");
        }
        validate_token_id(&self.token_id)?;
        if self.token_secret.is_empty() {
            bail!(
                "token secret is missing (set PROXMOX_TOKEN_SECRET, or run `mlab-proxmox login`)"
            );
        }
        Ok(())
    }

    /// A copy with the secret blanked, for printing.
    pub fn redacted(&self) -> Profile {
        let mut p = self.clone();
        p.token_secret = redact(&self.token_secret);
        p
    }
}

/// A token id is `user@realm!tokenname`; anything else authenticates as nobody
/// and the API answers 401 with no hint about which half is wrong.
pub fn validate_token_id(id: &str) -> Result<()> {
    let (user, name) = match id.split_once('!') {
        Some(parts) => parts,
        None => bail!("token id {id:?} must look like user@realm!tokenname"),
    };
    if name.is_empty() {
        bail!("token id {id:?} has no token name after the `!`");
    }
    match user.split_once('@') {
        Some((u, realm)) if !u.is_empty() && !realm.is_empty() => Ok(()),
        _ => bail!("token id {id:?} must name a realm, as in root@pam!{name}"),
    }
}

/// Mask a secret down to its last 4 characters.
pub fn redact(secret: &str) -> String {
    if secret.is_empty() {
        return String::new();
    }
    let tail: String = secret
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("****{tail}")
}

/// Canonicalize a host: strip any scheme and trailing slashes, reject a value
/// carrying a path, query, fragment, or whitespace.
pub fn normalize_host(h: &str) -> Result<String> {
    let mut s = h.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    let s = s.trim_end_matches('/');
    if s.is_empty() {
        bail!("host is empty");
    }
    if s.contains(['/', '?', '#', ' ', '\t', '\r', '\n']) {
        bail!("host {h:?} must be a hostname or host:port, without a path");
    }
    Ok(s.to_string())
}

/// The whole config file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigFile {
    /// Name of the profile used when `--profile` is not given.
    #[serde(rename = "default", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ConfigFile {
    /// Pick a profile: the one named, else the default, else the only one.
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        if let Some(n) = name {
            return match self.profiles.get(n) {
                Some(p) => Ok((n.to_string(), p.clone())),
                None => bail!("no profile named {n:?} in {}", path().display()),
            };
        }
        if let Some(d) = &self.default_profile {
            if let Some(p) = self.profiles.get(d) {
                return Ok((d.clone(), p.clone()));
            }
        }
        if self.profiles.len() == 1 {
            let (n, p) = self.profiles.iter().next().expect("len checked");
            return Ok((n.clone(), p.clone()));
        }
        if self.profiles.is_empty() {
            bail!("no profile configured; run `mlab-proxmox login` first");
        }
        bail!(
            "several profiles and no default; pass --profile, or run `mlab-proxmox profile use <name>`"
        )
    }
}

/// `$HOME/.mlab`, or `$MLAB_CONFIG_DIR` when set.
pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("MLAB_CONFIG_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".mlab")
}

pub fn path() -> PathBuf {
    dir().join("proxmox.conf")
}

pub fn load() -> Result<ConfigFile> {
    let p = path();
    if !p.exists() {
        return Ok(ConfigFile::default());
    }
    let raw = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    if raw.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", p.display()))
}

/// Write the file back, 0600 in a 0700 directory.
pub fn save(cfg: &ConfigFile) -> Result<()> {
    let d = dir();
    fs::create_dir_all(&d).with_context(|| format!("creating {}", d.display()))?;
    harden(&d, 0o700)?;

    let p = path();
    let body = serde_json::to_string_pretty(cfg).context("serializing the config")?;
    fs::write(&p, format!("{body}\n")).with_context(|| format!("writing {}", p.display()))?;
    harden(&p, 0o600)?;
    Ok(())
}

#[cfg(unix)]
fn harden(p: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting mode {mode:o} on {}", p.display()))
}

#[cfg(not(unix))]
fn harden(_p: &std::path::Path, _mode: u32) -> Result<()> {
    Ok(())
}

/// Warn when the config file is readable by anyone else. It holds a token
/// secret, and a token secret is a password.
#[cfg(unix)]
pub fn perms_warning() -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let p = path();
    let meta = fs::metadata(&p).ok()?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Some(format!(
            "{} is mode {mode:o}; it holds an API token secret. chmod 600 it.",
            p.display()
        ));
    }
    None
}

#[cfg(not(unix))]
pub fn perms_warning() -> Option<String> {
    None
}

/// Read `MLAB_PROXMOX_<name>`, then `PROXMOX_<name>`, then `PVE_<name>`.
pub fn env(name: &str) -> Option<String> {
    for prefix in ["MLAB_PROXMOX_", "PROXMOX_", "PVE_"] {
        if let Ok(v) = std::env::var(format!("{prefix}{name}")) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

pub fn env_bool(name: &str) -> Option<bool> {
    let v = env(name)?.to_ascii_lowercase();
    Some(!(v == "0" || v == "false" || v == "no"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_id_needs_a_realm_and_a_name() {
        assert!(validate_token_id("root@pam!mlab").is_ok());
        assert!(validate_token_id("root@pam").is_err());
        assert!(validate_token_id("root!mlab").is_err());
        assert!(validate_token_id("root@pam!").is_err());
    }

    #[test]
    fn a_host_loses_its_scheme_and_keeps_its_port() {
        assert_eq!(
            normalize_host("https://pve.lan:8006/").unwrap(),
            "pve.lan:8006"
        );
        assert_eq!(normalize_host(" 10.0.0.4 ").unwrap(), "10.0.0.4");
        assert!(normalize_host("pve.lan/api2").is_err());
    }

    #[test]
    fn the_default_port_is_filled_in_once() {
        let p = Profile {
            host: "pve.lan".into(),
            ..Default::default()
        };
        assert_eq!(p.endpoint().unwrap(), "pve.lan:8006");
        let p = Profile {
            host: "pve.lan:9006".into(),
            ..Default::default()
        };
        assert_eq!(p.endpoint().unwrap(), "pve.lan:9006");
    }

    #[test]
    fn redaction_keeps_only_the_tail() {
        assert_eq!(redact("0123456789abcdef"), "****cdef");
        assert_eq!(redact(""), "");
    }
}
