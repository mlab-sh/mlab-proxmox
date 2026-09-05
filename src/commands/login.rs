//! `login` — create or update a profile, prove it works, save it.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::Args;
use serde_json::Value;

use crate::cli::Overrides;
use crate::commands::prompt::{ask, ask_secret};
use crate::pve::{config, Client, Profile};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Profile name to create or update
    #[arg(long, short = 'n', default_value = "default", value_name = "NAME")]
    pub name: String,

    /// Make this profile the default one
    #[arg(long)]
    pub set_default: bool,

    /// Save without checking that the credentials work
    #[arg(long)]
    pub no_test: bool,

    /// Never prompt; fail when something is missing
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(ov: &Overrides, args: &LoginArgs) -> Result<()> {
    let mut cfg = config::load()?;
    let existing = cfg.profiles.get(&args.name).cloned();
    let base = existing.clone().unwrap_or_default();
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();

    let mut host = ov
        .host
        .clone()
        .or_else(|| config::env("HOST"))
        .unwrap_or_else(|| base.host.clone());
    if host.is_empty() {
        if !interactive {
            bail!("--host is required");
        }
        host = ask("node host (e.g. 192.168.1.10 or pve.lan)", "")?;
    }
    let host = config::normalize_host(&host)?;

    let token_id = token_id(ov, &base, interactive)?;
    let token_secret = token_secret(ov, &base, interactive)?;

    let mut p = Profile {
        host,
        port: ov.port.or(base.port),
        token_id,
        token_secret,
        fingerprint: base.fingerprint.clone(),
        insecure: ov.insecure.or(base.insecure),
        output: ov.output.clone().or(base.output.clone()),
    };
    p.validate()?;

    if args.no_test {
        ui::warning("skipping the connection test (--no-test)");
    } else {
        verify(&mut p).await?;
    }

    let first = cfg.profiles.is_empty();
    cfg.profiles.insert(args.name.clone(), p.clone());
    if args.set_default || first || cfg.default_profile.is_none() {
        cfg.default_profile = Some(args.name.clone());
    }
    config::save(&cfg)?;

    ui::success(&format!(
        "saved profile {:?} to {}",
        args.name,
        config::path().display()
    ));
    render::one(&serde_json::to_value(p.redacted())?);
    Ok(())
}

/// A token id from the flags, the environment, the stored profile, or the
/// terminal.
fn token_id(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let mut id = ov
        .token_id
        .clone()
        .or_else(|| config::env("TOKEN_ID"))
        .unwrap_or_default();

    if id.is_empty() {
        if !base.token_id.is_empty() {
            id = base.token_id.clone();
        } else if interactive {
            id = ask("token id (user@realm!tokenname)", "root@pam!mlab")?;
        } else {
            bail!("--token-id or PROXMOX_TOKEN_ID is required");
        }
    }
    let id = id.trim().to_string();
    config::validate_token_id(&id)?;
    Ok(id)
}

/// The secret is shown once, when the token is created; after that it only
/// exists here.
fn token_secret(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let mut secret = ov
        .token_secret
        .clone()
        .or_else(|| config::env("TOKEN_SECRET"))
        .unwrap_or_default();

    if secret.is_empty() {
        if !base.token_secret.is_empty() {
            ui::info(&format!(
                "keeping the stored token secret ({})",
                config::redact(&base.token_secret)
            ));
            secret = base.token_secret.clone();
        } else if interactive {
            secret = ask_secret("token secret (shown once, at token creation)")?;
        } else {
            bail!("--token-secret or PROXMOX_TOKEN_SECRET is required");
        }
    }

    if secret.trim().is_empty() {
        bail!("the token secret is empty");
    }
    Ok(secret.trim().to_string())
}

/// Prove the profile works before it is written, and record what answered.
async fn verify(p: &mut Profile) -> Result<()> {
    let c = Client::new(p, Duration::from_secs(30))?;

    let version = ui::spin(&format!("Testing {}", c.base()), c.get("/version")).await?;
    let release = version
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    ui::success(&format!("connected to Proxmox VE {release}"));

    // `/cluster/status` names the node that answered, which is the one whose
    // certificate this profile is actually pinned against.
    if let Ok(rows) = c.list("/cluster/status").await {
        let nodes: Vec<&Value> = rows
            .iter()
            .filter(|r| r.get("type").and_then(Value::as_str) == Some("node"))
            .collect();
        let local = nodes
            .iter()
            .find(|r| r.get("local").and_then(Value::as_i64) == Some(1))
            .or(nodes.first())
            .copied();

        if let Some(node) = local {
            let name = node.get("name").and_then(Value::as_str).unwrap_or_default();
            ui::info(&format!(
                "node {name}, {} node(s) in the cluster",
                nodes.len()
            ));
            if let Some(fp) = fingerprint(&c, name).await {
                match &p.fingerprint {
                    Some(old) if old != &fp => ui::warning(&format!(
                        "the certificate of {name} changed since the last login\n    was {old}\n    now {fp}"
                    )),
                    _ => {}
                }
                p.fingerprint = Some(fp);
            }
        }
    }

    // The token's own reach, so a later empty result can be read correctly.
    if let Ok(perms) = c.get("/access/permissions").await {
        let paths = perms.as_object().map(|o| o.len()).unwrap_or(0);
        let root_privs = perms
            .get("/")
            .and_then(Value::as_object)
            .map(|o| o.len())
            .unwrap_or(0);
        ui::info(&format!(
            "the token holds privileges on {paths} path(s), {root_privs} of them at /"
        ));
        if root_privs == 0 {
            ui::warning("nothing is granted at `/`; cluster-wide reads will come back empty");
        }
    }

    if p.insecure() {
        ui::warning("TLS certificate verification is off for this profile");
    }
    Ok(())
}

/// The SHA-256 fingerprint of whichever certificate the API serves.
async fn fingerprint(c: &Client, node: &str) -> Option<String> {
    let path = format!("/nodes/{}/certificates/info", crate::pve::esc(node));
    let certs = c.list(&path).await.ok()?;
    let pick = certs
        .iter()
        .find(|v| v.get("filename").and_then(Value::as_str) == Some("pveproxy-ssl.pem"))
        .or_else(|| certs.first())?;
    pick.get("fingerprint")
        .and_then(Value::as_str)
        .map(str::to_string)
}
