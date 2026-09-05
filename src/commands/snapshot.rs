//! `snapshot` — one dated, secret-free record of everything the token can read.
//!
//! Detection on Proxmox is differential: there is no event stream and no alert
//! endpoint, so the way to notice a change is to have written down what things
//! looked like before. Everything else in this CLI reads the present; this is
//! the command that gives it a past.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::collect;
use crate::pve::{config, Client};
use crate::ui::{self, render};

/// Field names whose value never belongs in a file on disk. Matched on a
/// lowercased key, as a substring, so `cipassword` and `smtp-password` both go.
const SECRET_KEYS: [&str; 6] = [
    "password",
    "secret",
    "privatekey",
    "private-key",
    "token_secret",
    "csrf",
];

/// Bulky fields with no value in a diff: the certificate body changes whenever
/// the certificate does, and the fingerprint already says that.
const DROP_KEYS: [&str; 2] = ["pem", "digest"];

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    /// Write here instead of the default directory
    // No short form: `-o` is the global --output.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
    /// Print the record on stdout instead of writing a file
    #[arg(long)]
    pub stdout: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &SnapshotArgs) -> Result<()> {
    let inv = collect::all(c).await?;
    let mut v = serde_json::to_value(&inv)?;
    redact(&mut v);

    let summary = json!({
        "collected": inv.collected,
        "endpoint": inv.endpoint,
        "nodes": inv.nodes.len(),
        "guests": inv.guests.len(),
        "storages": inv.storages.len(),
        "users": inv.access.users.len(),
        "acl": inv.access.acl.len(),
        "backupJobs": inv.backup_jobs.len(),
        "unreadable": inv.unreadable.len(),
    });

    if a.stdout {
        render::print_json(&v);
        return Ok(());
    }

    let path = match &a.out {
        Some(p) => p.clone(),
        None => default_path(&ctx.name, &inv.collected),
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let body = serde_json::to_string_pretty(&v)?;
    std::fs::write(&path, format!("{body}\n"))
        .with_context(|| format!("writing {}", path.display()))?;

    if render::is_json() {
        let mut out = summary.clone();
        out["path"] = json!(path.display().to_string());
        render::print_json(&out);
        return Ok(());
    }

    ui::success(&format!("wrote {}", path.display()));
    render::one(&summary);
    if inv.unreadable.is_empty() {
        ui::info("every catalogued route answered");
    } else {
        ui::warning(&format!(
            "{} route(s) were refused and are recorded as unreadable in the file",
            inv.unreadable.len()
        ));
    }
    Ok(())
}

/// `$HOME/.mlab/proxmox-snapshots/<profile>-<timestamp>.json`
pub fn default_path(profile: &str, collected: &str) -> PathBuf {
    let stamp = collected.replace([':', '-'], "").replace('Z', "");
    dir().join(format!("{}-{stamp}.json", sanitize(profile)))
}

pub fn dir() -> PathBuf {
    config::dir().join("proxmox-snapshots")
}

/// The newest snapshot on disk for a profile, which is what `shadow` compares
/// the present against.
pub fn latest(profile: &str) -> Option<PathBuf> {
    let prefix = format!("{}-", sanitize(profile));
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir())
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|x| x.to_str()) == Some("json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with(&prefix))
                    .unwrap_or(false)
        })
        .collect();
    files.sort();
    files.pop()
}

pub fn load(path: &Path) -> Result<Value> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Blank every secret and drop every bulky field, in place, at any depth.
pub fn redact(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                let lower = k.to_ascii_lowercase();
                if DROP_KEYS.iter().any(|d| lower == *d) {
                    map.remove(&k);
                    continue;
                }
                if SECRET_KEYS.iter().any(|s| lower.contains(s)) {
                    map.insert(k, Value::String("(redacted)".into()));
                    continue;
                }
                if let Some(child) = map.get_mut(&k) {
                    redact(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_blanked_at_any_depth_and_bulk_is_dropped() {
        let mut v = json!({
            "guests": [{ "config": { "cipassword": "hunter2", "name": "a" } }],
            "certs": [{ "pem": "-----BEGIN", "fingerprint": "AA:BB" }],
            "smtp": { "SMTP-Password": "x" }
        });
        redact(&mut v);
        assert_eq!(v["guests"][0]["config"]["cipassword"], "(redacted)");
        assert_eq!(v["guests"][0]["config"]["name"], "a");
        assert!(v["certs"][0].get("pem").is_none());
        assert_eq!(v["certs"][0]["fingerprint"], "AA:BB");
        assert_eq!(v["smtp"]["SMTP-Password"], "(redacted)");
    }

    #[test]
    fn a_snapshot_name_carries_the_profile_and_the_time() {
        let p = default_path("lab", "2026-09-05T18:04:11Z");
        let name = p.file_name().unwrap().to_str().unwrap();
        assert_eq!(name, "lab-20260905T180411.json");
    }
}
