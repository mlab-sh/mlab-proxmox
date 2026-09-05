//! `whoami` — what this token is, and everything it is allowed to read.
//!
//! Every other command's honesty rests on this one: a check that reports
//! nothing because the token cannot see the data must not read as a pass.

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::{Map, Value};

use crate::cli::Ctx;
use crate::pve::Client;
use crate::ui::{self, render};

/// The privileges the built-in `PVEAuditor` role carries, read from
/// `pve-access-control`. A token holding all of them at `/` reaches every
/// configuration read this CLI is built on.
const AUDIT_PRIVS: [&str; 7] = [
    "Sys.Audit",
    "VM.Audit",
    "VM.GuestAgent.Audit",
    "Datastore.Audit",
    "SDN.Audit",
    "Pool.Audit",
    "Mapping.Audit",
];

/// Reads that need a privilege beyond the auditor role, and what they cost.
const EXTRAS: [(&str, &str, &str); 3] = [
    (
        "Sys.Syslog",
        "journal, syslog, firewall logs",
        "read-only; the only route to detection rather than configuration review",
    ),
    (
        "Sys.Modify",
        "pending package updates",
        "also rewrites host network configuration — grant with care",
    ),
    (
        "User.Modify",
        "the API tokens of other users",
        "also grants user administration — grant with care",
    ),
];

#[derive(Args, Debug)]
pub struct WhoamiArgs {
    /// Only show grants under this ACL path
    #[arg(long, value_name = "PATH")]
    pub path: Option<String>,
}

pub async fn run(c: &Client, ctx: &Ctx, args: &WhoamiArgs) -> Result<()> {
    let perms = ui::spin(
        "Reading the token's own permissions",
        c.get("/access/permissions"),
    )
    .await?;

    let empty = Map::new();
    let map = perms.as_object().unwrap_or(&empty);
    let root: Vec<String> = map
        .get("/")
        .and_then(Value::as_object)
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();

    let missing: Vec<&str> = AUDIT_PRIVS
        .iter()
        .copied()
        .filter(|p| !root.iter().any(|r| r == p))
        .collect();

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "profile": ctx.name,
            "token": ctx.profile.token_id,
            "permissions": perms,
            "auditPrivilegesAtRoot": AUDIT_PRIVS
                .iter()
                .filter(|p| root.iter().any(|r| &r == p))
                .collect::<Vec<_>>(),
            "missingAuditPrivileges": missing,
            "extras": EXTRAS
                .iter()
                .map(|(priv_, unlocks, note)| serde_json::json!({
                    "privilege": priv_,
                    "unlocks": unlocks,
                    "note": note,
                    "held": root.iter().any(|r| r == priv_),
                }))
                .collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    render::heading(&format!("Token {}", ctx.profile.token_id));

    // A privilege list runs past any sensible column width, so this is a
    // key/value block rather than a table: nothing here may be clipped.
    let mut rows: Vec<(String, String)> = map
        .iter()
        .filter(|(path, _)| match &args.path {
            Some(want) => path.starts_with(want),
            None => true,
        })
        .map(|(path, privs)| {
            let mut names: Vec<&str> = privs
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect())
                .unwrap_or_default();
            names.sort_unstable();
            (path.clone(), names.join(" "))
        })
        .collect();
    rows.sort();

    if rows.is_empty() {
        ui::warning("this token holds no privilege anywhere; every read will be empty or refused");
        return Ok(());
    }
    let pairs: Vec<(&str, String)> = rows.iter().map(|(p, v)| (p.as_str(), v.clone())).collect();
    render::pairs(&pairs);
    render::count(rows.len(), "path");

    render::heading("Audit coverage at /");
    if missing.is_empty() {
        ui::success("every PVEAuditor privilege is held at / — the configuration surface is open");
    } else {
        ui::warning(&format!(
            "missing at /: {} — the reads behind them come back empty, not clean",
            missing.join(", ")
        ));
    }

    render::heading("Beyond the auditor role");
    println!();
    for (priv_, unlocks, note) in EXTRAS {
        let held = root.iter().any(|r| r == priv_);
        let marker = if held { "✔".green() } else { "·".dimmed() };
        let name = if held { priv_.green() } else { priv_.normal() };
        println!("  {marker} {name}  {}", unlocks.dimmed());
        if !held {
            println!("      {}", note.dimmed());
        }
    }
    println!();
    Ok(())
}
