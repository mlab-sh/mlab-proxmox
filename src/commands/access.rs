//! `access` — who can reach this cluster, with what, and for how long.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::checks::{access as achecks, flag, i, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum AccessCmd {
    /// Users, their realm, and whether they carry a second factor
    Users,
    /// API tokens, their privilege separation and their expiry
    Tokens,
    /// Roles and the privileges they carry
    Roles,
    /// The access control list: who holds which role, where
    Acl,
    /// Authentication realms
    Realms,
    /// The graded checks that apply to access control
    Check,
}

pub async fn run(c: &Client, cmd: AccessCmd) -> Result<()> {
    let mut f = Fetcher::new(c);
    let a = ui::spin("Reading access control", collect::access(&mut f)).await;

    match cmd {
        AccessCmd::Users => {
            let with_tfa: Vec<String> = a.tfa.iter().map(|t| s(t, "userid")).collect();
            let rows: Vec<Value> = a
                .users
                .iter()
                .map(|u| {
                    let id = s(u, "userid");
                    json!({
                        "name": id.clone(),
                        "enable": i(u, "enable").unwrap_or(1),
                        "type": s(u, "realm-type"),
                        "tfa": with_tfa.contains(&id),
                        "expire": i(u, "expire"),
                        "groups": s(u, "groups"),
                        "comment": s(u, "comment"),
                    })
                })
                .collect();
            render::heading("Users");
            render::list_auto(&rows);
            render::count(rows.len(), "user");
        }
        AccessCmd::Tokens => {
            if !a.tokens_readable {
                ui::warning(
                    "listing another user's tokens needs User.Modify; only this token's owner is shown",
                );
            }
            let rows: Vec<Value> = a
                .tokens
                .iter()
                .map(|t| {
                    json!({
                        "name": format!("{}!{}", s(t, "userid"), s(t, "tokenid")),
                        "privsep": i(t, "privsep").unwrap_or(1),
                        "expire": i(t, "expire"),
                        "comment": s(t, "comment"),
                    })
                })
                .collect();
            render::heading("API tokens");
            render::list_auto(&rows);
            render::count(rows.len(), "token");
        }
        AccessCmd::Roles => {
            let rows: Vec<Value> = a
                .roles
                .iter()
                .map(|r| {
                    json!({
                        "name": s(r, "roleid"),
                        "type": if flag(r, "special", false) { "built-in" } else { "custom" },
                        "privileges": s(r, "privs").split(',').filter(|p| !p.is_empty()).count(),
                    })
                })
                .collect();
            render::heading("Roles");
            render::list_auto(&rows);
            render::count(rows.len(), "role");

            // The privilege lists are the point, and they do not fit a column.
            let custom: Vec<&Value> = a
                .roles
                .iter()
                .filter(|r| !flag(r, "special", false))
                .collect();
            if !custom.is_empty() {
                render::heading("Custom roles in full");
                let pairs: Vec<(String, String)> = custom
                    .iter()
                    .map(|r| (s(r, "roleid"), s(r, "privs").replace(',', " ")))
                    .collect();
                let refs: Vec<(&str, String)> =
                    pairs.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
                render::pairs(&refs);
            }
        }
        AccessCmd::Acl => {
            let rows: Vec<Value> = a
                .acl
                .iter()
                .map(|e| {
                    json!({
                        "name": s(e, "ugid"),
                        "type": s(e, "type"),
                        "path": s(e, "path"),
                        "role": s(e, "roleid"),
                        "propagate": i(e, "propagate").unwrap_or(1),
                    })
                })
                .collect();
            render::heading("Access control list");
            render::list_auto(&rows);
            render::count(rows.len(), "grant");
        }
        AccessCmd::Realms => {
            let rows: Vec<Value> = a
                .realms
                .iter()
                .map(|r| {
                    json!({
                        "name": s(r, "realm"),
                        "type": s(r, "type"),
                        "tfa": s(r, "tfa"),
                        "comment": s(r, "comment"),
                    })
                })
                .collect();
            render::heading("Authentication realms");
            render::list_auto(&rows);
            render::count(rows.len(), "realm");
            ui::info("this list is readable without authentication, by anyone who reaches the API");
        }
        AccessCmd::Check => {
            let mut r = Report::default();
            r.extend(achecks::all(&a, collect::now()));
            return report::emit("Access control checks", &r, &f.unreadable, None);
        }
    }
    Ok(())
}
