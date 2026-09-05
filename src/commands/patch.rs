//! `patch` — where updates would come from, and what is waiting.

use anyhow::Result;
use serde_json::{json, Value};

use crate::checks::{flag, patch as pchecks, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let names = collect::node_names(&mut f).await;

    let mut nodes = Vec::new();
    for n in &names {
        nodes.push(ui::spin(&format!("Reading {n}"), collect::node(&mut f, n)).await);
    }

    let rows: Vec<Value> = nodes
        .iter()
        .map(|n| {
            json!({
                "name": n.name,
                "version": s(&n.version, "version"),
                "kernel": n.status.get("current-kernel").and_then(|k| k.get("release")),
                "subscription": s(&n.subscription, "status"),
                "updates": match &n.updates {
                    Some(u) => json!(u.len()),
                    None => json!("unreadable"),
                },
            })
        })
        .collect();
    render::heading("Patch state");
    render::list_auto(&rows);

    for n in &nodes {
        let mut repos: Vec<Value> = Vec::new();
        if let Some(files) = n.repositories.get("files").and_then(Value::as_array) {
            for file in files {
                let path = s(file, "path");
                let Some(list) = file.get("repositories").and_then(Value::as_array) else {
                    continue;
                };
                for r in list {
                    repos.push(json!({
                        "name": r.get("Components")
                            .and_then(Value::as_array)
                            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
                            .unwrap_or_default(),
                        "enable": flag(r, "Enabled", true),
                        "uri": r.get("URIs")
                            .and_then(Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        "suite": r.get("Suites")
                            .and_then(Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                        "file": path.rsplit('/').next().unwrap_or_default(),
                    }));
                }
            }
        }
        render::heading(&format!("Repositories on {}", n.name));
        render::list_auto(&repos);

        if let Some(updates) = &n.updates {
            if !updates.is_empty() {
                render::heading(&format!("Pending on {}", n.name));
                render::list_auto(
                    &updates
                        .iter()
                        .map(|p| {
                            json!({
                                "name": s(p, "Package"),
                                "version": s(p, "Version"),
                                "installed": s(p, "OldVersion"),
                                "origin": s(p, "Origin"),
                            })
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }
    }

    let mut r = Report::default();
    r.extend(pchecks::all(&nodes));
    report::emit("Patch checks", &r, &f.unreadable, None)
}
