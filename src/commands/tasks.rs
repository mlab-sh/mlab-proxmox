//! `tasks` — who did what on this cluster, and whether it worked.
//!
//! The task log is the only history the API keeps: every start, stop, backup,
//! migration, console session and configuration change, with the user that
//! asked for it. It is finite, so absence of a task is not absence of an event.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::checks::{i, s};
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct TasksArgs {
    /// Only tasks that did not end in OK
    #[arg(long)]
    pub failed: bool,
    /// Only this task type, e.g. vzdump, qmstart, vncproxy
    #[arg(long, value_name = "TYPE")]
    pub kind: Option<String>,
    /// Only tasks started by this user
    #[arg(long, value_name = "USER")]
    pub user: Option<String>,
    /// How many to show
    #[arg(long, default_value_t = 50, value_name = "N")]
    pub limit: u32,
    /// Keep polling and print what appears, until interrupted
    #[arg(long)]
    pub follow: bool,
    /// Seconds between polls with --follow
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    pub interval: u64,
}

pub async fn run(c: &Client, a: &TasksArgs) -> Result<()> {
    if a.follow {
        return follow(c, a).await;
    }

    let rows = filter(ui::spin("Reading the task log", fetch(c, a)).await?, a);
    render::heading("Tasks");
    render::list_auto(&rows.iter().map(row).collect::<Vec<_>>());
    render::count(rows.len(), "task");

    let failed = rows.iter().filter(|t| !ok(t)).count();
    if failed > 0 && !a.failed {
        ui::warning(&format!("{failed} of them did not end in OK"));
    }
    Ok(())
}

/// Poll for new tasks. There is no event stream in the Proxmox API — the web
/// interface polls too — so this is a loop with a memory of what it printed.
async fn follow(c: &Client, a: &TasksArgs) -> Result<()> {
    if render::is_json() {
        ui::warning("--follow prints one JSON object per task as it appears");
    }
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut first = true;

    loop {
        let rows = filter(fetch(c, a).await?, a);
        // Oldest first, so a burst reads in the order it happened.
        for t in rows.iter().rev() {
            let upid = s(t, "upid");
            if !seen.insert(upid) {
                continue;
            }
            // The first pass establishes the baseline rather than replaying it.
            if first {
                continue;
            }
            if render::is_json() {
                println!("{}", serde_json::to_string(&row(t))?);
            } else {
                println!(
                    "  {}  {:<10}  {:<22}  {}",
                    crate::pve::iso8601(i(t, "starttime").unwrap_or(0)),
                    s(t, "type"),
                    s(t, "id"),
                    if ok(t) {
                        s(t, "status")
                    } else {
                        format!("!! {}", s(t, "status"))
                    }
                );
            }
        }
        if first {
            ui::info(&format!(
                "watching {} task(s) every {}s; ^C to stop",
                seen.len(),
                a.interval
            ));
            first = false;
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(a.interval.max(2))) => {}
        }
    }
}

/// The cluster-wide list takes no parameters and returns a short tail, so the
/// filters go to the per-node endpoint instead, which accepts all of them.
async fn fetch(c: &Client, a: &TasksArgs) -> Result<Vec<Value>> {
    let nodes = c.list("/nodes").await?;
    let mut query: Vec<(String, String)> = vec![
        ("limit".into(), a.limit.to_string()),
        ("source".into(), "all".into()),
    ];
    if a.failed {
        query.push(("errors".into(), "1".into()));
    }
    if let Some(k) = &a.kind {
        query.push(("typefilter".into(), k.clone()));
    }
    if let Some(u) = &a.user {
        query.push(("userfilter".into(), u.clone()));
    }

    let mut out = Vec::new();
    for n in &nodes {
        let name = s(n, "node");
        let path = format!("/nodes/{}/tasks", crate::pve::esc(&name));
        match c.request(reqwest::Method::GET, &path, &query, None).await {
            Ok(Value::Array(rows)) => out.extend(rows),
            Ok(_) => {}
            Err(e) => ui::warning(&format!("{name}: {e}")),
        }
    }
    // Newest first, across every node.
    out.sort_by_key(|t| -i(t, "starttime").unwrap_or(0));
    out.truncate(a.limit as usize);
    Ok(out)
}

fn filter(rows: Vec<Value>, a: &TasksArgs) -> Vec<Value> {
    rows.into_iter()
        .filter(|t| !a.failed || !ok(t))
        .filter(|t| match &a.kind {
            Some(k) => &s(t, "type") == k,
            None => true,
        })
        .filter(|t| match &a.user {
            Some(u) => s(t, "user").contains(u.as_str()),
            None => true,
        })
        .take(a.limit as usize)
        .collect()
}

/// A task with no status yet is still running, which is not a failure.
fn ok(t: &Value) -> bool {
    let st = s(t, "status");
    st.is_empty() || st == "OK"
}

fn row(t: &Value) -> Value {
    json!({
        "name": s(t, "id"),
        "type": s(t, "type"),
        "node": s(t, "node"),
        "status": if s(t, "status").is_empty() { "running".to_string() } else { s(t, "status") },
        "starttime": i(t, "starttime"),
        "user": s(t, "user"),
    })
}
