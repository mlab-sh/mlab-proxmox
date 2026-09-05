//! `logins` — who authenticated, who failed, and from where.
//!
//! The cluster log is the only place a failed authentication is visible
//! through the API: the task log records what a session did, never the
//! attempts that never became one.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::checks::{detection, i, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct LoginsArgs {
    /// Only the attempts that failed
    #[arg(long)]
    pub failed: bool,
    /// How many log entries to read
    #[arg(long, default_value_t = 500, value_name = "N")]
    pub limit: u32,
}

pub async fn run(c: &Client, a: &LoginsArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let log = ui::spin("Reading the cluster log", f.list("/cluster/log")).await;

    let rows: Vec<Value> = log
        .iter()
        .filter(|r| {
            let m = s(r, "msg").to_lowercase();
            m.contains("auth")
                && (m.contains("successful") || m.contains("failure") || m.contains("failed"))
        })
        .map(|r| {
            let msg = s(r, "msg");
            let failed = !msg.to_lowercase().contains("successful");
            json!({
                "name": if failed { "failed" } else { "ok" },
                "user": if s(r, "user").is_empty() { extract(&msg, "user=") } else { s(r, "user") },
                "node": s(r, "node"),
                "starttime": i(r, "time"),
                "source": extract(&msg, "rhost="),
                "detail": msg.chars().take(70).collect::<String>(),
            })
        })
        .filter(|r| !a.failed || s(r, "name") == "failed")
        .take(a.limit as usize)
        .collect();

    render::heading("Authentication");
    render::list_auto(&rows);
    render::count(rows.len(), "event");

    let failed = rows.iter().filter(|r| s(r, "name") == "failed").count();
    if failed == 0 && !render::is_json() {
        ui::success("no failed authentication in the visible log");
    }

    // The log rotates, so what is here bounds the answer rather than giving it.
    let mut r = Report::default();
    r.extend(detection::all(&log, &[], collect::now()));
    report::emit("What that adds up to", &r, &f.unreadable, None)
}

/// The value following `key`, up to the next space or quote.
fn extract(msg: &str, key: &str) -> String {
    let Some(start) = msg.find(key) else {
        return String::new();
    };
    let rest = &msg[start + key.len()..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '\'' || c == ',')
        .unwrap_or(rest.len());
    rest[..end].trim().to_string()
}
