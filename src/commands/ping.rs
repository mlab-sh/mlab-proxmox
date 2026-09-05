//! `ping` — can this profile reach its cluster, and what is on the other end.

use anyhow::Result;
use serde_json::Value;

use crate::cli::Ctx;
use crate::pve::Client;
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let started = std::time::Instant::now();
    let version = ui::spin("Reaching the cluster", c.get("/version")).await?;
    let took = ui::elapsed(started.elapsed());

    let release = version
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    // A standalone node answers this too: one entry, quorate, itself.
    let status = c.list("/cluster/status").await.unwrap_or_default();
    let nodes: Vec<&Value> = status
        .iter()
        .filter(|r| r.get("type").and_then(Value::as_str) == Some("node"))
        .collect();
    let cluster = status
        .iter()
        .find(|r| r.get("type").and_then(Value::as_str) == Some("cluster"));
    let quorate = cluster
        .and_then(|v| v.get("quorate"))
        .and_then(Value::as_i64)
        .map(|q| q == 1);
    let local = nodes
        .iter()
        .find(|r| r.get("local").and_then(Value::as_i64) == Some(1))
        .or(nodes.first())
        .and_then(|n| n.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let online = nodes
        .iter()
        .filter(|n| n.get("online").and_then(Value::as_i64) == Some(1))
        .count();

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "profile": ctx.name,
            "endpoint": c.base(),
            "version": release,
            "node": local,
            "nodes": nodes.len(),
            "nodesOnline": online,
            "quorate": quorate,
            "tlsVerified": !c.insecure(),
            "elapsed": took,
        }));
        return Ok(());
    }

    ui::success(&format!("answered in {took}"));

    let cluster_line = match (cluster, quorate) {
        (Some(v), Some(q)) => format!(
            "{} — {}/{} node(s) online, {}",
            v.get("name").and_then(Value::as_str).unwrap_or("cluster"),
            online,
            nodes.len(),
            if q { "quorate" } else { "NO QUORUM" }
        ),
        _ => "standalone node".to_string(),
    };

    render::pairs(&[
        ("profile", ctx.name.clone()),
        ("endpoint", c.base().to_string()),
        ("release", format!("Proxmox VE {release}")),
        ("answered by", local),
        ("cluster", cluster_line),
        (
            "tls",
            if c.insecure() {
                "not verified"
            } else {
                "verified"
            }
            .to_string(),
        ),
    ]);

    if quorate == Some(false) {
        ui::warning("the cluster has no quorum; configuration is read-only until it returns");
    }
    Ok(())
}
