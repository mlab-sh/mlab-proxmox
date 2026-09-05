//! `nodes` — the hosts of the cluster, and what they run.

use anyhow::{bail, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::checks::{exposure, i, patch, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum NodeCmd {
    /// List the nodes with their live state
    #[command(alias = "ls")]
    List,
    /// One node in full: hardware, services, certificates, disks
    Get { node: String },
    /// The graded checks that apply to hosts
    Check,
}

pub async fn run(c: &Client, cmd: NodeCmd) -> Result<()> {
    match cmd {
        NodeCmd::List => list(c).await,
        NodeCmd::Get { node } => get(c, &node).await,
        NodeCmd::Check => check(c).await,
    }
}

async fn list(c: &Client) -> Result<()> {
    let rows = ui::spin("Reading the nodes", c.list("/nodes")).await?;
    let out: Vec<Value> = rows
        .iter()
        .map(|n| {
            json!({
                "name": s(n, "node"),
                "status": s(n, "status"),
                "uptime": i(n, "uptime"),
                "cpu": n.get("cpu"),
                "maxcpu": i(n, "maxcpu"),
                "mem": i(n, "mem"),
                "maxmem": i(n, "maxmem"),
                "level": s(n, "level"),
            })
        })
        .collect();
    render::heading("Nodes");
    render::list_auto(&out);
    render::count(out.len(), "node");
    Ok(())
}

async fn get(c: &Client, name: &str) -> Result<()> {
    let mut f = Fetcher::new(c);
    let n = ui::spin(&format!("Reading {name}"), collect::node(&mut f, name)).await;
    if n.status.is_null() && n.version.is_null() {
        bail!("node {name:?} answered nothing; is the name right? (`mlab-proxmox nodes list`)");
    }

    if render::is_json() {
        render::print_json(&serde_json::to_value(&n)?);
        return Ok(());
    }

    let kernel = n
        .status
        .get("current-kernel")
        .and_then(|k| k.get("release"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let boot = n
        .status
        .get("boot-info")
        .and_then(|b| b.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let cpu_model = n
        .status
        .get("cpuinfo")
        .and_then(|c| c.get("model"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let cpus = n
        .status
        .get("cpuinfo")
        .and_then(|c| c.get("cpus"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let mem_total = n
        .status
        .get("memory")
        .and_then(|m| m.get("total"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let mem_used = n
        .status
        .get("memory")
        .and_then(|m| m.get("used"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    render::heading(&format!("Node {name}"));
    render::pairs(&[
        (
            "release",
            format!("Proxmox VE {}", s(&n.version, "version")),
        ),
        ("kernel", format!("{kernel} ({boot} boot)")),
        ("cpu", format!("{cpu_model} × {cpus}")),
        (
            "memory",
            format!(
                "{} of {} used",
                human_bytes(mem_used),
                human_bytes(mem_total)
            ),
        ),
        ("subscription", s(&n.subscription, "status")),
        ("dns", s(&n.dns, "dns1")),
        ("timezone", s(&n.time, "timezone")),
    ]);

    render::heading("Services");
    let svc: Vec<Value> = n
        .services
        .iter()
        .filter(|x| s(x, "state") != "dead" || s(x, "unit-state") == "enabled")
        .map(|x| {
            json!({
                "name": s(x, "name"),
                "state": s(x, "state"),
                "enabled": s(x, "unit-state"),
                "desc": s(x, "desc"),
            })
        })
        .collect();
    render::list_auto(&svc);

    render::heading("Network");
    let net: Vec<Value> = n
        .network
        .iter()
        .map(|x| {
            json!({
                "name": s(x, "iface"),
                "type": s(x, "type"),
                "state": if i(x, "active") == Some(1) { "active" } else { "down" },
                "cidr": s(x, "cidr"),
                "gateway": s(x, "gateway"),
                "bridge_ports": s(x, "bridge_ports"),
                "vlan_aware": i(x, "bridge_vlan_aware"),
            })
        })
        .collect();
    render::list_auto(&net);

    render::heading("Disks");
    let disks: Vec<Value> = n
        .disks
        .iter()
        .map(|d| {
            json!({
                "name": s(d, "devpath"),
                "type": s(d, "type"),
                "model": s(d, "model"),
                "size": i(d, "size"),
                "health": s(d, "health"),
                "used": s(d, "used"),
            })
        })
        .collect();
    render::list_auto(&disks);

    render::heading("Certificates");
    let certs: Vec<Value> = n
        .certificates
        .iter()
        .map(|x| {
            json!({
                "name": s(x, "filename"),
                "subject": s(x, "subject"),
                "issuer": s(x, "issuer"),
                "notafter": i(x, "notafter"),
                "keytype": s(x, "public-key-type"),
                "keybits": i(x, "public-key-bits"),
            })
        })
        .collect();
    render::list_auto(&certs);

    let now = collect::now();
    let mut r = Report::default();
    r.extend(exposure::all(std::slice::from_ref(&n), &[], &[], now));
    r.extend(patch::all(std::slice::from_ref(&n)));
    report::emit(&format!("Checks for {name}"), &r, &f.unreadable, None)
}

async fn check(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let names = collect::node_names(&mut f).await;
    let mut nodes = Vec::new();
    for name in &names {
        let n = ui::spin(&format!("Reading {name}"), collect::node(&mut f, name)).await;
        nodes.push(n);
    }
    let now = collect::now();
    let mut r = Report::default();
    r.extend(exposure::all(&nodes, &[], &[], now));
    r.extend(patch::all(&nodes));
    report::emit("Host checks", &r, &f.unreadable, None)
}

/// Base-1024 sizes, for the few places a command composes its own sentence.
pub fn human_bytes(b: i64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if b < 1024 {
        return format!("{b} B");
    }
    let mut n = b as f64 / 1024.0;
    let mut unit = UNITS[0];
    for u in UNITS.iter().skip(1) {
        if n < 1024.0 {
            break;
        }
        n /= 1024.0;
        unit = u;
    }
    format!("{n:.1} {unit}")
}
