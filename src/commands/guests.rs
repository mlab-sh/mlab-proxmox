//! `guests` — the virtual machines and containers, and how they are configured.

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use serde_json::{json, Value};

use crate::checks::{
    firewall as fwchecks, flag, guests as gchecks, i, prop, propstring, s, Report,
};
use crate::collect::{self, Fetcher, Guest};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum GuestCmd {
    /// List every guest with its live state
    #[command(alias = "ls")]
    List(ListArgs),
    /// One guest: configuration, disks, network, snapshots
    Get { vmid: i64 },
    /// The hardening checks, over every guest or one of them
    #[command(alias = "harden")]
    Check(CheckArgs),
    /// What the QEMU guest agent reports from inside a guest
    Agent(CheckArgs),
}

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Only guests on this node
    #[arg(long, value_name = "NODE")]
    pub node: Option<String>,
    /// Only running guests
    #[arg(long)]
    pub running: bool,
}

#[derive(Args, Debug)]
pub struct CheckArgs {
    /// Only this guest
    #[arg(long, value_name = "VMID")]
    pub vmid: Option<i64>,
}

pub async fn run(c: &Client, cmd: GuestCmd) -> Result<()> {
    match cmd {
        GuestCmd::List(a) => list(c, &a).await,
        GuestCmd::Get { vmid } => get(c, vmid).await,
        GuestCmd::Check(a) => check(c, &a).await,
        GuestCmd::Agent(a) => agent(c, &a).await,
    }
}

async fn list(c: &Client, a: &ListArgs) -> Result<()> {
    let rows = ui::spin(
        "Reading the guests",
        c.request(
            reqwest::Method::GET,
            "/cluster/resources",
            &[("type".to_string(), "vm".to_string())],
            None,
        ),
    )
    .await?;
    let rows = rows.as_array().cloned().unwrap_or_default();

    let out: Vec<Value> = rows
        .iter()
        .filter(|g| match &a.node {
            Some(n) => &s(g, "node") == n,
            None => true,
        })
        .filter(|g| !a.running || s(g, "status") == "running")
        .map(|g| {
            json!({
                "name": s(g, "name"),
                "vmid": i(g, "vmid"),
                "type": s(g, "type"),
                "node": s(g, "node"),
                "status": if i(g, "template") == Some(1) { "template".to_string() } else { s(g, "status") },
                "uptime": i(g, "uptime"),
                "maxmem": i(g, "maxmem"),
                "maxdisk": i(g, "maxdisk"),
            })
        })
        .collect();

    render::heading("Guests");
    render::list_auto(&out);
    render::count(out.len(), "guest");
    Ok(())
}

/// Find one guest wherever it lives, and read it whole.
pub async fn find(f: &mut Fetcher<'_>, vmid: i64) -> Result<Guest> {
    let resources = f.list("/cluster/resources").await;
    let row = resources
        .iter()
        .find(|r| i(r, "vmid") == Some(vmid) && matches!(s(r, "type").as_str(), "qemu" | "lxc"));
    let Some(row) = row else {
        bail!("no guest {vmid} in this cluster");
    };
    let node = s(row, "node");
    let guests = collect::guests_of(f, &node).await;
    guests
        .into_iter()
        .find(|g| g.vmid == vmid)
        .ok_or_else(|| anyhow::anyhow!("guest {vmid} vanished between two reads"))
}

async fn get(c: &Client, vmid: i64) -> Result<()> {
    let mut f = Fetcher::new(c);
    let g = ui::spin(&format!("Reading guest {vmid}"), find(&mut f, vmid)).await?;

    if render::is_json() {
        render::print_json(&serde_json::to_value(&g)?);
        return Ok(());
    }

    render::heading(&format!("Guest {}", g.label()));
    render::pairs(&[
        ("node", g.node.clone()),
        (
            "kind",
            if g.kind == "lxc" {
                "container".to_string()
            } else {
                "virtual machine".to_string()
            },
        ),
        ("status", g.status.clone()),
        (
            "cores",
            format!(
                "{} core(s){}",
                i(&g.config, "cores").unwrap_or(0),
                match i(&g.config, "sockets") {
                    Some(s) if s > 1 => format!(" on {s} sockets"),
                    _ => String::new(),
                }
            ),
        ),
        (
            "memory",
            crate::commands::nodes::human_bytes(i(&g.config, "memory").unwrap_or(0) * 1024 * 1024),
        ),
        ("ostype", s(&g.config, "ostype")),
        (
            "protection",
            if flag(&g.config, "protection", false) {
                "on".to_string()
            } else {
                "off".to_string()
            },
        ),
    ]);

    render::heading("Network");
    let nets: Vec<Value> = g
        .nets()
        .iter()
        .map(|(k, raw)| {
            let p = propstring(raw, "model");
            json!({
                "name": k,
                "bridge": prop(&p, "bridge").unwrap_or(""),
                "vlan": prop(&p, "tag").unwrap_or(""),
                "trunks": prop(&p, "trunks").unwrap_or(""),
                "firewall": prop(&p, "firewall").unwrap_or("0"),
                "rate": prop(&p, "rate").unwrap_or(""),
                "mac": prop(&p, "virtio")
                    .or(prop(&p, "hwaddr"))
                    .or(prop(&p, "macaddr"))
                    .or(prop(&p, "e1000"))
                    .unwrap_or(""),
            })
        })
        .collect();
    render::list_auto(&nets);

    render::heading("Firewall");
    render::pairs(&[
        (
            "enabled",
            if flag(&g.firewall, "enable", false) {
                "yes".to_string()
            } else {
                "no".to_string()
            },
        ),
        ("policy in", s(&g.firewall, "policy_in")),
        ("policy out", s(&g.firewall, "policy_out")),
        ("rules", g.firewall_rules.len().to_string()),
    ]);

    // `current` is the live state the API lists alongside real snapshots.
    let snaps: Vec<Value> = g
        .snapshots
        .iter()
        .filter(|x| s(x, "name") != "current")
        .map(|x| {
            json!({
                "name": s(x, "name"),
                "snaptime": i(x, "snaptime"),
                "vmstate": i(x, "vmstate"),
                "description": s(x, "description"),
            })
        })
        .collect();
    if !snaps.is_empty() {
        render::heading("Snapshots");
        render::list_auto(&snaps);
    }

    render::heading("Configuration");
    render::one(&g.config);

    let now = collect::now();
    let mut r = Report::default();
    r.extend(gchecks::all(&g, now));
    r.extend(fwchecks::guest(&g, true));
    report::emit(
        &format!("Checks for {}", g.label()),
        &r,
        &f.unreadable,
        None,
    )
}

/// The inventory the guest gives of itself.
///
/// Worth saying plainly: this is the guest describing the guest. It costs no
/// packet on the network and no credential inside the machine, and it is an
/// inventory rather than a verification — a compromised guest answers whatever
/// it likes.
async fn agent(c: &Client, a: &CheckArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let guests = load(&mut f, a.vmid).await?;

    let rows: Vec<Value> = guests
        .iter()
        .filter(|g| g.kind == "qemu")
        .map(|g| {
            let os = g.agent.osinfo.get("result").unwrap_or(&g.agent.osinfo);
            json!({
                "name": g.label(),
                "status": if g.agent.alive {
                    "answering".to_string()
                } else if g.agent.configured {
                    "configured, silent".to_string()
                } else {
                    "no agent".to_string()
                },
                "os": s(os, "pretty-name"),
                "kernel": s(os, "kernel-release"),
                "hostname": g.agent.hostname.get("result")
                    .map(|r| s(r, "host-name"))
                    .unwrap_or_default(),
                "sessions": g.agent.users.len(),
                "addresses": g.agent.interfaces.len(),
            })
        })
        .collect();

    render::heading("Guest agents");
    render::list_auto(&rows);
    render::count(rows.len(), "guest");

    for g in guests.iter().filter(|g| g.agent.alive) {
        if g.agent.interfaces.is_empty() {
            continue;
        }
        render::heading(&format!("Interfaces of {}", g.label()));
        let nets: Vec<Value> = g
            .agent
            .interfaces
            .iter()
            .map(|i| {
                json!({
                    "name": s(i, "name"),
                    "mac": s(i, "hardware-address"),
                    "addresses": i.get("ip-addresses")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().map(|x| s(x, "ip-address")).collect::<Vec<_>>().join(" "))
                        .unwrap_or_default(),
                })
            })
            .collect();
        render::list_auto(&nets);
    }

    let silent = guests
        .iter()
        .filter(|g| g.agent.configured && !g.agent.alive && g.status == "running")
        .count();
    if silent > 0 {
        ui::warning(&format!(
            "{silent} running guest(s) declare an agent that does not answer: their snapshot \
             backups are taken without a filesystem freeze"
        ));
    }
    Ok(())
}

/// One guest, or every guest of the cluster.
async fn load(f: &mut Fetcher<'_>, vmid: Option<i64>) -> Result<Vec<Guest>> {
    if let Some(vmid) = vmid {
        return Ok(vec![find(f, vmid).await?]);
    }
    let mut all = Vec::new();
    for n in collect::node_names(f).await {
        let g = ui::spin(
            &format!("Reading the guests of {n}"),
            collect::guests_of(f, &n),
        )
        .await;
        all.extend(g);
    }
    Ok(all)
}

async fn check(c: &Client, a: &CheckArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let now = collect::now();
    let mut r = Report::default();

    let guests = load(&mut f, a.vmid).await?;

    // The cluster switch decides whether an unprotected guest is a finding.
    let fw_on = flag(&f.get("/cluster/firewall/options").await, "enable", false);
    for g in &guests {
        r.extend(gchecks::all(g, now));
        r.extend(fwchecks::guest(g, fw_on));
    }

    // IOMMU grouping is a property of the fleet, not of one guest, and it needs
    // the host's device list to say anything.
    let mut nodes = Vec::new();
    for name in guests
        .iter()
        .map(|g| g.node.clone())
        .collect::<std::collections::BTreeSet<_>>()
    {
        nodes.push(collect::node_without_updates(&mut f, &name).await);
    }
    r.extend(gchecks::iommu(&guests, &nodes));

    report::emit(
        &format!("Guest hardening ({} guest(s))", guests.len()),
        &r,
        &f.unreadable,
        None,
    )
}
