//! `footprint` — what this cluster looks like from outside, and what leaves it.

use anyhow::Result;
use serde_json::{json, Value};

use crate::checks::{exposure, i, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

/// The ports a Proxmox node listens on, as the documentation describes them.
/// Nothing is probed: this is what the software opens, not what a scan found.
const PORTS: [(&str, &str); 6] = [
    ("8006/tcp", "API and web interface"),
    ("3128/tcp", "SPICE proxy"),
    ("5900-5999/tcp", "VNC consoles"),
    ("22/tcp", "SSH, required between cluster nodes"),
    ("5405-5412/udp", "corosync, between cluster nodes"),
    ("111/tcp", "rpcbind, when an NFS storage is configured"),
];

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let names = collect::node_names(&mut f).await;

    let mut nodes = Vec::new();
    for n in &names {
        nodes.push(
            ui::spin(
                &format!("Reading {n}"),
                collect::node_without_updates(&mut f, n),
            )
            .await,
        );
    }
    let realms = f.list("/access/domains").await;
    let metrics = f.list("/cluster/metrics/server").await;
    let notifications = f.list("/cluster/notifications/targets").await;

    render::heading("Addresses");
    let mut addrs = Vec::new();
    for n in &nodes {
        for iface in &n.network {
            let cidr = s(iface, "cidr");
            if cidr.is_empty() {
                continue;
            }
            addrs.push(json!({
                "name": format!("{}:{}", n.name, s(iface, "iface")),
                "type": s(iface, "type"),
                "cidr": cidr,
                "gateway": s(iface, "gateway"),
                "state": if i(iface, "active") == Some(1) { "active" } else { "down" },
            }));
        }
    }
    render::list_auto(&addrs);

    render::heading("Certificates");
    let mut certs = Vec::new();
    for n in &nodes {
        for cert in &n.certificates {
            certs.push(json!({
                "name": format!("{}:{}", n.name, s(cert, "filename")),
                "subject": s(cert, "subject"),
                "issuer": s(cert, "issuer"),
                "notafter": i(cert, "notafter"),
                "san": cert.get("san")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" "))
                    .unwrap_or_default(),
            }));
        }
    }
    render::list_auto(&certs);

    render::heading("Listening, by design");
    let ports: Vec<Value> = PORTS
        .iter()
        .map(|(p, what)| json!({ "name": p, "service": what }))
        .collect();
    render::list_auto(&ports);
    ui::info("these are the ports Proxmox opens, not the result of a scan");

    render::heading("Readable before authentication");
    let pre: Vec<Value> = realms
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
    render::list_auto(&pre);
    ui::info("`GET /access/domains` needs no credentials: this list is public to anyone who reaches the API");

    render::heading("What leaves the cluster");
    let mut egress: Vec<Value> = metrics
        .iter()
        .map(|m| {
            json!({
                "name": s(m, "id"),
                "type": format!("metrics/{}", s(m, "type")),
                "target": format!("{}:{}", s(m, "server"), i(m, "port").unwrap_or(0)),
                "enable": i(m, "disable").map(|d| 1 - d).unwrap_or(1),
            })
        })
        .collect();
    egress.extend(notifications.iter().map(|t| {
        json!({
            "name": s(t, "name"),
            "type": format!("notify/{}", s(t, "type")),
            "target": s(t, "comment"),
            "enable": i(t, "disable").map(|d| 1 - d).unwrap_or(1),
        })
    }));
    render::list_auto(&egress);

    let mut r = Report::default();
    r.extend(exposure::all(
        &nodes,
        &metrics,
        &notifications,
        collect::now(),
    ));
    report::emit("Footprint checks", &r, &f.unreadable, None)
}
