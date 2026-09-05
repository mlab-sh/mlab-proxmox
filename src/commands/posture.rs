//! `posture` — the cluster-wide settings that claim to defend something.

use anyhow::Result;
use serde_json::Value;

use crate::checks::{cluster as cchecks, firewall as fwchecks, flag, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

pub async fn run(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);

    let status = ui::spin("Reading the cluster", f.list("/cluster/status")).await;
    let options = f.get("/cluster/options").await;
    let totem = f.get("/cluster/config/totem").await;
    let ha = f.list("/cluster/ha/resources").await;
    let qdevice = f.get("/cluster/config/qdevice").await;
    let ha_status = f.list("/cluster/ha/status/current").await;
    let replication = f.list("/cluster/replication").await;
    let fw = collect::firewall(&mut f).await;
    let guests = f.list("/cluster/resources").await;
    let guest_count = guests
        .iter()
        .filter(|r| matches!(s(r, "type").as_str(), "qemu" | "lxc"))
        .count();

    let cluster = status.iter().find(|r| s(r, "type") == "cluster");
    let nodes = status.iter().filter(|r| s(r, "type") == "node").count();

    render::heading("Cluster");
    render::pairs(&[
        (
            "shape",
            match cluster {
                Some(v) => format!("{} — {nodes} node(s)", s(v, "name")),
                None => "standalone node".to_string(),
            },
        ),
        (
            "quorum",
            match cluster
                .and_then(|v| v.get("quorate"))
                .and_then(Value::as_i64)
            {
                Some(1) => "quorate".to_string(),
                Some(_) => "LOST".to_string(),
                None => "n/a".to_string(),
            },
        ),
        (
            "migration",
            or(&s(&options, "migration"), "type=secure (default)"),
        ),
        ("fencing", or(&s(&options, "fencing"), "watchdog (default)")),
        ("ha", or(&s(&options, "ha"), "not configured")),
        (
            "mac prefix",
            or(&s(&options, "mac_prefix"), "BC:24:11 (default)"),
        ),
        ("proxy", or(&s(&options, "http_proxy"), "none")),
        (
            "consent banner",
            if s(&options, "consent-text").is_empty() {
                "none".to_string()
            } else {
                "set".to_string()
            },
        ),
        (
            "webauthn",
            if s(&options, "webauthn").is_empty() {
                "not configured".to_string()
            } else {
                "configured".to_string()
            },
        ),
    ]);

    render::heading("Firewall");
    render::pairs(&[
        (
            "datacenter switch",
            if flag(&fw.options, "enable", false) {
                "on".to_string()
            } else {
                "off".to_string()
            },
        ),
        ("rules", fw.rules.len().to_string()),
        ("security groups", fw.groups.len().to_string()),
        ("ip sets", fw.ipsets.len().to_string()),
        ("guests", guest_count.to_string()),
    ]);

    let mut r = Report::default();
    r.extend(cchecks::all(
        &status,
        &totem,
        &options,
        &ha,
        &replication,
        &qdevice,
        &ha_status,
    ));
    r.extend(fwchecks::cluster(&fw, guest_count));
    report::emit("Posture checks", &r, &f.unreadable, None)
}

fn or(v: &str, fallback: &str) -> String {
    if v.is_empty() {
        fallback.to_string()
    } else {
        v.to_string()
    }
}
