//! `blast` — what one compromised guest reaches.
//!
//! The honest answer on Proxmox is layer 2: a guest with a NIC on a bridge
//! reaches every other guest on that bridge and VLAN, and nothing in the
//! hypervisor stops it unless the firewall is on at both the datacenter and
//! the guest. Everything above that is the network's business, not Proxmox's,
//! and this command says so rather than guessing.

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::checks::{flag, prop, propstring, s, Finding, Report, Severity};
use crate::collect::{self, Fetcher, Guest};
use crate::commands::guests;
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct BlastArgs {
    /// The guest to start from
    pub vmid: i64,
}

pub async fn run(c: &Client, a: &BlastArgs) -> Result<()> {
    let mut f = Fetcher::new(c);
    let target = ui::spin(
        &format!("Reading guest {}", a.vmid),
        guests::find(&mut f, a.vmid),
    )
    .await?;

    let names = collect::node_names(&mut f).await;
    let mut all = Vec::new();
    for n in &names {
        all.extend(collect::guests_of(&mut f, n).await);
    }
    let node = collect::node_without_updates(&mut f, &target.node).await;
    let cluster_fw = flag(&f.get("/cluster/firewall/options").await, "enable", false);

    // Every (bridge, vlan) the target sits on.
    let segments: Vec<(String, String, String)> = target
        .nets()
        .iter()
        .map(|(k, raw)| {
            let p = propstring(raw, "model");
            (
                k.clone(),
                prop(&p, "bridge").unwrap_or_default().to_string(),
                prop(&p, "tag").unwrap_or_default().to_string(),
            )
        })
        .collect();

    render::heading(&format!("Blast radius of {}", target.label()));
    render::pairs(&[
        ("node", target.node.clone()),
        (
            "guest firewall",
            if flag(&target.firewall, "enable", false) {
                "on".to_string()
            } else {
                "off".to_string()
            },
        ),
        (
            "datacenter firewall",
            if cluster_fw { "on" } else { "off" }.to_string(),
        ),
        (
            "segments",
            segments
                .iter()
                .map(|(k, b, t)| {
                    if t.is_empty() {
                        format!("{k}→{b} untagged")
                    } else {
                        format!("{k}→{b} vlan {t}")
                    }
                })
                .collect::<Vec<_>>()
                .join(", "),
        ),
    ]);

    // Neighbours: same bridge, same tag, different guest.
    let mut neighbours: Vec<Value> = Vec::new();
    for g in &all {
        if g.vmid == target.vmid {
            continue;
        }
        for (nic, raw) in g.nets() {
            let p = propstring(&raw, "model");
            let bridge = prop(&p, "bridge").unwrap_or_default().to_string();
            let tag = prop(&p, "tag").unwrap_or_default().to_string();
            let shared = segments.iter().any(|(_, b, t)| b == &bridge && t == &tag);
            if !shared {
                continue;
            }
            neighbours.push(json!({
                "name": g.label(),
                "node": g.node,
                "status": g.status,
                "nic": nic,
                "bridge": bridge,
                "vlan": if tag.is_empty() { "untagged".to_string() } else { tag },
                "filtered": guest_filtered(g, cluster_fw),
            }));
        }
    }

    render::heading("Reachable at layer 2");
    render::list_auto(&neighbours);
    render::count(neighbours.len(), "guest");

    // The host itself is on those bridges when the bridge carries its address.
    let host_ifaces: Vec<Value> = node
        .network
        .iter()
        .filter(|i| {
            let name = s(i, "iface");
            segments.iter().any(|(_, b, _)| b == &name) && !s(i, "cidr").is_empty()
        })
        .map(|i| {
            json!({
                "name": s(i, "iface"),
                "cidr": s(i, "cidr"),
                "gateway": s(i, "gateway"),
                "comment": "the host answers on this segment: 8006, 22, 3128",
            })
        })
        .collect();
    if !host_ifaces.is_empty() {
        render::heading("The host, on the same segment");
        render::list_auto(&host_ifaces);
    }

    let mut r = Report::default();
    r.extend(verdict(
        &target,
        &neighbours,
        cluster_fw,
        !host_ifaces.is_empty(),
    ));
    report::emit("What this means", &r, &f.unreadable, None)
}

/// Whether anything at all filters this guest's traffic.
fn guest_filtered(g: &Guest, cluster_fw: bool) -> &'static str {
    if !cluster_fw {
        return "no";
    }
    if !flag(&g.firewall, "enable", false) {
        return "no";
    }
    let any = g
        .nets()
        .iter()
        .any(|(_, raw)| prop(&propstring(raw, "model"), "firewall") == Some("1"));
    if any {
        "yes"
    } else {
        "no"
    }
}

fn verdict(
    target: &Guest,
    neighbours: &[Value],
    cluster_fw: bool,
    host_on_segment: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = target.subject();

    let unfiltered = neighbours
        .iter()
        .filter(|n| s(n, "filtered") == "no")
        .count();

    if !cluster_fw && !neighbours.is_empty() {
        out.push(
            Finding::new(
                "blast.unfiltered-segment",
                Severity::High,
                &subject,
                format!(
                    "{} reaches {} guest(s) with nothing in between",
                    target.label(),
                    neighbours.len()
                ),
            )
            .detail(
                "The datacenter firewall is off, so no rule at any level applies: every guest on \
                 these bridges is one ARP away.",
            ),
        );
    } else if unfiltered > 0 {
        out.push(
            Finding::new(
                "blast.unfiltered-neighbours",
                Severity::Medium,
                &subject,
                format!("{unfiltered} neighbour(s) filter nothing"),
            )
            .detail(
                "The firewall is on at the datacenter, but these guests either have their own \
                 switch off or no NIC marked as filtered.",
            ),
        );
    }

    if host_on_segment {
        out.push(
            Finding::new(
                "blast.host-on-segment",
                Severity::Medium,
                &subject,
                "the hypervisor answers on the same segment as this guest",
            )
            .detail(
                "A compromised guest can reach the API on 8006 and SSH on 22 directly. That is \
                 where a `management` IPSet and a host firewall rule earn their keep.",
            ),
        );
    }

    // What the guest can reach on the host regardless of the network.
    for (key, _) in target.config.as_object().into_iter().flatten() {
        if key.starts_with("hostpci") {
            out.push(
                Finding::new(
                    "blast.pci-path",
                    Severity::Medium,
                    &subject,
                    "this guest owns a PCI device, so its reach is not only the network",
                )
                .detail(
                    "A DMA-capable device escapes the network model entirely; containment then \
                     depends on the IOMMU group.",
                ),
            );
            break;
        }
    }

    if neighbours.is_empty() {
        out.push(
            Finding::new(
                "blast.isolated",
                Severity::Info,
                &subject,
                "no other guest shares a bridge and VLAN with this one",
            )
            .detail(
                "Within this cluster. Anything else on those segments physically is outside what \
                 the API can see.",
            ),
        );
    }
    out
}
