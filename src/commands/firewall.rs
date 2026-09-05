//! `firewall` — the four levels, and whether they agree with each other.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::checks::{firewall as fwchecks, flag, i, prop, propstring, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum FirewallCmd {
    /// Whether the firewall is on, at each of the levels that can turn it off
    Status,
    /// The rules, at whichever level carries them
    Rules,
    /// IP sets, aliases and security groups
    Objects,
    /// What the host firewall is actually dropping
    Log(LogArgs),
    /// The graded checks that apply to filtering and segmentation
    Check,
}

#[derive(clap::Args, Debug)]
pub struct LogArgs {
    /// Read this node instead of every one of them
    #[arg(long, value_name = "NODE")]
    pub node: Option<String>,
    /// How many lines to read per node
    #[arg(long, default_value_t = 100, value_name = "N")]
    pub limit: u32,
}

pub async fn run(c: &Client, cmd: FirewallCmd) -> Result<()> {
    let mut f = Fetcher::new(c);

    match cmd {
        FirewallCmd::Status => status(&mut f).await,
        FirewallCmd::Rules => rules(&mut f).await,
        FirewallCmd::Objects => objects(&mut f).await,
        FirewallCmd::Log(a) => log(&mut f, &a).await,
        FirewallCmd::Check => check(&mut f).await,
    }
}

async fn status(f: &mut Fetcher<'_>) -> Result<()> {
    let fw = ui::spin("Reading the firewall", collect::firewall(f)).await;
    let cluster_on = flag(&fw.options, "enable", false);

    render::heading("Datacenter");
    render::pairs(&[
        ("firewall", on_off(cluster_on)),
        (
            "policy in",
            or(&s(&fw.options, "policy_in"), "DROP (default)"),
        ),
        (
            "policy out",
            or(&s(&fw.options, "policy_out"), "ACCEPT (default)"),
        ),
        (
            "policy forward",
            or(&s(&fw.options, "policy_forward"), "DROP (default)"),
        ),
        ("ebtables", on_off(flag(&fw.options, "ebtables", true))),
        ("rules", fw.rules.len().to_string()),
    ]);

    let names = collect::node_names(f).await;
    let mut node_rows = Vec::new();
    for n in &names {
        let node = collect::node_without_updates(f, n).await;
        node_rows.push(json!({
            "name": n,
            "enable": if flag(&node.firewall, "enable", true) { "on" } else { "off" },
            "engine": if flag(&node.firewall, "nftables", false) { "nftables" } else { "iptables" },
            "rules": node.firewall_rules.len(),
            "log_level_in": or(&s(&node.firewall, "log_level_in"), "nolog"),
            "synflood": if flag(&node.firewall, "protection_synflood", false) { "on" } else { "off" },
            "tcpflags": if flag(&node.firewall, "tcpflags", false) { "on" } else { "off" },
        }));
    }
    render::heading("Hosts");
    render::list_auto(&node_rows);

    let mut guest_rows = Vec::new();
    for n in &names {
        for g in collect::guests_of(f, n).await {
            let filtered = g
                .nets()
                .iter()
                .filter(|(_, raw)| prop(&propstring(raw, "model"), "firewall") == Some("1"))
                .count();
            guest_rows.push(json!({
                "name": g.label(),
                "enable": if flag(&g.firewall, "enable", false) { "on" } else { "off" },
                "nics": g.nets().len(),
                "filtered": filtered,
                "rules": g.firewall_rules.len(),
                "macfilter": if flag(&g.firewall, "macfilter", true) { "on" } else { "off" },
                "policy_in": or(&s(&g.firewall, "policy_in"), "DROP (default)"),
            }));
        }
    }
    render::heading("Guests");
    render::list_auto(&guest_rows);

    if !cluster_on {
        ui::warning("the datacenter switch is off, so none of the above filters anything");
    }
    Ok(())
}

async fn rules(f: &mut Fetcher<'_>) -> Result<()> {
    let fw = collect::firewall(f).await;
    render::heading("Datacenter rules");
    render::list_auto(&fw.rules.iter().map(rule_row).collect::<Vec<_>>());

    for n in collect::node_names(f).await {
        let node = collect::node_without_updates(f, &n).await;
        if node.firewall_rules.is_empty() {
            continue;
        }
        render::heading(&format!("Rules on {n}"));
        render::list_auto(&node.firewall_rules.iter().map(rule_row).collect::<Vec<_>>());

        for g in collect::guests_of(f, &n).await {
            if g.firewall_rules.is_empty() {
                continue;
            }
            render::heading(&format!("Rules on {}", g.label()));
            render::list_auto(&g.firewall_rules.iter().map(rule_row).collect::<Vec<_>>());
        }
    }
    Ok(())
}

async fn objects(f: &mut Fetcher<'_>) -> Result<()> {
    let fw = collect::firewall(f).await;

    render::heading("IP sets");
    let mut sets = Vec::new();
    for set in &fw.ipsets {
        let name = s(set, "name");
        let members = f
            .list(&format!(
                "/cluster/firewall/ipset/{}",
                crate::pve::esc(&name)
            ))
            .await;
        sets.push(json!({
            "name": name,
            "comment": s(set, "comment"),
            "entries": members.iter().map(|m| s(m, "cidr")).collect::<Vec<_>>().join(" "),
        }));
    }
    render::list_auto(&sets);

    render::heading("Aliases");
    render::list_auto(
        &fw.aliases
            .iter()
            .map(|a| json!({ "name": s(a, "name"), "cidr": s(a, "cidr"), "comment": s(a, "comment") }))
            .collect::<Vec<_>>(),
    );

    render::heading("Security groups");
    render::list_auto(
        &fw.groups
            .iter()
            .map(|g| json!({ "name": s(g, "group"), "comment": s(g, "comment") }))
            .collect::<Vec<_>>(),
    );
    Ok(())
}

/// The firewall log. Readable with `Sys.Syslog`, which is in the role this CLI
/// recommends — only the per-guest log needs `VM.Console`, and that is a price
/// not worth paying for a log tail.
async fn log(f: &mut Fetcher<'_>, a: &LogArgs) -> Result<()> {
    let nodes = match &a.node {
        Some(n) => vec![n.clone()],
        None => collect::node_names(f).await,
    };

    let mut total = 0;
    for n in &nodes {
        let path = format!("/nodes/{}/firewall/log", crate::pve::esc(n));
        let query = [
            ("limit".to_string(), a.limit.to_string()),
            ("start".to_string(), "0".to_string()),
        ];
        let rows = match f
            .client()
            .request(reqwest::Method::GET, &path, &query, None)
            .await
        {
            Ok(Value::Array(rows)) => rows,
            Ok(_) => Vec::new(),
            Err(e) => {
                ui::warning(&format!("{n}: {e}"));
                continue;
            }
        };

        render::heading(&format!("Firewall log on {n}"));
        if rows.is_empty() {
            println!();
            println!("  no entry");
            continue;
        }
        total += rows.len();
        if render::is_json() {
            render::print_json(&Value::Array(rows));
            continue;
        }
        println!();
        for row in &rows {
            println!("  {}", s(row, "t"));
        }
    }

    if !render::is_json() && total > 0 {
        render::count(total, "line");
        ui::info("an empty log with the firewall on usually means every log level is `nolog`");
    }
    Ok(())
}

async fn check(f: &mut Fetcher<'_>) -> Result<()> {
    let fw = ui::spin("Reading the firewall", collect::firewall(f)).await;
    let names = collect::node_names(f).await;

    let mut nodes = Vec::new();
    let mut guests = Vec::new();
    for n in &names {
        nodes.push(collect::node_without_updates(f, n).await);
        guests.extend(collect::guests_of(f, n).await);
    }

    let cluster_on = flag(&fw.options, "enable", false);
    let mut r = Report::default();
    r.extend(fwchecks::cluster(&fw, guests.len()));
    for n in &nodes {
        r.extend(fwchecks::node(n, cluster_on));
    }
    for g in &guests {
        r.extend(fwchecks::guest(g, cluster_on));
    }
    report::emit("Firewall checks", &r, &f.unreadable, None)
}

fn rule_row(r: &Value) -> Value {
    json!({
        "name": format!("#{}", i(r, "pos").unwrap_or(0)),
        "type": s(r, "type"),
        "enable": i(r, "enable").unwrap_or(1),
        "action": s(r, "action"),
        "proto": s(r, "proto"),
        "dport": s(r, "dport"),
        "source": or(&s(r, "source"), "any"),
        "dest": s(r, "dest"),
        "iface": s(r, "iface"),
        "log": or(&s(r, "log"), "nolog"),
    })
}

fn on_off(b: bool) -> String {
    if b { "on" } else { "off" }.to_string()
}

fn or(v: &str, fallback: &str) -> String {
    if v.is_empty() {
        fallback.to_string()
    } else {
        v.to_string()
    }
}
