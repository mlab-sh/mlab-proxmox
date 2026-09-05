//! `diff` — what changed between two snapshots.
//!
//! Presence for inventory, field by field for configuration. The rule that
//! keeps this honest: a collection that was unreadable in either snapshot is
//! reported as such rather than compared, because "absent" and "refused" look
//! identical once they are both empty.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::{json, Value};

use crate::checks::{i, s};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// The earlier snapshot
    pub before: PathBuf,
    /// The later snapshot; omit to compare against the newest on disk
    pub after: PathBuf,
    /// Also list what did not change
    #[arg(long)]
    pub all: bool,
}

/// One collection of a snapshot, and how to identify a row of it.
struct Tracked {
    label: &'static str,
    pointer: &'static str,
    /// Builds the identity of one row.
    key: fn(&Value) -> String,
}

const TRACKED: [Tracked; 10] = [
    Tracked {
        label: "guest",
        pointer: "/guests",
        key: |v| {
            let kind = s(v, "kind");
            let prefix = if kind == "lxc" { "ct" } else { "vm" };
            format!("{prefix}/{}", i(v, "vmid").unwrap_or(0))
        },
    },
    Tracked {
        label: "user",
        pointer: "/access/users",
        key: |v| s(v, "userid"),
    },
    Tracked {
        label: "token",
        pointer: "/access/tokens",
        key: |v| format!("{}!{}", s(v, "userid"), s(v, "tokenid")),
    },
    Tracked {
        label: "grant",
        pointer: "/access/acl",
        key: |v| {
            format!(
                "{} {} {} on {}",
                s(v, "type"),
                s(v, "ugid"),
                s(v, "roleid"),
                s(v, "path")
            )
        },
    },
    Tracked {
        label: "role",
        pointer: "/access/roles",
        key: |v| s(v, "roleid"),
    },
    Tracked {
        label: "storage",
        pointer: "/storages",
        key: |v| s(v, "storage"),
    },
    Tracked {
        label: "backup job",
        pointer: "/backup_jobs",
        key: |v| s(v, "id"),
    },
    // A firewall rule has no stable identity of its own — `pos` shifts as soon
    // as anything is inserted above it — so the rule *is* its own key.
    Tracked {
        label: "firewall rule",
        pointer: "/firewall/rules",
        key: |v| {
            [
                s(v, "type"),
                s(v, "action"),
                s(v, "macro"),
                s(v, "proto"),
                s(v, "dport"),
                s(v, "source"),
                s(v, "dest"),
                s(v, "iface"),
            ]
            .iter()
            .filter(|x| !x.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
        },
    },
    Tracked {
        label: "ip set",
        pointer: "/firewall/ipsets",
        key: |v| s(v, "name"),
    },
    Tracked {
        label: "security group",
        pointer: "/firewall/groups",
        key: |v| s(v, "group"),
    },
];

/// Single values worth a line of their own when they move.
const WATCHED: [(&str, &str, &str); 5] = [
    ("version", "/version/version", "release"),
    (
        "firewall",
        "/firewall/options/enable",
        "datacenter firewall",
    ),
    ("firewall", "/firewall/options/policy_in", "inbound policy"),
    ("datacenter", "/options/migration", "migration"),
    ("datacenter", "/options/http_proxy", "http proxy"),
];

pub async fn run(a: &DiffArgs) -> Result<()> {
    let before = super::snapshot::load(&a.before)?;
    let after = super::snapshot::load(&a.after)?;
    compare(&before, &after, a.all)
}

/// The comparison itself, shared with `shadow`.
pub fn compare(before: &Value, after: &Value, show_unchanged: bool) -> Result<()> {
    let mut rows: Vec<Value> = Vec::new();

    for t in &TRACKED {
        let b = index(before, t);
        let af = index(after, t);
        let keys: BTreeSet<&String> = b.keys().chain(af.keys()).collect();

        for k in keys {
            match (b.get(k), af.get(k)) {
                (None, Some(_)) => rows.push(json!({
                    "name": k, "type": t.label, "status": "appeared", "detail": ""
                })),
                (Some(_), None) => rows.push(json!({
                    "name": k, "type": t.label, "status": "disappeared", "detail": ""
                })),
                (Some(x), Some(y)) => {
                    let changes = fields(x, y);
                    if !changes.is_empty() {
                        rows.push(json!({
                            "name": k, "type": t.label, "status": "changed",
                            "detail": changes.join("; ")
                        }));
                    } else if show_unchanged {
                        rows.push(json!({
                            "name": k, "type": t.label, "status": "unchanged", "detail": ""
                        }));
                    }
                }
                (None, None) => {}
            }
        }
    }

    // Single values worth a line of their own. The collection time always
    // differs and is already in the heading, so it is not one of them.
    for (label, pointer, key) in WATCHED {
        let x = before.pointer(pointer).map(scalar).unwrap_or_default();
        let y = after.pointer(pointer).map(scalar).unwrap_or_default();
        if x != y && !x.is_empty() {
            rows.push(json!({
                "name": key, "type": label, "status": "changed",
                "detail": format!("{x} → {y}")
            }));
        }
    }

    if render::is_json() {
        render::print_json(&json!({
            "before": before.get("collected"),
            "after": after.get("collected"),
            "changes": rows,
        }));
        return Ok(());
    }

    render::heading(&format!(
        "Changes between {} and {}",
        scalar(before.get("collected").unwrap_or(&Value::Null)),
        scalar(after.get("collected").unwrap_or(&Value::Null))
    ));

    let changed: Vec<&Value> = rows
        .iter()
        .filter(|r| s(r, "status") != "unchanged")
        .collect();
    if changed.is_empty() {
        println!();
        println!("  {}", "nothing changed".green());
    } else {
        render::list_auto(&rows);
        render::count(changed.len(), "change");
    }

    // Both files record what they could not read; comparing across a blind
    // spot is how a diff invents a disappearance.
    for (which, snap) in [("before", before), ("after", after)] {
        if let Some(u) = snap.get("unreadable").and_then(Value::as_array) {
            if !u.is_empty() {
                ui::warning(&format!(
                    "the {which} snapshot has {} unreadable route(s); anything they cover is not compared",
                    u.len()
                ));
            }
        }
    }
    Ok(())
}

/// Rows of one tracked collection, by identity.
fn index<'a>(snap: &'a Value, t: &Tracked) -> BTreeMap<String, &'a Value> {
    snap.pointer(t.pointer)
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|r| ((t.key)(r), r))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default()
}

/// Scalar fields that differ between two versions of the same row.
fn fields(a: &Value, b: &Value) -> Vec<String> {
    let (Some(x), Some(y)) = (a.as_object(), b.as_object()) else {
        return Vec::new();
    };
    let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
    let mut out = Vec::new();
    for k in keys {
        // Live counters say nothing about configuration and would drown the
        // signal in noise on every run.
        if matches!(
            k.as_str(),
            "uptime"
                | "cpu"
                | "mem"
                | "disk"
                | "netin"
                | "netout"
                | "diskread"
                | "diskwrite"
                | "status"
                | "avail"
                | "used"
                | "total"
                | "next-run"
        ) {
            continue;
        }
        let va = x.get(k).unwrap_or(&Value::Null);
        let vb = y.get(k).unwrap_or(&Value::Null);
        if va == vb {
            continue;
        }
        match (va, vb) {
            (Value::Object(_), Value::Object(_)) | (Value::Array(_), Value::Array(_)) => {
                let inner = if va.is_object() {
                    fields(va, vb)
                } else {
                    vec![format!("{} entries → {}", len(va), len(vb))]
                };
                if !inner.is_empty() {
                    out.push(format!("{k}: {}", inner.join(", ")));
                }
            }
            (Value::String(x), Value::String(y)) if x.contains(',') || y.contains(',') => {
                // The API returns several of these as an unordered set —
                // `content` on a storage reorders between two identical reads.
                if tokens(x) != tokens(y) {
                    out.push(format!("{k}: {x} → {y}"));
                }
            }
            _ => out.push(format!("{k}: {} → {}", scalar(va), scalar(vb))),
        }
    }
    out
}

/// A comma-separated field as a set, for fields the API does not order.
fn tokens(v: &str) -> BTreeSet<&str> {
    v.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect()
}

fn len(v: &Value) -> usize {
    v.as_array().map(|a| a.len()).unwrap_or(0)
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "(none)".to_string(),
        other => other.to_string(),
    }
}
