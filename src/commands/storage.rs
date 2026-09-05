//! `storage` — what the cluster stores things on.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::checks::{backup as bchecks, flag, i, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::{esc, Client};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum StorageCmd {
    /// List the storages with what they hold and how full they are
    #[command(alias = "ls")]
    List,
    /// The graded checks that apply to storage
    Check,
}

pub async fn run(c: &Client, cmd: StorageCmd) -> Result<()> {
    match cmd {
        StorageCmd::List => list(c).await,
        StorageCmd::Check => check(c).await,
    }
}

async fn list(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let storages = ui::spin("Reading the storages", f.list("/storage")).await;

    // Usage lives per node, not on the definition; ask the first node that
    // serves each storage.
    let nodes = collect::node_names(&mut f).await;
    let mut usage: Vec<Value> = Vec::new();
    for n in &nodes {
        for row in f.list(&format!("/nodes/{}/storage", esc(n))).await {
            usage.push(row);
        }
    }

    let out: Vec<Value> = storages
        .iter()
        .map(|st| {
            let id = s(st, "storage");
            let live = usage.iter().find(|u| s(u, "storage") == id);
            json!({
                "name": id,
                "type": s(st, "type"),
                "status": if flag(st, "disable", false) { "disabled" } else { "available" },
                "shared": i(st, "shared").unwrap_or(0),
                "content": s(st, "content"),
                "total": live.and_then(|l| i(l, "total")),
                "avail": live.and_then(|l| i(l, "avail")),
                "nodes": s(st, "nodes"),
            })
        })
        .collect();

    render::heading("Storage");
    render::list_auto(&out);
    render::count(out.len(), "storage");
    Ok(())
}

async fn check(c: &Client) -> Result<()> {
    let mut f = Fetcher::new(c);
    let storages = f.list("/storage").await;
    let jobs = f.list("/cluster/backup").await;
    let mut r = Report::default();
    r.extend(bchecks::all(
        &jobs,
        &[],
        &storages,
        &[],
        &[],
        collect::now(),
    ));
    report::emit("Storage checks", &r, &f.unreadable, None)
}
