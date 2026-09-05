//! `backup` — what is protected, by what, and when it last worked.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::checks::{backup as bchecks, i, s, Report};
use crate::collect::{self, Fetcher};
use crate::commands::report;
use crate::pve::Client;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum BackupCmd {
    /// Which guests a job covers, and which none does
    Coverage,
    /// The backup jobs and their schedules
    Jobs,
    /// The backup and verification tasks that already ran
    History,
    /// The graded checks that apply to backup
    Check,
}

pub async fn run(c: &Client, cmd: BackupCmd) -> Result<()> {
    let mut f = Fetcher::new(c);

    match cmd {
        BackupCmd::Coverage => {
            let jobs = ui::spin("Reading the backup jobs", f.list("/cluster/backup")).await;
            let uncovered = f.list("/cluster/backup-info/not-backed-up").await;
            let resources = f.list("/cluster/resources").await;
            let guests: Vec<&Value> = resources
                .iter()
                .filter(|r| matches!(s(r, "type").as_str(), "qemu" | "lxc"))
                .collect();

            let uncovered_ids: Vec<i64> = uncovered.iter().filter_map(|g| i(g, "vmid")).collect();
            let rows: Vec<Value> = guests
                .iter()
                .map(|g| {
                    let vmid = i(g, "vmid").unwrap_or(0);
                    json!({
                        "name": s(g, "name"),
                        "vmid": vmid,
                        "type": s(g, "type"),
                        "status": if uncovered_ids.contains(&vmid) { "uncovered" } else { "covered" },
                        "node": s(g, "node"),
                    })
                })
                .collect();

            render::heading("Backup coverage");
            render::list_auto(&rows);
            render::count(rows.len(), "guest");
            if uncovered_ids.is_empty() {
                ui::success(&format!("every guest is in one of {} job(s)", jobs.len()));
            } else {
                ui::warning(&format!(
                    "{} guest(s) are in no backup job",
                    uncovered_ids.len()
                ));
            }
        }
        BackupCmd::Jobs => {
            let jobs = ui::spin("Reading the backup jobs", f.list("/cluster/backup")).await;
            let rows: Vec<Value> = jobs
                .iter()
                .map(|j| {
                    json!({
                        "name": if s(j, "comment").is_empty() { s(j, "id") } else { s(j, "comment") },
                        "id": s(j, "id"),
                        "enable": i(j, "enabled").unwrap_or(1),
                        "storage": s(j, "storage"),
                        "schedule": s(j, "schedule"),
                        "next-run": i(j, "next-run"),
                        "mode": s(j, "mode"),
                        "selection": if i(j, "all") == Some(1) { "all guests".to_string() } else { s(j, "vmid") },
                    })
                })
                .collect();
            render::heading("Backup jobs");
            render::list_auto(&rows);
            render::count(rows.len(), "job");

            let retention: Vec<(String, String)> = jobs
                .iter()
                .filter(|j| !s(j, "prune-backups").is_empty())
                .map(|j| (s(j, "id"), s(j, "prune-backups")))
                .collect();
            if !retention.is_empty() {
                render::heading("Retention");
                let refs: Vec<(&str, String)> = retention
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect();
                render::pairs(&refs);
            }
        }
        BackupCmd::History => {
            let tasks = ui::spin("Reading the task log", f.list("/cluster/tasks")).await;
            let rows: Vec<Value> = tasks
                .iter()
                .filter(|t| {
                    matches!(
                        s(t, "type").as_str(),
                        "vzdump" | "qmbackup" | "verificationjob"
                    )
                })
                .map(|t| {
                    json!({
                        "name": s(t, "id"),
                        "type": s(t, "type"),
                        "node": s(t, "node"),
                        "status": s(t, "status"),
                        "starttime": i(t, "starttime"),
                        "endtime": i(t, "endtime"),
                        "user": s(t, "user"),
                    })
                })
                .collect();
            render::heading("Backup history");
            render::list_auto(&rows);
            render::count(rows.len(), "task");
            if rows.is_empty() {
                ui::warning("no backup task appears in the visible task log");
            }
        }
        BackupCmd::Check => {
            let jobs = f.list("/cluster/backup").await;
            let uncovered = f.list("/cluster/backup-info/not-backed-up").await;
            let storages = f.list("/storage").await;
            let tasks = f.list("/cluster/tasks").await;
            let names = collect::node_names(&mut f).await;
            let mut guests = Vec::new();
            for n in &names {
                guests.extend(collect::guests_of(&mut f, n).await);
            }
            let mut r = Report::default();
            r.extend(bchecks::all(
                &jobs,
                &uncovered,
                &storages,
                &guests,
                &tasks,
                collect::now(),
            ));
            return report::emit("Backup checks", &r, &f.unreadable, None);
        }
    }
    Ok(())
}
