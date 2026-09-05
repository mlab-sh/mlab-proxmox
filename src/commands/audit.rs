//! `audit` — every graded check in one report.

use anyhow::Result;
use clap::Args;

use crate::checks::{self, Severity};
use crate::cli::Ctx;
use crate::collect;
use crate::commands::report;
use crate::pve::Client;

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Hide findings below this severity (unreadable is always shown)
    #[arg(long, value_name = "LEVEL", value_parser = ["critical", "high", "medium", "low", "info"])]
    pub min: Option<String>,

    /// Exit 2 when a finding at this severity or worse is present
    #[arg(long, value_name = "LEVEL", value_parser = ["critical", "high", "medium", "low", "info"])]
    pub fail_on: Option<String>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &AuditArgs) -> Result<()> {
    let inv = collect::all(c).await?;
    let now = collect::now();
    let r = checks::run_all(&inv, now);

    let min = a.min.as_deref().and_then(Severity::from_name);
    report::emit(
        &format!("Audit of {} ({})", ctx.name, inv.endpoint),
        &r,
        &inv.unreadable,
        min,
    )?;

    // An exit code is what makes this usable from cron; the default stays 0 so
    // a report is never mistaken for a failed command.
    if let Some(level) = a.fail_on.as_deref().and_then(Severity::from_name) {
        if r.findings
            .iter()
            .any(|f| f.severity <= level && f.severity != Severity::Unreadable)
        {
            std::process::exit(2);
        }
    }
    Ok(())
}
