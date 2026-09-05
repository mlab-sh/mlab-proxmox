//! `shadow` — what turned up since the last snapshot.
//!
//! The same comparison as `diff`, with the present as the later side and the
//! newest snapshot on disk as the earlier one. This is the command you run on
//! a schedule: it answers "did anything appear that nobody announced".

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

use crate::cli::Ctx;
use crate::collect;
use crate::commands::{diff, snapshot};
use crate::pve::Client;
use crate::ui;

#[derive(Args, Debug)]
pub struct ShadowArgs {
    /// Compare against this snapshot instead of the newest one on disk
    #[arg(long, value_name = "FILE")]
    pub against: Option<PathBuf>,
    /// Write the freshly collected state as a new snapshot afterwards
    #[arg(long)]
    pub save: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &ShadowArgs) -> Result<()> {
    let path = match &a.against {
        Some(p) => p.clone(),
        None => match snapshot::latest(&ctx.name) {
            Some(p) => p,
            None => bail!(
                "no snapshot to compare against; run `mlab-proxmox snapshot` once to \
                 establish a baseline"
            ),
        },
    };
    ui::info(&format!("baseline: {}", path.display()));
    let before = snapshot::load(&path)?;

    let inv = collect::all(c).await?;
    let mut after = serde_json::to_value(&inv)?;
    snapshot::redact(&mut after);

    diff::compare(&before, &after, false)?;

    if a.save {
        let out = snapshot::default_path(&ctx.name, &inv.collected);
        if let Some(dir) = out.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&out, format!("{}\n", serde_json::to_string_pretty(&after)?))?;
        ui::success(&format!("wrote {}", out.display()));
    }
    Ok(())
}
