//! The command line surface, and the dispatch behind it.
//!
//! Adding a command means: a module under [`crate::commands`], a variant in
//! [`Cmd`], and one arm in [`run`].

mod context;

pub use context::{Ctx, Overrides};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

use crate::commands;
use crate::pve::{config, Client};
use crate::ui::{self, render};

#[derive(Parser, Debug)]
#[command(
    name = "mlab-proxmox",
    version,
    about = "Talk to a Proxmox VE cluster over its REST API",
    long_about = "Talk to a Proxmox VE cluster over its REST API.\n\n\
                  Connection settings live in profiles in $HOME/.mlab/proxmox.conf; run \
                  `mlab-proxmox login` once to create one. Flags override environment \
                  variables (MLAB_PROXMOX_*, then PROXMOX_*, then PVE_*), which override \
                  the profile.",
    after_help = "Create a read-only token on the cluster first:\n  \
                  pveum role add MlabAudit --privs 'Sys.Audit,Sys.Syslog,VM.Audit,VM.GuestAgent.Audit,Datastore.Audit,SDN.Audit,Pool.Audit,Mapping.Audit'\n  \
                  pveum user add mlab@pve\n  \
                  pveum acl modify / --user mlab@pve --role MlabAudit\n  \
                  pveum user token add mlab@pve audit --privsep 0\n\n\
                  The token secret is shown once. Then: mlab-proxmox login --name lab --host <node>"
)]
pub struct Cli {
    /// Profile to use (default: the one marked default in the config)
    #[arg(long, short = 'p', global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Any node of the cluster: hostname, IP, or host:port
    #[arg(long, global = true, value_name = "HOST")]
    pub host: Option<String>,

    /// API port, when the host does not carry one
    #[arg(long, global = true, value_name = "PORT")]
    pub port: Option<u16>,

    /// Token identifier, user@realm!tokenname
    #[arg(long, global = true, value_name = "ID")]
    pub token_id: Option<String>,

    /// Token secret; prefer PROXMOX_TOKEN_SECRET, a command line is visible to other users
    #[arg(long, global = true, value_name = "UUID")]
    pub token_secret: Option<String>,

    /// Output format: a terminal render, or raw JSON for scripting
    #[arg(long, short = 'o', global = true, value_parser = ["human", "json"], value_name = "FORMAT")]
    pub output: Option<String>,

    /// Silence progress and status lines on stderr
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Per-request timeout, in seconds
    #[arg(long, global = true, default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    /// Skip TLS certificate verification (the default: Proxmox signs its own)
    #[arg(long, global = true, conflicts_with = "secure")]
    pub insecure: bool,

    /// Verify the TLS certificate against the system trust store
    #[arg(long, global = true)]
    pub secure: bool,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create or update a profile, test it, and save it to the config file
    #[command(alias = "configure", alias = "setup")]
    Login(commands::login::LoginArgs),

    /// Manage saved clusters
    Profile {
        #[command(subcommand)]
        cmd: commands::profile::ProfileCmd,
    },

    /// Inspect the config file
    Config {
        #[command(subcommand)]
        cmd: commands::settings::ConfigCmd,
    },

    /// Check that the current profile can reach its cluster
    Ping,

    /// What this token is, and everything it is allowed to read
    Whoami(commands::whoami::WhoamiArgs),

    /// The hosts of the cluster
    Nodes {
        #[command(subcommand)]
        cmd: commands::nodes::NodeCmd,
    },

    /// The virtual machines and containers
    #[command(alias = "vm", alias = "vms")]
    Guests {
        #[command(subcommand)]
        cmd: commands::guests::GuestCmd,
    },

    /// Storage definitions and how full they are
    Storage {
        #[command(subcommand)]
        cmd: commands::storage::StorageCmd,
    },

    /// Users, tokens, roles and the access control list
    Access {
        #[command(subcommand)]
        cmd: commands::access::AccessCmd,
    },

    /// The firewall, at each of the four levels that can turn it off
    #[command(alias = "fw")]
    Firewall {
        #[command(subcommand)]
        cmd: commands::firewall::FirewallCmd,
    },

    /// Backup coverage, jobs and history
    Backup {
        #[command(subcommand)]
        cmd: commands::backup::BackupCmd,
    },

    /// Repositories, subscription and pending updates
    Patch,

    /// The cluster-wide settings that claim to defend something
    Posture,

    /// What this cluster looks like from outside, and what leaves it
    Footprint,

    /// Who did what on this cluster, and whether it worked
    Tasks(commands::tasks::TasksArgs),

    /// Who authenticated, who failed, and from where
    Logins(commands::logins::LoginsArgs),

    /// What one compromised guest reaches
    Blast(commands::blast::BlastArgs),

    /// One dated, secret-free record of everything the token can read
    Snapshot(commands::snapshot::SnapshotArgs),

    /// What changed between two snapshots
    Diff(commands::diff::DiffArgs),

    /// What turned up since the last snapshot
    Shadow(commands::shadow::ShadowArgs),

    /// Every graded check in one report
    Audit(commands::audit::AuditArgs),

    /// Raw request against the API, for anything not wrapped yet
    #[command(
        after_help = "PATH is relative to /api2/json and starts with a slash.\n\n\
                      Examples:\n  \
                      mlab-proxmox api GET /version\n  \
                      mlab-proxmox api GET /cluster/resources\n  \
                      mlab-proxmox api GET /nodes/pve1/qemu/100/config\n  \
                      mlab-proxmox api GET /nodes/pve1/tasks --query limit=20"
    )]
    Api(commands::api::ApiArgs),
}

/// Parse, set up output, then hand over to a command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    ui::init(cli.quiet);
    // Resolved again from the profile in `Ctx::build` when neither the flag nor
    // the environment picked a format.
    render::init(cli.output.as_deref().or(config::env("OUTPUT").as_deref()));

    // Commands that only touch the config file need no connection.
    match &cli.command {
        Cmd::Login(args) => return commands::login::run(&Overrides::from(&cli), args).await,
        Cmd::Profile { cmd } => return commands::profile::run(cmd),
        Cmd::Config { cmd } => return commands::settings::run(cmd),
        _ => {}
    }

    if let Some(w) = config::perms_warning() {
        ui::warning(&w);
    }

    let ctx = Ctx::build(&cli)?;
    let c = Client::new(&ctx.profile, ctx.timeout)
        .with_context(|| format!("profile {:?}", ctx.name))?;

    match cli.command {
        Cmd::Login(_) | Cmd::Profile { .. } | Cmd::Config { .. } => unreachable!(),
        Cmd::Ping => commands::ping::run(&c, &ctx).await,
        Cmd::Whoami(a) => commands::whoami::run(&c, &ctx, &a).await,
        Cmd::Nodes { cmd } => commands::nodes::run(&c, cmd).await,
        Cmd::Guests { cmd } => commands::guests::run(&c, cmd).await,
        Cmd::Storage { cmd } => commands::storage::run(&c, cmd).await,
        Cmd::Access { cmd } => commands::access::run(&c, cmd).await,
        Cmd::Firewall { cmd } => commands::firewall::run(&c, cmd).await,
        Cmd::Backup { cmd } => commands::backup::run(&c, cmd).await,
        Cmd::Patch => commands::patch::run(&c).await,
        Cmd::Posture => commands::posture::run(&c).await,
        Cmd::Footprint => commands::footprint::run(&c).await,
        Cmd::Tasks(a) => commands::tasks::run(&c, &a).await,
        Cmd::Logins(a) => commands::logins::run(&c, &a).await,
        Cmd::Blast(a) => commands::blast::run(&c, &a).await,
        Cmd::Snapshot(a) => commands::snapshot::run(&c, &ctx, &a).await,
        Cmd::Diff(a) => commands::diff::run(&a).await,
        Cmd::Shadow(a) => commands::shadow::run(&c, &ctx, &a).await,
        Cmd::Audit(a) => commands::audit::run(&c, &ctx, &a).await,
        Cmd::Api(a) => commands::api::run(&c, a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// clap only validates the surface when a subcommand is actually reached,
    /// so a duplicate short option ships happily and panics in front of a user.
    /// This walks the whole tree at test time instead.
    #[test]
    fn the_command_line_surface_is_consistent() {
        Cli::command().debug_assert();
    }
}
