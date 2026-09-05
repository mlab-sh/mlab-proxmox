//! `mlab-proxmox` — a CLI over the Proxmox VE REST API.
//!
//! Layout:
//!
//! | module     | role                                                        |
//! | ---------- | ----------------------------------------------------------- |
//! | `pve`      | the API: HTTP handler, profiles                              |
//! | `collect`  | one pass over everything the token can read                   |
//! | `checks`   | the graded checks, as pure functions over collected data      |
//! | `ui`       | everything the user sees: progress on stderr, rendering       |
//! | `cli`      | the clap surface and the dispatch                             |
//! | `commands` | one module per command                                        |

mod checks;
mod cli;
mod collect;
mod commands;
mod pve;
mod ui;

use colored::Colorize;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        // A spinner may own a half-drawn line; wipe it before the message.
        ui::restore();
        eprintln!("  {} {e:#}", "✖".red().bold());
        std::process::exit(1);
    }
}
