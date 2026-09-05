//! One module per command.
//!
//! Each exposes a `run` taking whatever it needs — a [`Client`](crate::pve::Client)
//! and the resolved [`Ctx`](crate::cli::Ctx) for the API commands, nothing but
//! its own arguments for the ones that only touch the config file.

pub mod access;
pub mod api;
pub mod audit;
pub mod backup;
pub mod blast;
pub mod diff;
pub mod firewall;
pub mod footprint;
pub mod guests;
pub mod login;
pub mod logins;
pub mod nodes;
pub mod patch;
pub mod ping;
pub mod posture;
pub mod profile;
pub mod prompt;
pub mod report;
pub mod settings;
pub mod shadow;
pub mod snapshot;
pub mod storage;
pub mod tasks;
pub mod whoami;
