//! The Proxmox side of the CLI: what to talk to, and how.

pub mod client;
pub mod config;

pub use client::{esc, Client};
pub use config::Profile;

/// Format a Unix timestamp in seconds as UTC ISO 8601. The API reports epoch
/// integers everywhere (task times, token expiry, certificate dates) and an
/// inventory that mixes formats is unsortable.
pub fn iso8601(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let rem = epoch.rem_euclid(86_400);
    let (h, m, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Howard Hinnant's civil_from_days: shift the era so March starts the year,
    // which makes the leap day the last day and removes every special case.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mth <= 2);

    format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{sec:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_seconds_become_utc_iso8601() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(1_759_148_439), "2025-09-29T12:20:39Z");
    }

    #[test]
    fn the_march_shift_handles_leap_days() {
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
