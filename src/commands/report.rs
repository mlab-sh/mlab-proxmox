//! Rendering a run of checks, shared by every command that grades something.

use anyhow::Result;
use colored::Colorize;
use serde_json::{json, Value};

use crate::checks::{Report, Severity};
use crate::collect::Unreadable;
use crate::ui::render;

/// All six levels, worst first, which is also the order they are printed in.
const LEVELS: [Severity; 6] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
    Severity::Unreadable,
];

/// Print a report, and whatever the collection could not read.
///
/// `min` drops everything below a level, which is what the `--min` flag on the
/// graded commands sets. `Unreadable` is never dropped: hiding it would turn a
/// blind spot into a clean bill of health.
pub fn emit(
    title: &str,
    r: &Report,
    unreadable: &[Unreadable],
    min: Option<Severity>,
) -> Result<()> {
    let shown: Vec<&crate::checks::Finding> = r
        .sorted()
        .into_iter()
        .filter(|f| match min {
            Some(m) => f.severity <= m || f.severity == Severity::Unreadable,
            None => true,
        })
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "title": title,
            "summary": summary_json(r),
            "findings": shown,
            "unreadable": unreadable,
        }));
        return Ok(());
    }

    render::heading(title);
    if shown.is_empty() {
        println!();
        println!("  {}", "nothing to report".green());
    }

    let mut last = None;
    for f in &shown {
        if last != Some(f.severity) {
            println!();
            println!("  {}", f.severity.paint());
            last = Some(f.severity);
        }
        println!("    {}  {}", pad(&f.subject, 12).dimmed(), f.title);
        if !f.detail.is_empty() {
            for line in wrap(&f.detail, 84) {
                println!("      {}", line.dimmed());
            }
        }
        if let Some(rem) = &f.remedy {
            for line in wrap(&format!("→ {rem}"), 84) {
                println!("      {}", line.cyan());
            }
        }
    }

    summary(r, unreadable);
    Ok(())
}

/// The counts, and the sentence that puts them in order.
fn summary(r: &Report, unreadable: &[Unreadable]) {
    println!();
    let mut parts = Vec::new();
    for level in LEVELS {
        let n = r.count(level);
        if n > 0 {
            parts.push(format!("{n} {}", level.paint()));
        }
    }
    if parts.is_empty() {
        parts.push("0 findings".to_string());
    }
    println!("  {}", parts.join("   "));

    if !unreadable.is_empty() {
        println!();
        println!(
            "  {}",
            format!(
                "{} route(s) could not be read; the checks behind them report nothing, which is \
                 not the same as passing:",
                unreadable.len()
            )
            .dimmed()
        );
        for u in unreadable.iter().take(8) {
            println!("    {}  {}", u.path.dimmed(), clip(&u.reason, 70).dimmed());
        }
        if unreadable.len() > 8 {
            println!(
                "    {}",
                format!("… and {} more", unreadable.len() - 8).dimmed()
            );
        }
    }
    println!();
}

fn summary_json(r: &Report) -> Value {
    let mut o = serde_json::Map::new();
    for level in LEVELS {
        o.insert(level.as_str().to_string(), json!(r.count(level)));
    }
    o.insert(
        "worst".to_string(),
        match r.worst() {
            Some(s) => json!(s.as_str()),
            None => Value::Null,
        },
    );
    Value::Object(o)
}

fn pad(s: &str, w: usize) -> String {
    let n = s.chars().count();
    if n >= w {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(w - n))
    }
}

fn clip(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        return s.to_string();
    }
    let mut out: String = s.chars().take(w.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Wrap on spaces, so a detail sentence stays readable in a terminal.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_never_splits_a_word() {
        let out = wrap("one two three four five", 9);
        assert_eq!(out, vec!["one two", "three", "four five"]);
    }

    #[test]
    fn clipping_marks_what_it_removed() {
        assert_eq!(clip("abcdef", 4), "abc…");
        assert_eq!(clip("abc", 4), "abc");
    }
}
