//! Embed git/version info at compile time so the UI + /status can show
//! exactly which build is running (e.g. "v0.1.0-1a2b3c4-dirty").

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    // No rerun-if-changed: default = rerun when any file in this package
    // changes, so the embedded git describe stays fresh on every rebuild.

    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let sha = git(&["rev-parse", "--short=7", "HEAD"]);
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    let describe = git(&["describe", "--tags", "--always", "--dirty"])
        .unwrap_or_else(|| sha.clone().unwrap_or_else(|| "unknown".into()));

    // Display form: v<semver>-<sha7>[-dirty]. Without git (e.g. docker
    // builds where .git is excluded) fall back to plain v<semver>.
    let display = match &sha {
        Some(s) => {
            let mut d = format!("v{}-{}", pkg_version, s);
            if dirty {
                d.push_str("-dirty");
            }
            d
        }
        None => format!("v{}", pkg_version),
    };

    println!("cargo:rustc-env=BGFLOW_VERSION_DISPLAY={}", display);
    println!("cargo:rustc-env=BGFLOW_GIT_DESCRIBE={}", describe);
    println!(
        "cargo:rustc-env=BGFLOW_GIT_SHA={}",
        sha.as_deref().unwrap_or("unknown")
    );
    println!(
        "cargo:rustc-env=BGFLOW_GIT_DIRTY={}",
        if dirty { "1" } else { "0" }
    );
}
