//! Records the client revision this binary was built against.
//!
//! `cmns version` names the `commons-node-client` revision it carries, and a
//! hand-updated constant drifts from the pin. The lockfile already holds the
//! exact revision Cargo resolved, so the build reads it from there: the
//! version a user reports is the one the binary was built with.
//!
//! When the lockfile names no client the build still succeeds — a checkout
//! without a lockfile is a legitimate thing to build — but it says so, and the
//! `version_report` test refuses the result, so the fallback cannot pass as
//! data in this repository's own gates.

use std::{fs, path::PathBuf};

fn main() {
    let lock = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock.display());
    let rev = fs::read_to_string(&lock)
        .map_err(|err| format!("{}: {err}", lock.display()))
        .and_then(|text| {
            client_rev(&text)
                .ok_or_else(|| format!("{}: no commons-node-client entry", lock.display()))
        })
        .unwrap_or_else(|why| {
            println!("cargo:warning=CMNS_CLIENT_REV is 'unknown': {why}");
            "unknown".into()
        });
    println!("cargo:rustc-env=CMNS_CLIENT_REV={rev}");
    // `cmns update` picks the release asset built for this binary's target.
    let target = std::env::var("TARGET").expect("cargo sets TARGET for a build script");
    println!("cargo:rustc-env=CMNS_TARGET={target}");
}

/// The short revision of `commons-node-client` in a lockfile, from its
/// `source = "git+…?rev=…#<sha>"` line. `None` when the lockfile names no
/// such package (or this build has no lockfile at all).
fn client_rev(lock: &str) -> Option<String> {
    let mut in_client = false;
    for line in lock.lines().map(str::trim) {
        if line == "[[package]]" {
            in_client = false;
        } else if line == r#"name = "commons-node-client""# {
            in_client = true;
        } else if in_client {
            if let Some(source) = line
                .strip_prefix("source = \"git+")
                .and_then(|rest| rest.strip_suffix('"'))
            {
                let (_, sha) = source.rsplit_once('#')?;
                return Some(sha.chars().take(7).collect());
            }
        }
    }
    None
}
