//! `cmns sidecar status` and the sidecar's `dev check` behind `cmns cap check`.
//!
//! The sidecar is `cmn-http`, the node's HTTP door. Its status is read over
//! its private same-UID admin socket, `<sidecar dir>/admin/admin.sock`,
//! through `commons_node_client::sidecar::sidecar_admin_call` and nothing
//! else; this module adds no op and reads no key. Its directory follows
//! `cmn http`'s convention: `--data-dir` names it, and without that it is
//! `<node data dir>/http`, with `--node-data-dir` defaulting to the node's
//! own `./data`. `cmn-http` itself has no default directory.
//!
//! `cap check` runs the `cmn-http` binary, found as `cmn` finds it:
//! `CMN_HTTP_BIN` if set, else `cmn-http` beside this program.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Subcommand;
use serde_json::{json, Value};

use crate::{cap::DEFAULT_DATA_DIR, encode_json, escape, print_json};

#[derive(Debug, Subcommand)]
pub enum SidecarCommand {
    /// The sidecar's own answer to its `status` op: its pid, bind address,
    /// delegate, node, API keys and exposed datasets.
    Status,
}

/// The sidecar's directory, as `cmn http` resolves it: `--data-dir` when
/// given, else `<node data dir>/http`.
pub fn http_dir(data_dir: Option<&Path>, node_data_dir: Option<&Path>) -> PathBuf {
    match data_dir {
        Some(dir) => dir.to_path_buf(),
        None => node_data_dir
            .unwrap_or(Path::new(DEFAULT_DATA_DIR))
            .join("http"),
    }
}

/// Runs one `sidecar` command against the sidecar under the given directories.
pub fn run(
    data_dir: Option<&Path>,
    node_data_dir: Option<&Path>,
    command: SidecarCommand,
    human: bool,
) -> Result<()> {
    match command {
        SidecarCommand::Status => {
            let http = std::path::absolute(http_dir(data_dir, node_data_dir))
                .context("resolving the sidecar's directory")?;
            let runtime = tokio::runtime::Runtime::new().context("starting tokio")?;
            let answer = runtime
                .block_on(commons_node_client::sidecar::sidecar_admin_call(
                    &http,
                    "status",
                    json!({}),
                ))
                .map_err(|err| sidecar_error(&err, &http, data_dir, node_data_dir))?;
            print_json(&answer, human)
        }
    }
}

/// The call's own refusal, with what only the CLI knows added: which socket it
/// asked, and, when nothing is listening there, the `cmn` command that starts
/// the sidecar with the same directories. The call's message is kept whole;
/// `main` escapes the line it prints.
fn sidecar_error(
    err: &anyhow::Error,
    http: &Path,
    data_dir: Option<&Path>,
    node_data_dir: Option<&Path>,
) -> anyhow::Error {
    let socket = http.join("admin").join("admin.sock");
    if !not_running(err) {
        return anyhow!("sidecar status on {}: {err:#}", socket.display());
    }
    let mut start = String::from("cmn http start");
    if let Some(dir) = node_data_dir {
        start.push_str(&format!(" --node-data-dir {}", dir.display()));
    }
    if let Some(dir) = data_dir {
        start.push_str(&format!(" --data-dir {}", dir.display()));
    }
    anyhow!(
        "sidecar status on {}: {err:#}. Start the sidecar with `{start}` \
         (packaged: `cmn http start --unit`), or name its directory with \
         --data-dir <dir> or the node's with --node-data-dir <dir> (default {DEFAULT_DATA_DIR}).",
        socket.display()
    )
}

/// Whether the call failed because no sidecar listens on the socket: the
/// socket or its directory is absent, or a socket left behind refuses the
/// connection.
fn not_running(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
        })
    })
}

/// `cmn-http`: where `CMN_HTTP_BIN` names it, else beside `exe`. `cmn`'s
/// search (`commons-node` `crates/cli/src/http.rs`, `sidecar_binary`).
pub fn find_binary(env: Option<OsString>, exe: &Path) -> Result<PathBuf> {
    if let Some(path) = env {
        return Ok(PathBuf::from(path));
    }
    let beside = exe
        .parent()
        .context("cmns has no directory")?
        .join("cmn-http");
    ensure!(
        beside.is_file(),
        "cmn-http was not found beside cmns ({}); install it there or set CMN_HTTP_BIN",
        beside.display()
    );
    Ok(beside)
}

/// What `cmn-http dev check` printed, made safe for a terminal, and its exit
/// code.
#[derive(Debug)]
pub struct Checked {
    pub stdout: String,
    pub stderr: String,
    pub code: u8,
}

/// `cmn-http dev check <folder>`, with `--json` unless `human`. The folder is
/// one argument after `--`, so a name starting with `-` is still a folder,
/// and no shell is involved. The JSON report is re-encoded with
/// [`encode_json`], so it decodes to exactly the sidecar's value; the human
/// report and the sidecar's error output are escaped line by line.
pub fn dev_check(bin: &Path, folder: &Path, human: bool) -> Result<Checked> {
    let mut command = Command::new(bin);
    command.args(["dev", "check"]);
    if !human {
        command.arg("--json");
    }
    command.arg("--").arg(folder);
    let output = command
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running cmn-http at {}", bin.display()))?;
    let Some(code) = output.status.code() else {
        bail!(
            "cmn-http at {} ended without an exit code ({}): {}",
            bin.display(),
            output.status,
            escape_lines(&String::from_utf8_lossy(&output.stderr))
        );
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = if human || stdout.trim().is_empty() {
        escape_lines(&stdout)
    } else {
        let report: Value = serde_json::from_str(&stdout).with_context(|| {
            format!(
                "cmn-http's report is not JSON (exit {code}): {}",
                escape(stdout.trim())
            )
        })?;
        let mut encoded = encode_json(&report)?;
        encoded.push('\n');
        encoded
    };
    Ok(Checked {
        stdout,
        stderr: escape_lines(&String::from_utf8_lossy(&output.stderr)),
        code: u8::try_from(code).unwrap_or(1),
    })
}

/// [`escape`] applied to each line, keeping the line breaks themselves.
fn escape_lines(text: &str) -> String {
    text.split('\n').map(escape).collect::<Vec<_>>().join("\n")
}

/// `cmns cap check <folder>`: prints the sidecar's report and answers its exit
/// code.
pub fn check(folder: &Path, human: bool) -> Result<u8> {
    let exe = std::env::current_exe().context("locating cmns")?;
    let bin = find_binary(std::env::var_os("CMN_HTTP_BIN"), &exe)?;
    let checked = dev_check(&bin, folder, human)?;
    print!("{}", checked.stdout);
    eprint!("{}", checked.stderr);
    Ok(checked.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sidecar_directory_follows_cmn_http() {
        assert_eq!(http_dir(None, None), PathBuf::from("./data/http"));
        assert_eq!(
            http_dir(None, Some(Path::new("/n"))),
            PathBuf::from("/n/http")
        );
        assert_eq!(
            http_dir(Some(Path::new("/h")), Some(Path::new("/n"))),
            PathBuf::from("/h")
        );
    }

    #[test]
    fn cmn_http_bin_wins_and_beside_is_checked() {
        let dir = std::env::temp_dir().join(format!("cmns-find-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("cmns");
        let named = find_binary(Some("/opt/x/cmn-http".into()), &exe).unwrap();
        assert_eq!(named, PathBuf::from("/opt/x/cmn-http"));

        let err = find_binary(None, &exe).unwrap_err().to_string();
        let beside = dir.join("cmn-http");
        assert!(
            err.contains(&beside.display().to_string()) && err.contains("CMN_HTTP_BIN"),
            "{err}"
        );

        std::fs::write(&beside, "").unwrap();
        assert_eq!(find_binary(None, &exe).unwrap(), beside);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn only_an_absent_or_refusing_socket_gets_the_start_hint() {
        let http = Path::new("/n/http");
        let absent = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("cmn-http is not running here (/n/http/admin is absent); start it first");
        let shown = sidecar_error(&absent, http, None, Some(Path::new("/n"))).to_string();
        assert!(
            shown.contains("/n/http/admin/admin.sock")
                && shown.contains("cmn-http is not running here")
                && shown.contains("`cmn http start --node-data-dir /n`"),
            "{shown}"
        );

        let refused =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                .context("connecting to cmn-http");
        let shown = sidecar_error(&refused, http, Some(http), None).to_string();
        assert!(
            shown.contains("`cmn http start --data-dir /n/http`"),
            "{shown}"
        );

        let other = anyhow!("the sidecar's admin directory must be private (0700)");
        let shown = sidecar_error(&other, http, None, None).to_string();
        assert_eq!(
            shown,
            "sidecar status on /n/http/admin/admin.sock: the sidecar's admin directory must be private (0700)"
        );
    }
}
