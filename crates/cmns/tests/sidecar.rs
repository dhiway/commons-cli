//! `cmns sidecar status` and `cmns cap check`, run as the real binary: a fake
//! sidecar socket answers the status op as `cmn-http` does, and a fake
//! `cmn-http` script stands in for `dev check`.
#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{json, Value};

/// ESC starting a colour sequence, a right-to-left override and a line
/// separator: what a hostile title would carry.
const HOSTILE: &str = "t\u{1b}[31m\u{202e}x\u{2028}y";

fn assert_no_raw(text: &str) {
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{202e}') && !text.contains('\u{2028}'),
        "a raw character reached the terminal: {text:?}"
    );
}

/// A directory under the system temp dir, removed on drop. Short, because a
/// Unix socket path is limited to about 104 bytes on macOS.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "cmns-sc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Binds `<dir>/admin/admin.sock` private, as the sidecar does.
fn bind_admin(dir: &Path) -> UnixListener {
    let admin = dir.join("admin");
    std::fs::create_dir_all(&admin).unwrap();
    std::fs::set_permissions(&admin, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = admin.join("admin.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
    listener
}

/// A sidecar that answers one request with `answer` and returns the request.
fn serve_once(dir: &Path, answer: Value) -> std::thread::JoinHandle<Value> {
    let listener = bind_admin(dir);
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let mut stream = reader.into_inner();
        stream.write_all(format!("{answer}\n").as_bytes()).unwrap();
        serde_json::from_str(&line).unwrap()
    })
}

fn cmns(args: &[&str], cmn_http_bin: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cmns"));
    command.args(args);
    match cmn_http_bin {
        Some(bin) => command.env("CMN_HTTP_BIN", bin),
        None => command.env_remove("CMN_HTTP_BIN"),
    };
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn sidecar_status_prints_the_sidecars_own_answer_escaped() {
    let dir = Dir::new();
    let status = json!({ "pid": 42, "bind": "127.0.0.1:8080", "title": HOSTILE });
    let server = serve_once(&dir.0, json!({ "result": status }));
    let out = cmns(
        &["sidecar", "status", "--data-dir", dir.0.to_str().unwrap()],
        None,
    );
    assert_eq!(
        server.join().unwrap(),
        json!({ "op": "status", "params": {} })
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert_no_raw(&stdout);
    assert!(stdout.contains(r"t\u001b[31m\u202ex\u2028y"), "{stdout}");
    let printed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(printed, status, "the answer is printed unchanged");

    let server = {
        std::fs::remove_dir_all(dir.0.join("admin")).unwrap();
        serve_once(&dir.0, json!({ "result": status }))
    };
    let out = cmns(
        &[
            "--human",
            "sidecar",
            "status",
            "--data-dir",
            dir.0.to_str().unwrap(),
        ],
        None,
    );
    server.join().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let stdout = text(&out.stdout);
    assert_no_raw(&stdout);
    assert!(
        stdout.contains("pid: 42\n") && stdout.contains(r"title: t\u{1b}[31m\u{202e}x\u{2028}y"),
        "{stdout}"
    );
}

#[test]
fn a_sidecar_refusal_is_an_error_carrying_its_message_escaped() {
    let dir = Dir::new();
    let server = serve_once(
        &dir.0,
        json!({ "error": { "code": "forbidden", "message": format!("no {HOSTILE}") } }),
    );
    let out = cmns(
        &["sidecar", "status", "--data-dir", dir.0.to_str().unwrap()],
        None,
    );
    server.join().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let stderr = text(&out.stderr);
    assert_no_raw(&stderr);
    assert!(
        stderr.contains(r"no t\u{1b}[31m\u{202e}x\u{2028}y (forbidden)"),
        "{stderr}"
    );
}

#[test]
fn an_absent_sidecar_is_refused_naming_the_socket_and_how_to_start_it() {
    let node = Dir::new();
    let out = cmns(
        &[
            "sidecar",
            "status",
            "--node-data-dir",
            node.0.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    let socket = node.0.join("http/admin/admin.sock");
    assert!(
        stderr.contains(&socket.display().to_string())
            && stderr.contains("cmn-http is not running here")
            && stderr.contains(&format!(
                "`cmn http start --node-data-dir {}`",
                node.0.display()
            )),
        "{stderr}"
    );
}

#[test]
fn a_socket_left_behind_is_refused_with_the_same_hint() {
    let dir = Dir::new();
    drop(bind_admin(&dir.0));
    let out = cmns(
        &["sidecar", "status", "--data-dir", dir.0.to_str().unwrap()],
        None,
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("connecting to cmn-http")
            && stderr.contains(&format!("`cmn http start --data-dir {}`", dir.0.display())),
        "{stderr}"
    );
}

/// A fake `cmn-http` that records its arguments one per line in `args`, then
/// runs `body`.
fn fake_cmn_http(dir: &Path, body: &str) -> PathBuf {
    let bin = dir.join("cmn-http");
    let script = format!(
        "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{}'\n{body}\n",
        dir.join("args").display()
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    bin
}

#[test]
fn cap_check_passes_the_report_and_the_failing_status_through() {
    let dir = Dir::new();
    let report =
        json!({ "ok": false, "lines": [{ "ok": false, "part": "manifest", "message": HOSTILE }] });
    // What the sidecar's serde_json writes: ESC as `\u001b` (kept literal
    // through printf), U+202E and U+2028 raw (printf's octal escapes).
    let raw = report.to_string().replace(r"\u001b", r"\\u001b");
    let raw = raw.replace('\u{202e}', "\\342\\200\\256");
    let raw = raw.replace('\u{2028}', "\\342\\200\\250");
    let bin = fake_cmn_http(
        &dir.0,
        &format!("printf '{raw}\\n'\nprintf 'warn \\033[2K\\n' >&2\nexit 1"),
    );
    let folder = dir.0.join("-my cap");
    let out = cmns(&["cap", "check", folder.to_str().unwrap()], Some(&bin));

    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let args = std::fs::read_to_string(dir.0.join("args")).unwrap();
    assert_eq!(
        args,
        format!("dev\ncheck\n--json\n--\n{}\n", folder.display()),
        "the folder is one argument after --"
    );
    let stdout = text(&out.stdout);
    assert_no_raw(&stdout);
    let printed: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{e}: {stdout:?}, stderr {:?}", text(&out.stderr)));
    assert_eq!(printed, report, "the report decodes to the sidecar's value");
    let stderr = text(&out.stderr);
    assert_eq!(stderr, "warn \\u{1b}[2K\n", "the sidecar's stderr, escaped");
}

#[test]
fn cap_check_human_prints_the_sidecars_own_report_and_its_status() {
    let dir = Dir::new();
    let bin = fake_cmn_http(
        &dir.0,
        "printf 'ok    manifest  fine\\nFAIL  hook  bad \\033[31m\\342\\200\\256x\\342\\200\\250y\\n'\nexit 3",
    );
    let out = cmns(&["--human", "cap", "check", "/c"], Some(&bin));
    assert_eq!(out.status.code(), Some(3));
    let args = std::fs::read_to_string(dir.0.join("args")).unwrap();
    assert_eq!(args, "dev\ncheck\n--\n/c\n", "no --json for humans");
    let stdout = text(&out.stdout);
    assert_eq!(
        stdout,
        "ok    manifest  fine\nFAIL  hook  bad \\u{1b}[31m\\u{202e}x\\u{2028}y\n"
    );
}

#[test]
fn cap_check_passes_a_clean_report_with_status_zero() {
    let dir = Dir::new();
    let bin = fake_cmn_http(&dir.0, "printf '{\"ok\": true, \"lines\": []}\\n'");
    let out = cmns(&["cap", "check", "/c"], Some(&bin));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let printed: Value = serde_json::from_str(&text(&out.stdout)).unwrap();
    assert_eq!(printed, json!({ "ok": true, "lines": [] }));
}

#[test]
fn cap_check_without_cmn_http_names_the_path_beside_cmns_and_the_variable() {
    let out = cmns(&["cap", "check", "/c"], None);
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    let beside = Path::new(env!("CARGO_BIN_EXE_cmns"))
        .parent()
        .unwrap()
        .join("cmn-http");
    assert!(
        stderr.contains(&format!(
            "cmn-http was not found beside cmns ({})",
            beside.display()
        )) && stderr.contains("set CMN_HTTP_BIN"),
        "{stderr}"
    );
}

#[test]
fn cap_check_with_cmn_http_bin_naming_nothing_is_refused_naming_it() {
    let dir = Dir::new();
    let missing = dir.0.join("nowhere");
    let out = cmns(&["cap", "check", "/c"], Some(&missing));
    assert_eq!(out.status.code(), Some(1));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains(&format!("running cmn-http at {}", missing.display())),
        "{stderr}"
    );
}
