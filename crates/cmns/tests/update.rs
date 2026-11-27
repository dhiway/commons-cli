//! `cmns update check|apply` and `cmns node upgrade`, run as the real binary
//! against a channel in a temporary directory: a manifest signed with a
//! throwaway key, as `ssh-keygen -Y sign` signs one, and release archives laid
//! out as `build-cmns.sh` packs them. No test touches the network or a node.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256, Sha512};

const TARGET: &str = env!("CMNS_TARGET");
const RUNNING: &str = env!("CARGO_PKG_VERSION");

/// A release `steps` patch numbers after the running cmns, so a set of it is
/// newer than `RUNNING` whatever version the crate carries.
fn newer(steps: u64) -> String {
    let mut version = semver::Version::parse(RUNNING).unwrap();
    version.patch += steps;
    version.pre = semver::Prerelease::EMPTY;
    version.build = semver::BuildMetadata::EMPTY;
    version.to_string()
}

/// ESC starting a colour sequence, a right-to-left override and a line
/// separator: what a hostile manifest field would carry.
const HOSTILE: &str = "\u{1b}[31m\u{202e}x\u{2028}y";

fn assert_no_raw(text: &str) {
    assert!(
        !text.contains('\u{1b}') && !text.contains('\u{202e}') && !text.contains('\u{2028}'),
        "a raw character reached the terminal: {text:?}"
    );
}

/// A directory under the system temp dir, removed on drop.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "cmns-up-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A throwaway Ed25519 key that signs as `ssh-keygen -Y sign -n
/// commons-release-manifest` does.
struct Key(SigningKey);

impl Key {
    fn new(label: &str) -> Self {
        let seed: [u8; 32] = Sha512::digest(format!("cmns update test key {label}").as_bytes())
            [..32]
            .try_into()
            .unwrap();
        Key(SigningKey::from_bytes(&seed))
    }

    fn blob(&self) -> Vec<u8> {
        let mut b = Vec::new();
        string(&mut b, b"ssh-ed25519");
        string(&mut b, self.0.verifying_key().as_bytes());
        b
    }

    /// Writes the `.pub` file a channel publishes.
    fn write_pub(&self, path: &Path) {
        let line = format!("ssh-ed25519 {} test-key\n", STANDARD.encode(self.blob()));
        fs::write(path, format!("# cmns update test key\n\n{line}")).unwrap();
    }

    fn sign(&self, message: &[u8]) -> String {
        const NAMESPACE: &[u8] = b"commons-release-manifest";
        let mut signed = b"SSHSIG".to_vec();
        string(&mut signed, NAMESPACE);
        string(&mut signed, b"");
        string(&mut signed, b"sha512");
        string(&mut signed, &Sha512::digest(message));
        let mut sig = Vec::new();
        string(&mut sig, b"ssh-ed25519");
        string(&mut sig, &self.0.sign(&signed).to_bytes());
        let mut blob = b"SSHSIG".to_vec();
        blob.extend_from_slice(&1u32.to_be_bytes());
        string(&mut blob, &self.blob());
        string(&mut blob, NAMESPACE);
        string(&mut blob, b"");
        string(&mut blob, b"sha512");
        string(&mut blob, &sig);
        let b64 = STANDARD.encode(blob);
        let body: Vec<&str> = b64
            .as_bytes()
            .chunks(70)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
            body.join("\n")
        )
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The stand-in for a released `cmns`: a script that prints its version, so a
/// test can run each installed version and see which one answers.
fn fake_cmns(version: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho \"cmns {version}\"\n").into_bytes()
}

/// `cmns-<version>-<target>.tar.gz` as `build-cmns.sh` packs it: PAX, the
/// binary and BUILD-INFO.json under `cmns-<version>-<target>/`. `binary`
/// `None` leaves the binary out.
fn archive(version: &str, binary: Option<&[u8]>) -> Vec<u8> {
    let stem = format!("cmns-{version}-{TARGET}");
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    let info = format!("{{\"component\": \"cmns\", \"version\": \"{version}\"}}\n");
    let mut entries: Vec<(&str, &[u8], u32)> = vec![("BUILD-INFO.json", info.as_bytes(), 0o644)];
    if let Some(binary) = binary {
        entries.push(("cmns", binary, 0o755));
    }
    for (name, data, mode) in entries {
        let mut header = tar::Header::new_ustar();
        header.set_path(format!("{stem}/{name}")).unwrap();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(mode);
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// One set as a channel lists it.
struct SetSpec {
    version: String,
    id: String,
    format_change: bool,
    /// The cmns asset's file name; `None` is the name `build-cmns.sh` uses.
    file_name: Option<String>,
    /// The archive's bytes; `None` is a good archive of `fake_cmns`.
    archive: Option<Vec<u8>>,
}

impl SetSpec {
    fn new(version: &str) -> Self {
        SetSpec {
            version: version.into(),
            id: version.into(),
            format_change: false,
            file_name: None,
            archive: None,
        }
    }

    fn file_name(&self) -> String {
        self.file_name
            .clone()
            .unwrap_or_else(|| format!("cmns-{}-{TARGET}.tar.gz", self.version))
    }

    fn archive(&self) -> Vec<u8> {
        self.archive
            .clone()
            .unwrap_or_else(|| archive(&self.version, Some(&fake_cmns(&self.version))))
    }
}

/// A channel directory, a key, and an install root, for one test.
struct Channel {
    dir: Dir,
    key: Key,
}

impl Channel {
    fn new() -> Self {
        let channel = Channel {
            dir: Dir::new(),
            key: Key::new("ci"),
        };
        fs::create_dir_all(channel.source().join("beta")).unwrap();
        fs::create_dir_all(channel.data()).unwrap();
        channel.key.write_pub(&channel.key_file());
        channel
    }

    fn source(&self) -> PathBuf {
        self.dir.0.join("releases")
    }

    fn key_file(&self) -> PathBuf {
        self.dir.0.join("beta-1.pub")
    }

    /// `XDG_DATA_HOME` for the run; the install root is under it.
    fn data(&self) -> PathBuf {
        self.dir.0.join("data")
    }

    fn root(&self) -> PathBuf {
        self.data().join("commons").join("cmns")
    }

    /// Signs and publishes a beta manifest listing `sets`, and writes each
    /// set's cmns archive beside it. The asset entry describes the good
    /// archive; `tamper` then replaces the file on disk.
    fn publish(&self, sequence: u64, sets: &[SetSpec]) {
        let beta = self.source().join("beta");
        let sets: Vec<Value> = sets
            .iter()
            .map(|set| {
                let bytes = set.archive();
                let name = set.file_name();
                fs::write(beta.join(&name), &bytes).unwrap();
                let node_name = format!("cmn-{}-{TARGET}.tar.gz", set.version);
                json!({
                    "id": set.id,
                    "format_change": set.format_change,
                    "requires_data_dir": if set.format_change { "new" } else { "same" },
                    "components": {
                        "cmns": {
                            "version": set.version,
                            "commit": "1111111111111111111111111111111111111111",
                            "assets": { TARGET: {
                                "url": format!("https://example.invalid/v{}/{name}", set.version),
                                "sha256": sha256_hex(&bytes),
                                "size": bytes.len(),
                            }}
                        },
                        "node": {
                            "version": set.version,
                            "commit": "2222222222222222222222222222222222222222",
                            "assets": { TARGET: {
                                "url": format!("https://example.invalid/v{}/{node_name}", set.version),
                                "sha256": sha256_hex(b"node"),
                                "size": 4,
                            }}
                        }
                    },
                    "notes_url": format!("https://example.invalid/notes/{}", set.version),
                    "build_profile": "release: lto=true, codegen-units=1, strip=true",
                })
            })
            .collect();
        let manifest = json!({
            "schema": 1,
            "channel": "beta",
            "published": "2020-01-01T00:00:00Z",
            "sequence": sequence,
            "expires": "2999-12-31T00:00:00Z",
            "sets": sets,
        });
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        fs::write(beta.join("manifest.json"), &bytes).unwrap();
        fs::write(beta.join("manifest.json.sig"), self.key.sign(&bytes)).unwrap();
    }

    /// Replaces a published asset with bytes of the same length, so only
    /// its sha256 is wrong.
    fn tamper(&self, file_name: &str) {
        let path = self.source().join("beta").join(file_name);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&path, bytes).unwrap();
    }

    fn cmns(&self, args: &[&str]) -> Run {
        let source = self.source();
        let key = self.key_file();
        let mut all: Vec<&str> = args.to_vec();
        all.extend([
            "--source",
            source.to_str().unwrap(),
            "--trust-key",
            key.to_str().unwrap(),
        ]);
        self.cmns_raw(&all)
    }

    fn cmns_raw(&self, args: &[&str]) -> Run {
        let output = Command::new(env!("CARGO_BIN_EXE_cmns"))
            .args(args)
            .env("XDG_DATA_HOME", self.data())
            .output()
            .unwrap();
        Run(output)
    }

    fn link(&self, name: &str) -> Option<PathBuf> {
        fs::read_link(self.root().join(name)).ok()
    }

    /// Runs an installed version through a link (`current`, `previous`) and
    /// answers what it printed.
    fn run_link(&self, name: &str) -> String {
        let out = Command::new(self.root().join(name).join("cmns"))
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }

    fn downloads_left(&self) -> usize {
        fs::read_dir(self.root().join("downloads")).map_or(0, |d| d.count())
    }
}

struct Run(Output);

impl Run {
    fn code(&self) -> i32 {
        self.0.status.code().unwrap()
    }
    fn stdout(&self) -> String {
        String::from_utf8(self.0.stdout.clone()).unwrap()
    }
    fn stderr(&self) -> String {
        String::from_utf8(self.0.stderr.clone()).unwrap()
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout())
            .unwrap_or_else(|e| panic!("{e}: {}\nstderr: {}", self.stdout(), self.stderr()))
    }
    fn expect(&self, code: i32) -> &Self {
        assert_eq!(
            self.code(),
            code,
            "stdout: {}\nstderr: {}",
            self.stdout(),
            self.stderr()
        );
        self
    }
}

#[test]
fn an_up_to_date_set_exits_0_and_a_newer_set_exits_10() {
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(RUNNING)]);
    let run = ch.cmns(&["update", "check"]);
    let report = run.expect(0).json();
    assert_eq!(report["verdict"], "current");
    assert_eq!(report["cmns"]["installed"], RUNNING);
    assert_eq!(report["node"]["installed"], Value::Null);

    let next = newer(1);
    ch.publish(2, &[SetSpec::new(RUNNING), SetSpec::new(&next)]);
    let run = ch.cmns(&["update", "check", "--json"]);
    let report = run.expect(10).json();
    assert_eq!(report["verdict"], "update-available");
    assert_eq!(report["cmns"]["available"], next.as_str());
    assert_eq!(report["set"]["id"], next.as_str());
    assert_eq!(report["moves_as_one_set"], false);
    assert_eq!(report["target"], TARGET);

    let human = ch.cmns(&["--human", "update", "check"]);
    let text = human.expect(10).stdout();
    assert!(
        text.contains("verdict: update-available\n")
            && text.contains(&format!("cmns.available: {next}\n")),
        "{text}"
    );
    let both = ch.cmns(&["--human", "update", "check", "--json"]);
    assert!(
        both.expect(1).stderr().contains("give one"),
        "{}",
        both.stderr()
    );

    // A format-change set is an update too, and the report says the two
    // move as one set.
    let mut set = SetSpec::new(&newer(2));
    set.format_change = true;
    ch.publish(3, &[set]);
    let report = ch.cmns(&["update", "check"]).expect(10).json();
    assert_eq!(report["moves_as_one_set"], true);
    assert!(
        report["message"]
            .as_str()
            .unwrap()
            .contains("cmns node upgrade"),
        "{report}"
    );
}

#[test]
fn a_tampered_asset_exits_20_naming_the_check_and_current_keeps_the_old_version() {
    let (old, new) = (newer(1), newer(2));
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(&old)]);
    ch.cmns(&["update", "apply"]).expect(0);
    let old_dir = PathBuf::from(format!("versions/{old}"));
    assert_eq!(ch.link("current").unwrap(), old_dir);

    let set = SetSpec::new(&new);
    let name = set.file_name();
    ch.publish(2, &[set]);
    ch.tamper(&name);
    // check reads only the manifest, which is good.
    ch.cmns(&["update", "check"]).expect(10);

    let run = ch.cmns(&["update", "apply"]);
    let report = run.expect(20).json();
    assert_eq!(report["verdict"], "verification-failed");
    assert_eq!(report["check"], "asset-sha256");
    assert!(
        report["detail"].as_str().unwrap().contains(&name),
        "{report}"
    );
    assert_eq!(ch.link("current").unwrap(), old_dir);
    assert!(ch.link("previous").is_none());
    assert!(!ch.root().join(format!("versions/{new}")).exists());
    assert_eq!(ch.downloads_left(), 0, "the download folder is removed");
    assert_eq!(ch.run_link("current"), format!("cmns {old}\n"));
}

#[test]
fn a_format_change_set_is_refused_with_30_naming_node_upgrade() {
    let ch = Channel::new();
    let mut set = SetSpec::new(&newer(1));
    set.format_change = true;
    ch.publish(1, &[set]);
    let run = ch.cmns(&["update", "apply"]);
    let report = run.expect(30).json();
    assert_eq!(report["verdict"], "refused");
    assert!(
        report["reason"]
            .as_str()
            .unwrap()
            .contains("`cmns node upgrade`"),
        "{report}"
    );
    assert!(ch.link("current").is_none());
    assert!(!ch.root().join("versions").exists());
}

#[test]
fn a_sequence_lower_than_the_last_seen_is_refused() {
    let next = newer(1);
    let ch = Channel::new();
    ch.publish(8, &[SetSpec::new(&next)]);
    ch.cmns(&["update", "check"]).expect(10);
    let state: Value =
        serde_json::from_slice(&fs::read(ch.root().join("state.json")).unwrap()).unwrap();
    assert_eq!(state["last_sequence"]["beta"], 8);

    // An older manifest, validly signed, is served again.
    ch.publish(7, &[SetSpec::new(&next)]);
    for command in ["check", "apply"] {
        let report = ch.cmns(&["update", command]).expect(20).json();
        assert_eq!(report["check"], "sequence", "{command}: {report}");
    }
    assert!(ch.link("current").is_none());
    // The same sequence again is not lower, and is accepted.
    ch.publish(8, &[SetSpec::new(&next)]);
    ch.cmns(&["update", "check"]).expect(10);
}

#[test]
fn apply_switches_current_and_keeps_the_previous_version_usable() {
    let (old, new) = (newer(1), newer(2));
    let (old_dir, new_dir) = (
        PathBuf::from(format!("versions/{old}")),
        PathBuf::from(format!("versions/{new}")),
    );
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(&old)]);
    let report = ch.cmns(&["update", "apply"]).expect(0).json();
    assert_eq!(report["verdict"], "applied");
    assert_eq!(report["cmns"]["installed"], old.as_str());
    assert_eq!(report["cmns"]["previous"], RUNNING);
    // No earlier version was installed here: the binary that ran stays where
    // it is, and no `previous` link is made.
    assert_eq!(report["previous"], env!("CARGO_BIN_EXE_cmns"));
    assert!(ch.link("previous").is_none());
    assert_eq!(ch.link("current").unwrap(), old_dir);
    assert_eq!(ch.run_link("current"), format!("cmns {old}\n"));
    let current = ch.root().join("current");
    let quoted = format!("export PATH='{}':\"$PATH\"", current.display());
    assert!(
        report["message"].as_str().unwrap().contains(&quoted),
        "{report}"
    );

    ch.publish(2, &[SetSpec::new(&old), SetSpec::new(&new)]);
    let report = ch.cmns(&["update", "apply"]).expect(0).json();
    assert_eq!(report["cmns"]["previous"], old.as_str());
    assert_eq!(ch.link("current").unwrap(), new_dir);
    assert_eq!(ch.link("previous").unwrap(), old_dir);
    assert_eq!(ch.run_link("current"), format!("cmns {new}\n"));
    assert_eq!(ch.run_link("previous"), format!("cmns {old}\n"));
    assert_eq!(ch.downloads_left(), 0);

    // Installed and current: nothing is downloaded, and check agrees.
    let report = ch.cmns(&["update", "apply"]).expect(0).json();
    assert_eq!(report["verdict"], "current");
    ch.cmns(&["update", "check"]).expect(0);
    let mut versions: Vec<String> = fs::read_dir(ch.root().join("versions"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    versions.sort();
    let mut expected = [old, new];
    expected.sort();
    assert_eq!(versions, expected);
}

/// Failures after the manifest and the asset passed verification, before
/// the switch: `current` still names the old version, which still runs.
#[test]
fn a_failure_between_download_and_switch_leaves_current_on_the_old_version() {
    let (old, new) = (newer(1), newer(2));
    let old_dir = PathBuf::from(format!("versions/{old}"));
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(&old)]);
    ch.cmns(&["update", "apply"]).expect(0);

    // A signed archive that does not hold the binary.
    let mut set = SetSpec::new(&new);
    set.archive = Some(archive(&new, None));
    ch.publish(2, &[set]);
    let run = ch.cmns(&["update", "apply"]);
    assert!(
        run.expect(1)
            .stderr()
            .contains(&format!("holds no cmns-{new}-{TARGET}/cmns")),
        "{}",
        run.stderr()
    );
    assert_eq!(ch.link("current").unwrap(), old_dir);
    assert!(!ch.root().join(format!("versions/{new}")).exists());
    assert_eq!(ch.downloads_left(), 0);

    // The version's folder cannot be made: a file is in its place.
    ch.publish(3, &[SetSpec::new(&new)]);
    fs::write(ch.root().join(format!("versions/{new}")), "in the way").unwrap();
    ch.cmns(&["update", "apply"]).expect(1);
    assert_eq!(ch.link("current").unwrap(), old_dir);
    assert!(ch.link("previous").is_none());
    assert_eq!(ch.run_link("current"), format!("cmns {old}\n"));
    assert_eq!(ch.downloads_left(), 0);
}

#[test]
fn a_channel_with_no_trusted_key_is_refused_with_30() {
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(&newer(1))]);
    let source = ch.source();
    let run = ch.cmns_raw(&["update", "check", "--source", source.to_str().unwrap()]);
    let report = run.expect(30).json();
    assert!(
        report["reason"].as_str().unwrap().contains("--trust-key"),
        "{report}"
    );
    // A key that did not sign the manifest fails the signature check.
    let other = ch.dir.0.join("other.pub");
    Key::new("someone else").write_pub(&other);
    let run = ch.cmns_raw(&[
        "update",
        "check",
        "--source",
        source.to_str().unwrap(),
        "--trust-key",
        other.to_str().unwrap(),
    ]);
    assert_eq!(run.expect(20).json()["check"], "signature");
}

#[test]
fn node_upgrade_outside_a_dry_run_is_refused_before_reading_anything() {
    let ch = Channel::new();
    let run = ch.cmns_raw(&["node", "upgrade", "--source", "/nonexistent/releases"]);
    let report = run.expect(30).json();
    assert!(
        report["reason"].as_str().unwrap().contains("M5"),
        "{report}"
    );
    assert!(!ch.root().exists());
}

#[test]
fn node_upgrade_dry_run_prints_the_set_the_verdict_and_the_steps_and_changes_nothing() {
    let next = newer(1);
    let ch = Channel::new();
    ch.publish(1, &[SetSpec::new(&next)]);
    let report = ch.cmns(&["node", "upgrade", "--dry-run"]).expect(0).json();
    assert_eq!(report["verdict"], "dry-run");
    assert_eq!(report["changed"], "nothing");
    assert_eq!(report["compatibility"], "same-data-directory");
    assert_eq!(report["set"]["id"], next.as_str());
    assert_eq!(report["node"]["target"], next.as_str());
    let steps: Vec<&str> = report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(steps.contains(&"stop the node"), "{steps:?}");
    assert!(
        steps.iter().any(|s| s.starts_with("health check")),
        "{steps:?}"
    );

    let mut set = SetSpec::new(&newer(2));
    set.format_change = true;
    ch.publish(2, &[set]);
    let text = ch
        .cmns(&["--human", "node", "upgrade", "--dry-run"])
        .expect(0)
        .stdout();
    assert!(text.contains("compatibility: format-change\n"), "{text}");
    assert!(text.contains("a new, empty data directory"), "{text}");
    assert!(!text.contains("stop the node"), "{text}");
    assert!(
        !ch.root().exists(),
        "a dry run writes nothing, not even the sequence"
    );
}

/// A set id carries ESC, U+202E and U+2028 (the verifier accepts any
/// non-empty id), and an asset's file name carries ESC and U+202E (a URL
/// cannot hold U+2028). Both reach the output only escaped, on the JSON and
/// the human path, and the JSON still decodes to the manifest's text.
#[test]
fn text_from_the_manifest_is_escaped_on_the_json_and_the_human_path() {
    let (old, new) = (newer(1), newer(2));
    let ch = Channel::new();
    let mut set = SetSpec::new(&old);
    set.id = format!("{old}{HOSTILE}");
    ch.publish(1, &[set]);

    let run = ch.cmns(&["update", "check"]);
    let stdout = run.expect(10).stdout();
    assert_no_raw(&stdout);
    assert!(
        stdout.contains(&format!("\"id\": \"{old}\\u001b[31m\\u202ex\\u2028y\"")),
        "{stdout}"
    );
    let report: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(report["set"]["id"], format!("{old}{HOSTILE}"));

    let human = ch.cmns(&["--human", "update", "check"]).expect(10).stdout();
    assert_no_raw(&human);
    assert!(
        human.contains(&format!(
            "set.id: {old}\\u{{1b}}[31m\\u{{202e}}x\\u{{2028}}y\n"
        )),
        "{human}"
    );

    let mut set = SetSpec::new(&new);
    set.file_name = Some(format!("cmns\u{1b}[2K\u{202e}-{TARGET}.tar.gz"));
    let name = set.file_name();
    ch.publish(2, &[set]);
    ch.tamper(&name);
    let run = ch.cmns(&["update", "apply"]);
    let stdout = run.expect(20).stdout();
    assert_no_raw(&stdout);
    assert!(stdout.contains("(cmns\\u001b[2K\\u202e-"), "{stdout}");
    let human = ch.cmns(&["--human", "update", "apply"]).expect(20).stdout();
    assert_no_raw(&human);
    assert!(
        human.contains("check: asset-sha256\n") && human.contains(r"(cmns\u{1b}[2K\u{202e}-"),
        "{human}"
    );
}

#[test]
fn a_source_that_is_not_https_or_a_directory_is_an_error() {
    let ch = Channel::new();
    for source in ["http://example.invalid/releases", "ftp://example.invalid"] {
        let run = ch.cmns_raw(&["update", "check", "--source", source]);
        assert!(
            run.expect(1).stderr().contains("neither an https:// URL"),
            "{}",
            run.stderr()
        );
    }
}
