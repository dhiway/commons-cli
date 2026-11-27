//! `cmns` — the Commons command line.
//!
//! This is step C of the plan (`docs/architecture/cli.md` in the coordination
//! repository): a read-only command line that reaches a node over the
//! interfaces the node publishes, with no dependency on the node's own crate.
//! `version` and `node status` are the first commands; the rest of the surface
//! is built behind the same boundary.
//!
//! The boundary rule: this crate depends on `commons-node-client` (wire types
//! and client), `iroh` for the caller's endpoint, and ordinary crates. It must
//! never depend on `commons-node` or `commons-node-rpc`.

use std::{path::PathBuf, str::FromStr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use commons_node_client::{
    ClientError, ControlClient, OP_ADMIN_DATASETS_LIST, OP_ADMIN_DATASETS_SHOW,
    OP_ADMIN_HTTP_STATUS, OP_ADMIN_NODE_INFO,
};
use iroh::SecretKey;
use iroh_tickets::endpoint::EndpointTicket;
use serde_json::{json, Value};

mod cap;
mod sidecar;
mod update;

/// The node versions this build was written against. Stated on `version`, and
/// enforced on every answer that carries a node `version` (see
/// [`ensure_compatible`]): a different minor version is refused, not guessed at.
const COMPATIBLE_NODE: &str = "node 0.9.x (control/1, admin over iroh)";
/// The client revision this build carries, read from the lockfile by the
/// build script (`build.rs`), so it cannot drift from the pin.
const CLIENT_REV: &str = env!("CMNS_CLIENT_REV");
/// How long `node status` waits for the node by default.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

#[derive(Debug, Parser)]
#[command(name = "cmns", version, about = "The Commons command line")]
struct Cli {
    /// Output as a table instead of JSON.
    #[arg(long, global = true)]
    human: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The CLI's version and the node versions it works with.
    Version,
    /// Which key this caller acts with.
    Whoami {
        /// The caller's key: 32 bytes, hex.
        #[arg(long)]
        key: PathBuf,
    },
    /// A node: its health and what it reports about itself.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// The node's HTTP API: what it serves and to whom.
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
    /// A dataset the node hosts.
    Dataset {
        #[command(subcommand)]
        command: DatasetCommand,
    },
    /// The node's capabilities: its plugin documents and datasets, read over
    /// its private local admin socket on this machine.
    Cap {
        /// The node's data directory; its admin socket is
        /// `<data-dir>/admin/admin.sock`.
        #[arg(long, global = true, default_value = cap::DEFAULT_DATA_DIR)]
        data_dir: PathBuf,
        #[command(subcommand)]
        command: cap::CapCommand,
    },
    /// The node's HTTP door, cmn-http, read over its private admin socket
    /// on this machine. The flags are `cmn http`'s.
    Sidecar {
        /// cmn-http's directory; its admin socket is
        /// `<data-dir>/admin/admin.sock` (default: `<node-data-dir>/http`, as
        /// `cmn http` uses; cmn-http itself has no default).
        #[arg(long, global = true, value_name = "PATH")]
        data_dir: Option<PathBuf>,
        /// The node's data directory (default ./data), under which the
        /// sidecar's directory is `http` unless --data-dir names another.
        #[arg(long, global = true, value_name = "PATH")]
        node_data_dir: Option<PathBuf>,
        #[command(subcommand)]
        command: sidecar::SidecarCommand,
    },
    /// cmns's own updates, from a channel's signed release manifest.
    Update {
        #[command(subcommand)]
        command: update::UpdateCommand,
    },
}

/// How to reach one node: its ticket, the caller's key, and the budget.
#[derive(Debug, Args)]
struct Conn {
    /// The node's ticket, as printed by `cmn info --ticket` on the node.
    #[arg(long)]
    ticket: String,
    /// The caller's admin key: 32 bytes, hex. The node's operator must
    /// have enrolled it with `cmn admins add <endpoint-id>`.
    #[arg(long)]
    key: PathBuf,
    /// Seconds to wait for the node, for the whole exchange.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Ask a node for its status over iroh, named by its ticket.
    Status {
        #[command(flatten)]
        conn: Conn,
    },
    /// What upgrading the node to a channel's newest set would do. Only
    /// `--dry-run` is available: it changes nothing. Exit 0 printed, 20
    /// verification failed, 30 refused (always, without --dry-run).
    Upgrade(update::UpgradeArgs),
}

#[derive(Debug, Subcommand)]
enum ApiCommand {
    /// What the node's HTTP door serves, and whether each part is exposed.
    Status {
        #[command(flatten)]
        conn: Conn,
    },
}

#[derive(Debug, Subcommand)]
enum DatasetCommand {
    /// The node's own datasets, one page at a time.
    List {
        #[command(flatten)]
        conn: Conn,
        /// Continue after the cursor a previous page returned.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// One dataset, with its owners and peers and their rights.
    Show {
        #[command(flatten)]
        conn: Conn,
        /// The dataset's namespace, as `dataset list` prints it.
        namespace: String,
    },
}

fn main() -> std::process::ExitCode {
    // Clap prints its own usage errors and exits 2 inside `parse`; every
    // other failure is printed here, once, and exits 1 as before. A command
    // that passes on another program's status (`cap check`) answers it.
    match Cli::parse().run() {
        Ok(code) => std::process::ExitCode::from(code),
        Err(err) => {
            eprintln!("{}", error_line(&err));
            std::process::ExitCode::FAILURE
        }
    }
}

/// The one place a failure reaches the terminal. `main` prints every error
/// through here, so text a node controls cannot reach stderr raw by any path,
/// including errors passed through unchanged from the client or the
/// transport (a peer's connection-close reason, say). The chain is printed on
/// one line (`{:#}`) and escaped with [`escape`]. Escaping is idempotent:
/// it rewrites only [`must_escape`] characters, and an already-escaped
/// `\u{1b}` contains none, so errors that escaped their pieces earlier read
/// the same.
fn error_line(err: &anyhow::Error) -> String {
    format!("Error: {}", escape(&format!("{err:#}")))
}

impl Cli {
    /// Runs the command and answers the process's exit code.
    fn run(self) -> Result<u8> {
        match self.command {
            Command::Version => {
                let v = version_report();
                print_json(&v, self.human)?;
            }
            Command::Whoami { key } => {
                let key = read_key(&key)?;
                let v = json!({
                    "endpoint_id": key.public().to_z32(),
                    "hex": key.public().to_string(),
                });
                print_json(&v, self.human)?;
            }
            Command::Node { command } => match command {
                NodeCommand::Status { conn } => {
                    let answer = call(OP_ADMIN_NODE_INFO, json!({}), conn)?;
                    print_json(&answer, self.human)?;
                }
                NodeCommand::Upgrade(args) => {
                    return update::print(&update::node_upgrade(&args)?, self.human)
                }
            },
            Command::Update { command } => {
                return update::print(&update::update(command, self.human)?, self.human)
            }
            Command::Api { command } => match command {
                ApiCommand::Status { conn } => {
                    let answer = call(OP_ADMIN_HTTP_STATUS, json!({}), conn)?;
                    print_json(&answer, self.human)?;
                }
            },
            Command::Dataset { command } => match command {
                DatasetCommand::List { conn, cursor } => {
                    let answer = call(OP_ADMIN_DATASETS_LIST, json!({ "cursor": cursor }), conn)?;
                    print_json(&answer, self.human)?;
                }
                DatasetCommand::Show { conn, namespace } => {
                    let answer = call(
                        OP_ADMIN_DATASETS_SHOW,
                        json!({ "namespace": namespace }),
                        conn,
                    )?;
                    print_json(&answer, self.human)?;
                }
            },
            Command::Cap { data_dir, command } => return cap::run(&data_dir, command, self.human),
            Command::Sidecar {
                data_dir,
                node_data_dir,
                command,
            } => sidecar::run(
                data_dir.as_deref(),
                node_data_dir.as_deref(),
                command,
                self.human,
            )?,
        }
        Ok(0)
    }
}

/// One round trip: connect, call, close. `node status` is this with
/// `admin.node-info`; every read command is the same exchange with another
/// operation.
fn call(op: &str, params: Value, conn: Conn) -> Result<Value> {
    let runtime = tokio::runtime::Runtime::new().context("starting tokio")?;
    runtime.block_on(admin_call(op, params, &conn))
}

/// What `cmns version` prints. A function so a test can read the fields the
/// command actually emits, not only the constants behind them.
fn version_report() -> Value {
    json!({
        "cmns": env!("CARGO_PKG_VERSION"),
        "compatible": COMPATIBLE_NODE,
        "client_rev": CLIENT_REV,
    })
}

fn print_json(value: &Value, human: bool) -> Result<()> {
    if human {
        // One `key: value` line per field. serde_json's maps are ordered by
        // key (no preserve_order), so this is alphabetical, not the node's
        // own order; values are the node's.
        match value.as_object() {
            Some(map) => {
                for (k, v) in map {
                    println!("{}: {}", escape(k), scalar(v));
                }
            }
            None => println!("{}", scalar(value)),
        }
        return Ok(());
    }
    println!("{}", encode_json(value)?);
    Ok(())
}

/// Whether a character from the node must not reach a terminal raw, decided
/// by Unicode category rather than by a list: a control character (Cc: C0
/// such as ESC and CR, DEL, C1 such as U+009B CSI), a format character (Cf:
/// the bidi overrides and isolates, zero-width marks, U+00AD, the BOM, the tag
/// characters U+E0000..U+E007F), a line or paragraph separator (Zl, Zp:
/// U+2028, U+2029, which break a `key: value` line), or a default-ignorable
/// code point (variation selectors, CGJ U+034F, Hangul fillers, ...). The data
/// is ICU's compiled Unicode tables. One predicate for the human path
/// ([`escape`]) and the JSON path ([`encode_json`]); the README's Output
/// section states the rule.
pub(crate) fn must_escape(c: char) -> bool {
    use icu_properties::{
        props::{DefaultIgnorableCodePoint, GeneralCategory},
        CodePointMapData, CodePointSetData,
    };
    c.is_control()
        || matches!(
            CodePointMapData::<GeneralCategory>::new().get(c),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
        )
        || CodePointSetData::new::<DefaultIgnorableCodePoint>().contains(c)
}

/// A string from the node made safe for a terminal, for the human output and
/// error messages: a control character is written as `char::escape_default`
/// writes it (`\u{1b}`, `\r`), any other as `char::escape_unicode`
/// (`\u{202e}`, `\u{e0041}`), so a title or a refusal cannot move the cursor, recolour,
/// reorder or hide what the operator reads.
pub(crate) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if !must_escape(c) {
            out.push(c);
        } else if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
}

/// A node's answer as pretty JSON that is safe to print to a terminal.
///
/// serde_json escapes C0 controls inside strings but writes every other
/// [`must_escape`] character raw; this rewrites each of those as `\uXXXX`.
/// JSON's `\u` takes four hex digits, so a code point above U+FFFF (the tag
/// characters, U+E0000..U+E007F, are astral) is written as its UTF-16
/// surrogate pair, `\udb40\udc41` for U+E0041, which a JSON reader joins
/// back into the one character. These characters can only occur inside a
/// string, so the output is valid JSON and decodes to exactly the node's
/// value; only the encoded bytes for those characters differ from serde's. A
/// raw C0 character left in the text is the printer's own newline between
/// tokens, which is kept.
pub(crate) fn encode_json(value: &Value) -> Result<String> {
    let pretty = serde_json::to_string_pretty(value)?;
    let mut out = String::with_capacity(pretty.len());
    for c in pretty.chars() {
        if must_escape(c) && u32::from(c) >= 0x7F {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn scalar(value: &Value) -> String {
    escape(&match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    })
}

fn read_key(path: &PathBuf) -> Result<SecretKey> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes = hex::decode(text.trim()).context("the key file is not hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("the key file is not 32 bytes"))?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// [`admin_exchange`], refused unless the node is one this build works with
/// ([`ensure_compatible`]).
async fn admin_call(op: &str, params: Value, conn: &Conn) -> Result<Value> {
    let (value, node) = admin_exchange(op, params, conn).await?;
    ensure_compatible(&value, &node)?;
    Ok(value)
}

/// One admin call: the answer as the node sent it, and the node's endpoint
/// id. `cmns update` reads the node's version straight from this, since a
/// node of another minor version is the case an update exists for; every
/// other command goes through [`admin_call`].
async fn admin_exchange(op: &str, params: Value, conn: &Conn) -> Result<(Value, String)> {
    let timeout_secs = conn.timeout;
    let ticket = EndpointTicket::from_str(conn.ticket.trim()).context(
        "parsing the ticket: pass the ticket `cmn info --ticket` prints, not the one `init` prints",
    )?;
    let addr = ticket.endpoint_addr().clone();
    let key = read_key(&conn.key)?;
    // The ticket names which node to reach; it does not choose the network.
    // A Commons program builds its endpoint from the Commons profile — the
    // relays, their allowlist, the DNS resolver and the signed lookups — and
    // never from the ticket's own relay list (spec node-access 8.1,
    // architecture principle 1). A relay-only node is still reached through
    // the profile's relays, and no relay outside the profile is contacted.
    let endpoint = commons_node_client::profile::builder()
        .context("reading the Commons network profile")?
        .secret_key(key.clone())
        .bind()
        .await
        .context("binding the caller's endpoint")?;
    let budget = Duration::from_secs(timeout_secs);
    let started = std::time::Instant::now();

    let client = match tokio::time::timeout(
        budget,
        ControlClient::connect(&endpoint, addr.clone(), &key, &[op]),
    )
    .await
    {
        Err(_) => {
            endpoint.close().await;
            bail!(
                "the node did not answer within {timeout_secs}s (ticket names {})",
                addr.id.to_z32()
            );
        }
        Ok(Ok(client)) => client,
        Ok(Err(ClientError::Refused { code, payload, .. })) => {
            endpoint.close().await;
            bail!(
                "the node refused this key {caller} ({}): {}. The node's operator enrols it with `cmn admins add {caller}`.",
                escape(&code.to_string()),
                escape(&payload.to_string()),
                caller = key.public().to_z32()
            );
        }
        Ok(Err(err)) => {
            endpoint.close().await;
            return Err(err.into());
        }
    };

    // The timeout covers the whole exchange, not only the dial: the client's
    // request has no deadline of its own, so a node that opens the session and
    // then stalls would otherwise hang the command.
    let left = budget.saturating_sub(started.elapsed());
    let answer = match tokio::time::timeout(left, client.call(op, &params, None)).await {
        Err(_) => {
            client.close();
            endpoint.close().await;
            bail!(
                "the node accepted the session but did not answer within {timeout_secs}s (ticket names {})",
                addr.id.to_z32()
            );
        }
        Ok(answer) => answer,
    };
    client.close();
    endpoint.close().await;

    match answer {
        Ok(value) => Ok((value, addr.id.to_z32())),
        Err(ClientError::Refused { code, payload, .. }) => {
            bail!(
                "the node refused the call ({}): {}",
                escape(&code.to_string()),
                escape(&payload.to_string())
            )
        }
        Err(err) => Err(err.into()),
    }
}

/// Refuse an answer from a node this build was not written for.
///
/// The check is deliberately narrow: a node that reports a `version` other
/// than 0.9.x is refused, and the message says which side is older, because
/// acting on it is guessing. A node that reports no version at all is not
/// refused — the interface answered, and the caller can see the absence.
fn ensure_compatible(answer: &Value, node: &str) -> Result<()> {
    let Some(version) = answer.get("version").and_then(Value::as_str) else {
        return Ok(());
    };
    let version = escape(version);
    let version = version.as_str();
    let Some((major, minor)) = parse_minor(version) else {
        bail!("the node {node} reports version {version}, which this cmns cannot read; this build is written for {COMPATIBLE_NODE}");
    };
    if (major, minor) == (0, 9) {
        return Ok(());
    }
    let ourselves = format!("cmns {}", env!("CARGO_PKG_VERSION"));
    if (major, minor) < (0, 9) {
        bail!("the node {node} is older: it answers version {version}, and {ourselves} is written for {COMPATIBLE_NODE}. Upgrade the node, or use a cmns built for it.");
    }
    bail!("{ourselves} is older: the node {node} answers version {version}, and this build is written for {COMPATIBLE_NODE}. Upgrade cmns.");
}

/// `0.9.47` -> (0, 9). Anything else is `None` and is refused as unreadable.
fn parse_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{endpoint::presets, Endpoint, RelayMode};

    #[test]
    fn version_reports_the_cli_and_the_node_it_works_with() {
        let cli = Cli::try_parse_from(["cmns", "version"]).expect("version parses");
        assert!(matches!(cli.command, Command::Version));
        let v = version_report();
        assert_eq!(v["cmns"], env!("CARGO_PKG_VERSION"));
        assert!(v["compatible"].as_str().unwrap().contains("node 0.9.x"));
    }

    /// The revision printed is the one the lockfile resolved, not a constant
    /// and not the build script's `unknown` fallback: the seven characters
    /// must be the start of the client's pinned source revision.
    #[test]
    fn version_reports_the_client_revision_the_lockfile_resolved() {
        let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.lock");
        let text = std::fs::read_to_string(&lock).expect("this build has a lockfile");
        let rev = version_report()["client_rev"].as_str().unwrap().to_owned();
        assert_eq!(rev.len(), 7, "the build script read the lockfile: {rev}");
        let entry = text
            .lines()
            .skip_while(|line| line.trim() != r#"name = "commons-node-client""#)
            .find_map(|line| line.trim().strip_prefix("source = \"git+"))
            .expect("the lockfile names the client's source");
        assert!(entry.contains(&rev), "printed {rev}, lockfile says {entry}");
    }

    #[test]
    fn a_timeout_of_zero_is_refused_by_the_parser() {
        let err = Cli::try_parse_from([
            "cmns",
            "node",
            "status",
            "--ticket",
            "t",
            "--key",
            "k",
            "--timeout",
            "0",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation, "{err}");
    }

    #[test]
    fn a_key_file_that_is_not_32_bytes_is_refused() {
        let dir = std::env::temp_dir().join(format!("cmns-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("short.key");
        std::fs::write(&path, "abcd").unwrap();
        let err = read_key(&path).unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "unexpected error: {err}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn status_needs_a_ticket_and_a_key() {
        let err = Cli::try_parse_from(["cmns", "node", "status"]).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("--ticket") || text.contains("--key"),
            "{text}"
        );
    }

    #[test]
    fn a_node_from_another_minor_version_is_refused_naming_the_older_side() {
        let ok = json!({"version": "0.9.47"});
        assert!(ensure_compatible(&ok, "n1").is_ok());

        let old = json!({"version": "0.8.1"});
        let err = ensure_compatible(&old, "n1").unwrap_err().to_string();
        assert!(
            err.contains("0.8.1") && err.contains("node n1 is older"),
            "{err}"
        );

        let newer = json!({"version": "0.10.0"});
        let err = ensure_compatible(&newer, "n1").unwrap_err().to_string();
        let ourselves = format!("cmns {} is older", env!("CARGO_PKG_VERSION"));
        assert!(err.contains(&ourselves), "{err}");

        let unreadable = json!({"version": "one"});
        assert!(ensure_compatible(&unreadable, "n1").is_err());

        let silent = json!({"health": "ready"});
        assert!(ensure_compatible(&silent, "n1").is_ok());
    }

    #[test]
    fn the_read_commands_parse_and_require_their_arguments() {
        let api = Cli::try_parse_from(["cmns", "api", "status", "--ticket", "t", "--key", "k"])
            .expect("api status parses");
        assert!(matches!(api.command, Command::Api { .. }));

        let list = Cli::try_parse_from([
            "cmns", "dataset", "list", "--ticket", "t", "--key", "k", "--cursor", "c1",
        ])
        .expect("dataset list parses");
        match list.command {
            Command::Dataset {
                command: DatasetCommand::List { cursor, .. },
            } => {
                assert_eq!(cursor.as_deref(), Some("c1"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        assert!(
            Cli::try_parse_from(["cmns", "dataset", "show", "--ticket", "t", "--key", "k"])
                .is_err(),
            "dataset show needs a namespace"
        );
    }

    /// `--human` on the M2 read commands (`api status`, `dataset show`, ...)
    /// prints node strings through `scalar`; a control character there is
    /// escaped for the terminal and left as the node sent it in JSON.
    #[test]
    fn a_control_character_in_a_node_string_is_escaped_for_humans_and_kept_in_json() {
        let hostile = "title\u{1b}[31mRED\rFORGED\u{9b}2J\u{7f}";
        let human = scalar(&json!(hostile));
        assert!(
            !human.chars().any(char::is_control),
            "raw control character for the terminal: {human:?}"
        );
        assert_eq!(human, r"title\u{1b}[31mRED\rFORGED\u{9b}2J\u{7f}");

        let answer = json!({ "card": { "title": hostile } });
        let encoded = encode_json(&answer).unwrap();
        assert!(encoded.contains(r"title\u001b[31mRED\rFORGED"), "{encoded}");
        let decoded: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            decoded["card"]["title"], hostile,
            "JSON keeps the node's string"
        );
        let nested = scalar(&answer["card"]);
        assert!(!nested.chars().any(char::is_control), "{nested:?}");

        let old = json!({ "version": "0.8.1\u{1b}[2K" });
        let err = ensure_compatible(&old, "n1").unwrap_err().to_string();
        assert!(!err.chars().any(char::is_control), "{err:?}");
    }

    /// The characters that reorder or hide text: a right-to-left override and
    /// a zero-width space, next to the controls.
    const SPOOF: &str = "ns-a\u{202E}lbat\u{200B}x\u{9b}2J\u{7f}\u{1b}[1m";

    #[test]
    fn a_bidi_or_zero_width_character_is_escaped_for_humans() {
        let human = scalar(&json!(SPOOF));
        assert!(!human.chars().any(must_escape), "{human:?}");
        assert_eq!(human, r"ns-a\u{202e}lbat\u{200b}x\u{9b}2J\u{7f}\u{1b}[1m");
        let nested = scalar(&json!({ "title": SPOOF }));
        assert!(!nested.chars().any(must_escape), "{nested:?}");
    }

    #[test]
    fn the_json_escapes_c1_del_and_format_characters_and_decodes_to_the_node_string() {
        let answer = json!({ "card": { "title": SPOOF }, "n": 1 });
        let encoded = encode_json(&answer).unwrap();
        assert!(
            !encoded.chars().any(|c| must_escape(c) && c != '\n'),
            "raw character in the JSON text: {encoded:?}"
        );
        assert!(
            encoded.contains(r"ns-a\u202elbat\u200bx\u009b2J\u007f\u001b[1m"),
            "{encoded}"
        );
        let decoded: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            decoded, answer,
            "the JSON decodes to the node's exact value"
        );
    }

    /// The four characters the category rule was written for: a soft hyphen
    /// (Cf), the line separator (Zl), a variation selector (default
    /// ignorable) and a tag character (Cf, astral: a surrogate pair in JSON).
    #[test]
    fn category_rule_escapes_soft_hyphen_line_separator_variation_selector_and_tag() {
        for (c, human_form, json_form) in [
            ('\u{AD}', r"\u{ad}", r"\u00ad"),
            ('\u{2028}', r"\u{2028}", r"\u2028"),
            ('\u{FE0F}', r"\u{fe0f}", r"\ufe0f"),
            ('\u{E0041}', r"\u{e0041}", r"\udb40\udc41"),
        ] {
            assert!(must_escape(c), "U+{:04X} must be escaped", u32::from(c));
            let node = format!("a{c}b");

            let human = scalar(&json!(node));
            assert!(!human.chars().any(must_escape), "{human:?}");
            assert_eq!(human, format!("a{human_form}b"));

            let answer = json!({ "title": node });
            let encoded = encode_json(&answer).unwrap();
            assert!(
                !encoded.chars().any(|c| must_escape(c) && c != '\n'),
                "raw character in the JSON text: {encoded:?}"
            );
            assert!(encoded.contains(&format!("a{json_form}b")), "{encoded}");
            let decoded: Value = serde_json::from_str(&encoded).unwrap();
            assert_eq!(
                decoded,
                answer,
                "U+{:04X} decodes back exactly",
                u32::from(c)
            );
        }
        // Ordinary text, including non-Latin letters and an emoji, is untouched.
        for c in ['e', 'é', 'न', '中', '😀', ' '] {
            assert!(!must_escape(c), "U+{:04X} is ordinary text", u32::from(c));
        }
    }

    /// An error the program passes through unchanged still reaches stderr
    /// escaped: `main` prints every failure through `error_line`.
    #[test]
    fn an_error_carrying_node_text_is_escaped_where_main_prints_it() {
        let hostile = "closed: a\u{1b}[2Kb\rc\u{9b}2Jd\u{202e}e\u{2028}f";
        let err = anyhow::anyhow!("{hostile}").context("dialling the node");
        let line = error_line(&err);
        assert!(!line.chars().any(must_escape), "{line:?}");
        assert!(
            line.starts_with("Error: dialling the node: closed: a\\u{1b}[2Kb\\rc"),
            "{line}"
        );
        assert_eq!(
            error_line(&anyhow::anyhow!("{}", escape(hostile))),
            line.replace("dialling the node: ", ""),
            "escaping twice reads the same"
        );
    }

    /// The reviewer's case: a node that opens the session and then closes
    /// the connection with a crafted reason. The client returns it as
    /// `ClientError::Unavailable`, whose chain prints the peer's reason bytes.
    #[test]
    fn a_peer_close_reason_is_escaped_where_main_prints_it() {
        use iroh::endpoint::{ApplicationClose, ConnectionError, ReadError, VarInt};
        let reason = "bye\u{1b}]0;owned\u{7}\r\u{9b}31m\u{202e}x\u{2028}y";
        let closed = ConnectionError::ApplicationClosed(ApplicationClose {
            error_code: VarInt::from_u32(7),
            reason: reason.as_bytes().to_vec().into(),
        });
        let err: anyhow::Error =
            ClientError::Unavailable(ReadError::ConnectionLost(closed).into()).into();
        let raw = format!("{err:#}");
        assert!(
            raw.chars().any(must_escape),
            "the test value carries the hostile reason: {raw:?}"
        );
        let line = error_line(&err);
        assert!(!line.chars().any(must_escape), "{line:?}");
        assert!(line.contains(r"bye\u{1b}]0;owned\u{7}\r"), "{line}");
    }

    #[test]
    fn cap_takes_the_data_directory_on_either_side_and_defaults_to_the_nodes() {
        let cli = Cli::try_parse_from(["cmns", "cap", "list"]).expect("cap list parses");
        match cli.command {
            Command::Cap { data_dir, .. } => assert_eq!(data_dir, PathBuf::from("./data")),
            other => panic!("unexpected: {other:?}"),
        }
        let cli = Cli::try_parse_from(["cmns", "cap", "show", "n1", "--data-dir", "/tmp/d"])
            .expect("cap show parses");
        match cli.command {
            Command::Cap {
                data_dir,
                command: cap::CapCommand::Show { namespace },
            } => {
                assert_eq!(data_dir, PathBuf::from("/tmp/d"));
                assert_eq!(namespace, "n1");
            }
            other => panic!("unexpected: {other:?}"),
        }
        assert!(
            Cli::try_parse_from(["cmns", "cap", "show"]).is_err(),
            "cap show needs a namespace"
        );
    }

    #[tokio::test]
    async fn a_ticket_that_is_not_a_ticket_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("cmns-test-ticket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.key");
        std::fs::write(&key, hex::encode([7u8; 32])).unwrap();
        let conn = Conn {
            ticket: "not-a-ticket".into(),
            key: key.clone(),
            timeout: 1,
        };
        let err = admin_call(OP_ADMIN_NODE_INFO, json!({}), &conn)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("ticket"),
            "unexpected error: {err}"
        );
        std::fs::remove_file(&key).ok();
    }

    /// The timeout covers the call, not only the dial. A node that completes
    /// the session open and then never answers must fail the command inside
    /// the budget instead of hanging: the fake node below speaks the real
    /// handshake (it signs a session certificate for the operations the
    /// caller asked) and then holds the call's stream open.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_that_opens_the_session_and_never_answers_times_out() {
        use auth_wire::v2::{SessionCertificate, VERSION};
        use commons_node_client::{ControlRequest, ControlResponse, CONTROL_ALPN, MAX_FRAME};

        // The budget covers the dial, the session open and the call; 5 s
        // leaves room for the first dial on a loaded machine.
        const BUDGET_SECS: u64 = 5;
        let node_key = SecretKey::generate();
        let server = Endpoint::builder(presets::Minimal)
            .secret_key(node_key.clone())
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![CONTROL_ALPN.to_vec()])
            .bind()
            .await
            .expect("binding the fake node");
        let ticket = EndpointTicket::new(server.addr()).to_string();

        let answering = server.clone();
        let signer = node_key.clone();
        let fake = tokio::spawn(async move {
            let connection = answering.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let raw = recv.read_to_end(MAX_FRAME).await.unwrap();
            let ControlRequest::Signed(open) = postcard::from_bytes(&raw).unwrap() else {
                panic!("the caller's first request opens a session");
            };
            let asked: serde_json::Value = serde_json::from_slice(&open.payload).unwrap();
            let session_public: [u8; 32] = asked["sessionPublic"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_u64().unwrap() as u8)
                .collect::<Vec<_>>()
                .try_into()
                .expect("a 32-byte session key");
            let capabilities: Vec<String> = asked["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| c.as_str().unwrap().to_owned())
                .collect();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let mut certificate = SessionCertificate {
                version: VERSION,
                session_id: [7; 16],
                principal: open.principal.clone(),
                session_public,
                audience: open.audience.clone(),
                capabilities,
                issued_at_ms: now,
                expires_at_ms: now + 120_000,
                authorized_at_ms: now,
                issuer_key: *signer.public().as_bytes(),
                signature: Vec::new(),
            };
            auth_wire::sign(&mut certificate, &signer).unwrap();
            let answer = ControlResponse::Session(Box::new(certificate));
            send.write_all(&postcard::to_stdvec(&answer).unwrap())
                .await
                .unwrap();
            send.finish().unwrap();
            // The call's stream: accepted, read by nobody, answered never.
            let (_send, _recv) = connection.accept_bi().await.unwrap();
            std::future::pending::<()>().await;
        });

        let dir = std::env::temp_dir().join(format!("cmns-test-stall-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.key");
        std::fs::write(&key, hex::encode([9u8; 32])).unwrap();
        let conn = Conn {
            ticket,
            key: key.clone(),
            timeout: BUDGET_SECS,
        };
        let started = std::time::Instant::now();
        let err = admin_call(OP_ADMIN_NODE_INFO, json!({}), &conn)
            .await
            .unwrap_err()
            .to_string();
        let elapsed = started.elapsed();
        assert!(
            err.contains("accepted the session but did not answer"),
            "unexpected error: {err}"
        );
        assert!(elapsed >= Duration::from_secs(BUDGET_SECS), "{elapsed:?}");
        assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");

        server.close().await;
        fake.abort();
        std::fs::remove_file(&key).ok();
    }
}
