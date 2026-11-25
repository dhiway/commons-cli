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
use clap::{Parser, Subcommand};
use commons_node_client::{ClientError, ControlClient, OP_ADMIN_NODE_INFO};
use iroh::{endpoint::presets, Endpoint, RelayMode, SecretKey};
use iroh_tickets::endpoint::EndpointTicket;
use serde_json::{json, Value};

/// The node versions this build was written against. Stated on `version`, and
/// enforced on every answer that carries a node `version` (see
/// [`ensure_compatible`]): a different minor version is refused, not guessed at.
const COMPATIBLE_NODE: &str = "node 0.9.x (control/1, admin over iroh)";
/// The client revision this build carries; recorded so a report can name it.
const CLIENT_REV: &str = "b7e5d82";
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
    /// A node: its health and what it reports about itself.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// Ask a node for its status over iroh, named by its ticket.
    Status {
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
    },
}

fn main() -> Result<()> {
    Cli::parse().run()
}

impl Cli {
    fn run(self) -> Result<()> {
        match self.command {
            Command::Version => {
                let v = version_report();
                print_json(&v, self.human)?;
            }
            Command::Node { command } => match command {
                NodeCommand::Status {
                    ticket,
                    key,
                    timeout,
                } => {
                    let runtime = tokio::runtime::Runtime::new().context("starting tokio")?;
                    let answer = runtime.block_on(node_status(&ticket, &key, timeout))?;
                    print_json(&answer, self.human)?;
                }
            },
        }
        Ok(())
    }
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
                    println!("{k}: {}", scalar(v));
                }
            }
            None => println!("{}", scalar(value)),
        }
        return Ok(());
    }
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
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

async fn node_status(ticket: &str, key_path: &PathBuf, timeout_secs: u64) -> Result<Value> {
    let ticket = EndpointTicket::from_str(ticket.trim()).context(
        "parsing the ticket: pass the ticket `cmn info --ticket` prints, not the one `init` prints",
    )?;
    let addr = ticket.endpoint_addr().clone();
    let key = read_key(key_path)?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key.clone())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .context("binding the caller's endpoint")?;
    let budget = Duration::from_secs(timeout_secs);
    let started = std::time::Instant::now();

    let client = match tokio::time::timeout(
        budget,
        ControlClient::connect(&endpoint, addr.clone(), &key, &[OP_ADMIN_NODE_INFO]),
    )
    .await
    {
        Err(_) => {
            endpoint.close().await;
            bail!(
                "the node did not answer within {timeout_secs}s (ticket names {})",
                addr.id
            );
        }
        Ok(Ok(client)) => client,
        Ok(Err(ClientError::Refused { code, payload, .. })) => {
            endpoint.close().await;
            bail!("the node refused this key ({code}): {payload}. The node's operator enrols a key with `cmn admins add <endpoint-id>`.");
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
    let answer = match tokio::time::timeout(left, client.call(OP_ADMIN_NODE_INFO, &json!({}), None))
        .await
    {
        Err(_) => {
            client.close();
            endpoint.close().await;
            bail!(
                "the node accepted the session but did not answer within {timeout_secs}s (ticket names {})",
                addr.id
            );
        }
        Ok(answer) => answer,
    };
    client.close();
    endpoint.close().await;

    match answer {
        Ok(value) => {
            ensure_compatible(&value, &addr.id.to_string())?;
            Ok(value)
        }
        Err(ClientError::Refused { code, payload, .. }) => {
            bail!("the node refused the call ({code}): {payload}")
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

    #[test]
    fn version_reports_the_cli_and_the_node_it_works_with() {
        let cli = Cli::try_parse_from(["cmns", "version"]).expect("version parses");
        assert!(matches!(cli.command, Command::Version));
        let v = version_report();
        assert_eq!(v["cmns"], env!("CARGO_PKG_VERSION"));
        assert!(v["compatible"].as_str().unwrap().contains("node 0.9.x"));
        assert_eq!(v["client_rev"], CLIENT_REV);
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
        assert!(err.to_string().contains("0"), "{err}");
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
        assert!(err.contains("cmns 0.1.0 is older"), "{err}");

        let unreadable = json!({"version": "one"});
        assert!(ensure_compatible(&unreadable, "n1").is_err());

        let silent = json!({"health": "ready"});
        assert!(ensure_compatible(&silent, "n1").is_ok());
    }

    #[tokio::test]
    async fn a_ticket_that_is_not_a_ticket_is_refused_by_name() {
        let dir = std::env::temp_dir().join(format!("cmns-test-ticket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("k.key");
        std::fs::write(&key, hex::encode([7u8; 32])).unwrap();
        let err = node_status("not-a-ticket", &key, 1).await.unwrap_err();
        assert!(
            err.to_string().contains("ticket"),
            "unexpected error: {err}"
        );
        std::fs::remove_file(&key).ok();
    }
}
