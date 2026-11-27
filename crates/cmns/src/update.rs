//! `cmns update check|apply` and `cmns node upgrade --dry-run`: this machine's
//! `cmns` (and, when named, its node) against a channel's signed release
//! manifest.
//!
//! Every check of a manifest and of a downloaded asset is
//! [`commons_release_verify::verify`]: the signature, schema, channel,
//! freshness, sequence, the set rule, and each asset's size and sha256. This
//! module fetches, chooses a set, installs `cmns`, and prints; it names a
//! failed check with [`Check::as_str`](commons_release_verify::Check::as_str)
//! and checks nothing itself. It never stops, replaces, restarts or signals a
//! node: `node upgrade` prints what it would do and is refused outside a dry
//! run until the node install and service work (M5) exist.
//!
//! The install root is `$XDG_DATA_HOME/commons/cmns`, else
//! `~/.local/share/commons/cmns`:
//!
//! - `versions/<version>/cmns`: each installed version; nothing here deletes
//!   one;
//! - `current` -> `versions/<version>`, switched by renaming a new link over
//!   it, so it names the old version or the new one and never neither;
//! - `previous` -> the version `current` named before the last switch;
//! - `state.json`: the highest manifest `sequence` accepted per channel;
//! - `downloads/<version>-<pid>-<nanos>/`: one apply's download, removed when
//!   the apply ends, however it ends.
//!
//! Exit codes: 0 current, applied, or a dry run printed; 10 an update is
//! available; 20 verification failed (the report names the check); 30
//! refused; 1 any other error. Every report goes through the one escaping
//! rule: [`encode_json`] for JSON, [`escape`] (by way of [`crate::scalar`])
//! for `--human`.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, Subcommand};
use commons_node_client::OP_ADMIN_NODE_INFO;
use commons_release_verify::{
    manifest::{Set, CHANNELS},
    verify, Error as VerifyError, Options, PublicKey, TrustedKeys, Verified,
};
use semver::Version;
use serde_json::{json, Map, Value};

use crate::{encode_json, escape, scalar, Conn};

pub const CURRENT: u8 = 0;
pub const AVAILABLE: u8 = 10;
pub const VERIFICATION_FAILED: u8 = 20;
pub const REFUSED: u8 = 30;

/// Where the channels are published: `commons-releases` holds
/// `<channel>/manifest.json` and its `.sig` on its `main` branch.
pub const DEFAULT_SOURCE: &str = "https://raw.githubusercontent.com/dhiway/commons-releases/main";
/// The target triple this binary was built for; its release asset is the
/// one keyed by it.
pub const TARGET: &str = env!("CMNS_TARGET");

/// The keys this build trusts, per channel: `(channel, key in use, next
/// key)`, each an OpenSSH public key as `keys/<channel>-<n>.pub` publishes
/// it. Empty because commons-releases has published no key yet
/// (`keys/README.md` at b9e9554); until one is compiled in here, a channel
/// is read only with `--trust-key`.
const COMPILED_KEYS: &[(&str, &str, Option<&str>)] = &[];

/// A manifest and its signature are small text files; these bounds stop a
/// server that never ends its answer, and are far above any real one.
const MANIFEST_MAX: u64 = 4 << 20;
const SIGNATURE_MAX: u64 = 64 << 10;

#[derive(Debug, Args)]
pub struct Channel {
    /// The release channel.
    #[arg(long, default_value = "beta", value_parser = clap::builder::PossibleValuesParser::new(CHANNELS))]
    pub channel: String,
    /// Where the channel is published: an https:// base URL under which
    /// `<channel>/manifest.json` and `manifest.json.sig` are found, or a
    /// directory laid out the same way with the assets beside the manifest,
    /// for a machine with no network.
    #[arg(long, value_name = "URL|DIR", default_value = DEFAULT_SOURCE)]
    pub source: String,
    /// An OpenSSH public key file to trust for the channel instead of the
    /// keys this build carries; give it twice during a key rotation, the key
    /// in use first.
    #[arg(long, value_name = "FILE")]
    pub trust_key: Vec<PathBuf>,
}

/// The node on this machine, named the way `cmns node status` names one.
#[derive(Debug, Args)]
pub struct LocalNode {
    /// The node's ticket, as `cmn info --ticket` prints it; its version is
    /// read over its admin interface. Without it no node is compared.
    #[arg(long, requires = "key")]
    pub ticket: Option<String>,
    /// The caller's admin key for --ticket: 32 bytes, hex.
    #[arg(long, requires = "ticket")]
    pub key: Option<PathBuf>,
    /// Seconds to wait for the node.
    #[arg(long, default_value_t = crate::DEFAULT_TIMEOUT_SECS, value_parser = clap::value_parser!(u64).range(1..))]
    pub timeout: u64,
}

#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    /// The installed and available versions of cmns and, with --ticket, of
    /// the node, and whether they move as one set. Exit 0 current, 10 an
    /// update is available, 20 verification failed, 30 refused.
    Check {
        #[command(flatten)]
        channel: Channel,
        #[command(flatten)]
        node: LocalNode,
        /// Print JSON, which is the default; refused with --human.
        #[arg(long)]
        json: bool,
    },
    /// Update cmns itself: download the newest set's cmns into a versioned
    /// folder, verify it against the signed manifest, and switch `current`
    /// to it, keeping the previous version. Refused (30) when the set
    /// changes the node's format or the node would move with it: that is
    /// `cmns node upgrade`.
    Apply {
        #[command(flatten)]
        channel: Channel,
        #[command(flatten)]
        node: LocalNode,
    },
}

#[derive(Debug, Args)]
pub struct UpgradeArgs {
    /// Print the set, the compatibility verdict and each step it would take,
    /// and change nothing. Required: an upgrade that acts on the node is
    /// refused until the node install and service work (M5) exist.
    #[arg(long)]
    pub dry_run: bool,
    #[command(flatten)]
    pub channel: Channel,
    #[command(flatten)]
    pub node: LocalNode,
}

/// What a command decided: its exit code and the report printed for it.
#[derive(Debug)]
pub struct Outcome {
    pub code: u8,
    pub report: Value,
}

impl Outcome {
    fn refused(reason: String) -> Self {
        Outcome {
            code: REFUSED,
            report: json!({ "verdict": "refused", "reason": reason }),
        }
    }
}

/// Prints a report, JSON or `--human`, and answers its exit code.
pub fn print(outcome: &Outcome, human: bool) -> Result<u8> {
    if human {
        print!("{}", render_human(&outcome.report));
    } else {
        println!("{}", encode_json(&outcome.report)?);
    }
    Ok(outcome.code)
}

/// One `path: value` line per scalar of the report, nested objects as
/// `a.b` and arrays as `a.0`; keys and values each go through [`escape`].
fn render_human(report: &Value) -> String {
    fn walk(path: &str, value: &Value, out: &mut String) {
        let join = |key: &str| {
            if path.is_empty() {
                key.to_owned()
            } else {
                format!("{path}.{key}")
            }
        };
        match value {
            Value::Object(map) => map.iter().for_each(|(k, v)| walk(&join(k), v, out)),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .for_each(|(i, v)| walk(&join(&i.to_string()), v, out)),
            scalar_value => {
                out.push_str(&escape(path));
                out.push_str(": ");
                out.push_str(&scalar(scalar_value));
                out.push('\n');
            }
        }
    }
    let mut out = String::new();
    walk("", report, &mut out);
    out
}

/// `cmns update check|apply`.
pub fn update(command: UpdateCommand, human: bool) -> Result<Outcome> {
    match command {
        UpdateCommand::Check {
            channel,
            node,
            json,
        } => {
            ensure!(
                !(json && human),
                "--json and --human ask for two outputs; give one"
            );
            check(&channel, &node)
        }
        UpdateCommand::Apply { channel, node } => apply(&channel, &node),
    }
}

/// Where a channel's manifest and assets come from.
enum Source {
    Https(String),
    Dir(PathBuf),
}

impl Source {
    fn parse(text: &str) -> Result<Self> {
        if text.starts_with("https://") {
            return Ok(Source::Https(text.trim_end_matches('/').to_owned()));
        }
        ensure!(
            !text.contains("://"),
            "--source {text} is neither an https:// URL nor a directory"
        );
        Ok(Source::Dir(PathBuf::from(text)))
    }
}

/// A channel's manifest as fetched, before or after verification.
struct Fetched {
    bytes: Vec<u8>,
    signature: String,
}

/// Everything one command needs to read a channel.
struct Reader {
    channel: String,
    source: Source,
    keys: TrustedKeys,
    root: PathBuf,
    runtime: tokio::runtime::Runtime,
}

impl Reader {
    /// `None` when this build trusts no key for the channel and none was
    /// given: the command is refused before anything is fetched.
    fn new(channel: &Channel) -> Result<Option<Self>> {
        let source = Source::parse(&channel.source)?;
        let Some(keys) = trusted_keys(channel)? else {
            return Ok(None);
        };
        Ok(Some(Reader {
            channel: channel.channel.clone(),
            source,
            keys,
            root: install_root()?,
            runtime: tokio::runtime::Runtime::new().context("starting tokio")?,
        }))
    }

    fn fetch(&self) -> Result<Fetched> {
        let channel = &self.channel;
        match &self.source {
            Source::Dir(dir) => {
                let path = dir.join(channel).join("manifest.json");
                let bytes =
                    fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                let sig = dir.join(channel).join("manifest.json.sig");
                let signature = fs::read_to_string(&sig)
                    .with_context(|| format!("reading {}", sig.display()))?;
                Ok(Fetched { bytes, signature })
            }
            Source::Https(base) => {
                let client = http_client()?;
                let url = format!("{base}/{channel}/manifest.json");
                let bytes = self.runtime.block_on(get(&client, &url, MANIFEST_MAX))?;
                let sig = format!("{url}.sig");
                let signature = self.runtime.block_on(get(&client, &sig, SIGNATURE_MAX))?;
                let signature =
                    String::from_utf8(signature).with_context(|| format!("{sig} is not text"))?;
                Ok(Fetched { bytes, signature })
            }
        }
    }

    /// Runs every check through the library. `Ok(Err(..))` is a failed
    /// check, reported with exit 20; `Err` is a check that could not run.
    fn verify(
        &self,
        fetched: &Fetched,
        assets_dir: Option<&Path>,
    ) -> Result<std::result::Result<Verified, Outcome>> {
        let opts = Options {
            keys: &self.keys,
            now: time::OffsetDateTime::now_utc(),
            channel: Some(&self.channel),
            last_sequence: last_sequence(&self.root, &self.channel)?,
            assets_dir,
        };
        match verify(&fetched.bytes, &fetched.signature, &opts) {
            Ok(verified) => Ok(Ok(verified)),
            Err(VerifyError::Failed { check, detail }) => Ok(Err(Outcome {
                code: VERIFICATION_FAILED,
                report: json!({
                    "channel": self.channel,
                    "verdict": "verification-failed",
                    "check": check.as_str(),
                    "detail": detail,
                    "message": format!(
                        "the {} check failed; nothing was installed or switched",
                        check.as_str()
                    ),
                }),
            })),
            Err(VerifyError::Io(detail)) => Err(anyhow!(detail)),
        }
    }

    /// Copies the asset into `dest`, at most one byte more than the
    /// manifest's size, so a longer file fails the library's size check
    /// without being read to its end.
    fn fetch_asset(
        &self,
        asset: &commons_release_verify::manifest::Asset,
        dest: &Path,
    ) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dest)
            .with_context(|| format!("creating {}", dest.display()))?;
        match &self.source {
            Source::Dir(dir) => {
                let path = dir.join(&self.channel).join(asset.file_name());
                let source =
                    fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
                io::copy(
                    &mut io::Read::take(source, asset.size.saturating_add(1)),
                    &mut file,
                )
                .with_context(|| format!("copying {}", path.display()))?;
            }
            Source::Https(_) => {
                let client = http_client()?;
                self.runtime
                    .block_on(download(&client, &asset.url, asset.size, &mut file))?;
            }
        }
        file.sync_all()
            .with_context(|| format!("writing {}", dest.display()))
    }

    /// The node's version over its admin interface, when one is named.
    fn node_version(&self, node: &LocalNode) -> Result<Option<String>> {
        let (Some(ticket), Some(key)) = (&node.ticket, &node.key) else {
            return Ok(None);
        };
        let conn = Conn {
            ticket: ticket.clone(),
            key: key.clone(),
            timeout: node.timeout,
        };
        let (answer, _) =
            self.runtime
                .block_on(crate::admin_exchange(OP_ADMIN_NODE_INFO, json!({}), &conn))?;
        let version = answer
            .get("version")
            .and_then(Value::as_str)
            .context("the node's answer to admin.node-info carries no version")?;
        Ok(Some(version.to_owned()))
    }
}

fn trusted_keys(channel: &Channel) -> Result<Option<TrustedKeys>> {
    let read = |path: &PathBuf| {
        PublicKey::read_file(path).map_err(|e| anyhow!("--trust-key {}: {e}", path.display()))
    };
    match channel.trust_key.as_slice() {
        [] => {}
        [current] => {
            return Ok(Some(TrustedKeys {
                current: read(current)?,
                next: None,
            }))
        }
        [current, next] => {
            return Ok(Some(TrustedKeys {
                current: read(current)?,
                next: Some(read(next)?),
            }))
        }
        _ => bail!("give --trust-key once, or twice during a key rotation"),
    }
    COMPILED_KEYS
        .iter()
        .find(|(name, ..)| *name == channel.channel)
        .map(|(_, current, next)| {
            Ok(TrustedKeys {
                current: PublicKey::from_key_text(current).map_err(anyhow::Error::msg)?,
                next: next
                    .map(PublicKey::from_key_text)
                    .transpose()
                    .map_err(anyhow::Error::msg)?,
            })
        })
        .transpose()
}

fn no_key(channel: &str) -> Outcome {
    Outcome::refused(format!(
        "this cmns carries no signing key for the {channel} channel yet, so it cannot verify \
         that channel's manifest; give the channel's public key with --trust-key FILE"
    ))
}

/// `$XDG_DATA_HOME/commons/cmns`, else `~/.local/share/commons/cmns`.
fn install_root() -> Result<PathBuf> {
    let base =
        match std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
        {
            Some(dir) => dir,
            None => PathBuf::from(std::env::var_os("HOME").context(
                "HOME is not set; set XDG_DATA_HOME to say where cmns keeps its versions",
            )?)
            .join(".local")
            .join("share"),
        };
    Ok(base.join("commons").join("cmns"))
}

/// The highest sequence accepted on `channel`, from `state.json`. A state
/// file that cannot be read is an error, not a fresh start: starting over
/// would accept an older manifest.
fn last_sequence(root: &Path, channel: &str) -> Result<Option<u64>> {
    let Some(state) = read_state(root)? else {
        return Ok(None);
    };
    match state
        .get("last_sequence")
        .and_then(|seen| seen.get(channel))
    {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).with_context(|| {
            format!(
                "{}: last_sequence.{channel} is not a whole number",
                root.join("state.json").display()
            )
        }),
    }
}

fn read_state(root: &Path) -> Result<Option<Value>> {
    let path = root.join("state.json");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let state: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not JSON; it records the last manifest sequence accepted, so cmns does not replace it",
            path.display()
        )
    })?;
    Ok(Some(state))
}

/// Records `sequence` as the highest seen on `channel`, by writing a new
/// file and renaming it over the old one.
fn record_sequence(root: &Path, channel: &str, sequence: u64) -> Result<()> {
    let mut state = read_state(root)?.unwrap_or_else(|| json!({}));
    let seen = state
        .as_object_mut()
        .context("state.json is not a JSON object")?
        .entry("last_sequence")
        .or_insert_with(|| json!({}));
    let seen = seen
        .as_object_mut()
        .context("state.json: last_sequence is not a JSON object")?;
    let highest = seen
        .get(channel)
        .and_then(Value::as_u64)
        .map_or(sequence, |old| old.max(sequence));
    seen.insert(channel.to_owned(), json!(highest));
    fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let path = root.join("state.json");
    let tmp = root.join(format!(".state.json.{}", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))
}

fn http_client() -> Result<reqwest::Client> {
    // reqwest is built without a crypto provider, as iroh builds it; ring is
    // the one rustls carries in this graph. An error means one is installed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .user_agent(concat!("cmns/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building the HTTPS client")
}

async fn get(client: &reqwest::Client, url: &str, max: u64) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let read = download(client, url, max, &mut body).await?;
    ensure!(read <= max, "{url} is larger than {max} bytes");
    Ok(body)
}

/// Writes at most `max + 1` bytes of `url` to `sink` and answers how many it
/// wrote: one more than `max` says the body is longer than it should be,
/// without reading the rest.
async fn download(
    client: &reqwest::Client,
    url: &str,
    max: u64,
    sink: &mut impl io::Write,
) -> Result<u64> {
    let mut response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = response.status();
    ensure!(status.is_success(), "fetching {url}: HTTP {status}");
    let limit = max.saturating_add(1);
    let mut written = 0u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("reading {url}"))?
    {
        let room = usize::try_from(limit - written).unwrap_or(usize::MAX);
        let take = chunk.len().min(room);
        sink.write_all(&chunk[..take])
            .with_context(|| format!("writing {url}"))?;
        written += take as u64;
        if written >= limit {
            break;
        }
    }
    Ok(written)
}

fn parse_version(text: &str) -> Result<Version> {
    Version::parse(text).with_context(|| format!("version {text} is not a semantic version"))
}

/// The newest set, by version, among those `has_build` accepts.
fn newest(sets: &[Set], has_build: impl Fn(&Set) -> bool) -> Result<Option<(&Set, Version)>> {
    let mut best: Option<(&Set, Version)> = None;
    for set in sets.iter().filter(|set| has_build(set)) {
        let version = parse_version(&set.components.cmns.version)?;
        if best.as_ref().is_none_or(|(_, b)| version > *b) {
            best = Some((set, version));
        }
    }
    Ok(best)
}

fn has_cmns(set: &Set) -> bool {
    set.components.cmns.assets.contains_key(TARGET)
}

fn has_node(set: &Set) -> bool {
    set.components.node.assets.contains_key(TARGET)
}

/// Whether the node moves with `cmns` to a set at `target`: when the set
/// changes the node's on-disk format, or when the node is known and is not
/// at that version. `cmns` carries the node's version, so the two move as
/// one set or not at all.
fn node_moves(set: &Set, node: Option<&Version>, target: &Version) -> bool {
    set.format_change || node.is_some_and(|node| node != target)
}

/// The cmns version this machine has: the one `current` names when cmns
/// manages its own install, else this binary's.
fn installed_cmns(root: &Path) -> String {
    current_version(root).unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned())
}

fn current_version(root: &Path) -> Option<String> {
    let target = fs::read_link(root.join("current")).ok()?;
    Some(target.file_name()?.to_str()?.to_owned())
}

fn set_report(set: &Set) -> Value {
    json!({
        "id": set.id,
        "version": set.components.cmns.version,
        "format_change": set.format_change,
        "requires_data_dir": set.requires_data_dir,
        "notes_url": set.notes_url,
    })
}

fn header(reader: &Reader, verified: &Verified) -> Map<String, Value> {
    let mut report = Map::new();
    report.insert("channel".into(), json!(reader.channel));
    report.insert("sequence".into(), json!(verified.manifest.sequence));
    report.insert("signed_by".into(), json!(verified.signed_by));
    report.insert("target".into(), json!(TARGET));
    report
}

/// A shell-quoted path for a command printed for the operator to run.
fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
}

fn check(channel: &Channel, node: &LocalNode) -> Result<Outcome> {
    let Some(reader) = Reader::new(channel)? else {
        return Ok(no_key(&channel.channel));
    };
    let fetched = reader.fetch()?;
    let verified = match reader.verify(&fetched, None)? {
        Ok(verified) => verified,
        Err(failed) => return Ok(failed),
    };
    record_sequence(&reader.root, &reader.channel, verified.manifest.sequence)?;
    let node_installed = reader.node_version(node)?;
    let installed = installed_cmns(&reader.root);

    let mut report = header(&reader, &verified);
    let Some((set, available)) = newest(&verified.manifest.sets, has_cmns)? else {
        report.insert("verdict".into(), json!("no-build"));
        report.insert(
            "message".into(),
            json!(format!("the channel has no cmns build for {TARGET}")),
        );
        return Ok(Outcome {
            code: CURRENT,
            report: Value::Object(report),
        });
    };
    let cmns_version = parse_version(&installed)?;
    let node_version = node_installed.as_deref().map(parse_version).transpose()?;
    let cmns_behind = cmns_version < available;
    let node_behind = node_version.as_ref().is_some_and(|n| *n < available);
    let moves = node_moves(set, node_version.as_ref(), &available);

    report.insert("set".into(), set_report(set));
    report.insert(
        "cmns".into(),
        json!({
            "installed": installed,
            "running": env!("CARGO_PKG_VERSION"),
            "available": available.to_string(),
        }),
    );
    report.insert(
        "node".into(),
        json!({ "installed": node_installed, "available": available.to_string() }),
    );
    report.insert("moves_as_one_set".into(), json!(moves));
    let (code, verdict, message) = if !cmns_behind && !node_behind {
        (CURRENT, "current", format!("cmns {installed} is current"))
    } else if moves {
        (
            AVAILABLE,
            "update-available",
            format!(
                "set {available} moves the node and cmns together; `cmns node upgrade --dry-run` \
                 shows the steps"
            ),
        )
    } else {
        (
            AVAILABLE,
            "update-available",
            format!("cmns {installed} -> {available}: run `cmns update apply`"),
        )
    };
    report.insert("verdict".into(), json!(verdict));
    report.insert("message".into(), json!(message));
    Ok(Outcome {
        code,
        report: Value::Object(report),
    })
}

fn apply(channel: &Channel, node: &LocalNode) -> Result<Outcome> {
    let Some(reader) = Reader::new(channel)? else {
        return Ok(no_key(&channel.channel));
    };
    let fetched = reader.fetch()?;
    let verified = match reader.verify(&fetched, None)? {
        Ok(verified) => verified,
        Err(failed) => return Ok(failed),
    };
    record_sequence(&reader.root, &reader.channel, verified.manifest.sequence)?;
    let node_installed = reader.node_version(node)?;
    let installed = installed_cmns(&reader.root);

    let mut report = header(&reader, &verified);
    let Some((set, available)) = newest(&verified.manifest.sets, has_cmns)? else {
        return Ok(Outcome::refused(format!(
            "the channel has no cmns build for {TARGET}"
        )));
    };
    report.insert("set".into(), set_report(set));
    if parse_version(&installed)? >= available {
        report.insert("verdict".into(), json!("current"));
        report.insert(
            "message".into(),
            json!(format!(
                "cmns {installed} is current; nothing was downloaded"
            )),
        );
        return Ok(Outcome {
            code: CURRENT,
            report: Value::Object(report),
        });
    }
    let node_version = node_installed.as_deref().map(parse_version).transpose()?;
    if set.format_change {
        return Ok(Outcome::refused(format!(
            "set {available} changes the node's on-disk format, so the node and cmns move \
             together: use `cmns node upgrade` (`--dry-run` shows the steps)"
        )));
    }
    if node_moves(set, node_version.as_ref(), &available) {
        return Ok(Outcome::refused(format!(
            "the node runs {} and set {available} moves it with cmns: use `cmns node upgrade` \
             (`--dry-run` shows the steps)",
            node_installed.unwrap_or_default()
        )));
    }

    let version = available.to_string();
    let downloads = reader.root.join("downloads");
    fs::create_dir_all(&downloads).with_context(|| format!("creating {}", downloads.display()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let staging = downloads.join(format!("{version}-{}-{nanos}", std::process::id()));
    fs::create_dir(&staging).with_context(|| format!("creating {}", staging.display()))?;
    let installed_now = install(&reader, &fetched, set, &version, &staging);
    // This run's own download folder, whatever happened.
    let _ = fs::remove_dir_all(&staging);
    let previous = match installed_now? {
        Ok(previous) => previous,
        Err(failed) => return Ok(failed),
    };

    let current = reader.root.join("current");
    let previous_report = match &previous {
        Some(link) => reader.root.join(link).display().to_string(),
        None => std::env::current_exe()
            .map(|exe| exe.display().to_string())
            .unwrap_or_default(),
    };
    report.insert(
        "cmns".into(),
        json!({ "installed": version, "previous": installed }),
    );
    report.insert("current".into(), json!(current.display().to_string()));
    report.insert("previous".into(), json!(previous_report));
    report.insert("verdict".into(), json!("applied"));
    let kept = match &previous {
        Some(_) => format!("the previous version stays in {previous_report}"),
        None => format!(
            "no earlier version was installed here; the cmns that ran this command stays at \
             {previous_report}"
        ),
    };
    report.insert(
        "message".into(),
        json!(format!(
            "cmns {version} is installed at {}; {kept}. To run it as `cmns`: export PATH={}:\"$PATH\"",
            current.join("cmns").display(),
            shell_quote(&current)
        )),
    );
    Ok(Outcome {
        code: CURRENT,
        report: Value::Object(report),
    })
}

/// Downloads into `staging`, verifies, extracts, and switches `current`.
/// Until the switch nothing outside `staging` changes but the new version's
/// folder; `current` names the old version on every failure. Answers the
/// link `current` held before.
fn install(
    reader: &Reader,
    fetched: &Fetched,
    set: &Set,
    version: &str,
    staging: &Path,
) -> Result<std::result::Result<Option<PathBuf>, Outcome>> {
    let asset = &set.components.cmns.assets[TARGET];
    let archive = staging.join(asset.file_name());
    reader.fetch_asset(asset, &archive)?;
    // The library checks the downloaded file's size and sha256 against the
    // same signed manifest.
    if let Err(failed) = reader.verify(fetched, Some(staging))? {
        return Ok(Err(failed));
    }
    let binary = staging.join("cmns");
    extract(&archive, &format!("cmns-{version}-{TARGET}/cmns"), &binary)?;
    let folder = reader.root.join("versions").join(version);
    fs::create_dir_all(&folder).with_context(|| format!("creating {}", folder.display()))?;
    let dest = folder.join("cmns");
    fs::rename(&binary, &dest).with_context(|| format!("installing {}", dest.display()))?;
    Ok(Ok(switch(&reader.root, version)?))
}

/// Copies the archive's entry `inner`, which must be a regular file, to a
/// new executable file at `dest`. Nothing else is read out of the archive:
/// no other path, directory or link is created, so its contents cannot
/// write anywhere but `dest`.
fn extract(archive: &Path, inner: &str, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("opening {}", archive.display()))?;
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    for entry in tar.entries().context("reading the release archive")? {
        let mut entry = entry.context("reading the release archive")?;
        if entry.path_bytes().as_ref() != inner.as_bytes() {
            continue;
        }
        ensure!(
            entry.header().entry_type() == tar::EntryType::Regular,
            "{inner} in the release archive is not a regular file"
        );
        let mut out = new_executable(dest)?;
        io::copy(&mut entry, &mut out).context("reading the release archive")?;
        out.sync_all()
            .with_context(|| format!("writing {}", dest.display()))?;
        return Ok(());
    }
    bail!("the release archive holds no {inner}")
}

#[cfg(unix)]
fn new_executable(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))
}

#[cfg(not(unix))]
fn new_executable(_: &Path) -> Result<fs::File> {
    bail!("cmns update installs only on Unix")
}

/// Points `current` at `versions/<version>` and `previous` at what
/// `current` named before, each by renaming a new link over the old one.
fn switch(root: &Path, version: &str) -> Result<Option<PathBuf>> {
    let current = root.join("current");
    let before = match fs::read_link(&current) {
        Ok(link) => Some(link),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", current.display())),
    };
    if let Some(before) = &before {
        relink(root, "previous", before)?;
    }
    relink(root, "current", &Path::new("versions").join(version))?;
    Ok(before)
}

#[cfg(unix)]
fn relink(root: &Path, name: &str, target: &Path) -> Result<()> {
    let tmp = root.join(format!(".{name}.{}", std::process::id()));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing {}", tmp.display()))
        }
        _ => {}
    }
    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("linking {}", tmp.display()))?;
    let link = root.join(name);
    fs::rename(&tmp, &link).with_context(|| format!("switching {}", link.display()))
}

#[cfg(not(unix))]
fn relink(_: &Path, _: &str, _: &Path) -> Result<()> {
    bail!("cmns update installs only on Unix")
}

/// `cmns node upgrade`: a dry run that prints the set, the compatibility
/// verdict and each step, and changes nothing, not even the recorded
/// sequence. Without `--dry-run` it is refused before anything is read.
pub fn node_upgrade(args: &UpgradeArgs) -> Result<Outcome> {
    if !args.dry_run {
        return Ok(Outcome::refused(
            "cmns node upgrade acts on a node only once the node install and service work (M5) \
             exist; until then `cmns node upgrade --dry-run` prints the steps and changes nothing"
                .into(),
        ));
    }
    let Some(reader) = Reader::new(&args.channel)? else {
        return Ok(no_key(&args.channel.channel));
    };
    let fetched = reader.fetch()?;
    let verified = match reader.verify(&fetched, None)? {
        Ok(verified) => verified,
        Err(failed) => return Ok(failed),
    };
    let node_installed = reader.node_version(&args.node)?;

    let mut report = header(&reader, &verified);
    report.insert("verdict".into(), json!("dry-run"));
    report.insert("changed".into(), json!("nothing"));
    let Some((set, target)) = newest(&verified.manifest.sets, has_node)? else {
        report.insert("compatibility".into(), json!("no-build"));
        report.insert(
            "message".into(),
            json!(format!("the channel has no node build for {TARGET}")),
        );
        return Ok(Outcome {
            code: CURRENT,
            report: Value::Object(report),
        });
    };
    let asset = &set.components.node.assets[TARGET];
    let node_version = node_installed.as_deref().map(parse_version).transpose()?;
    let from = node_installed
        .clone()
        .unwrap_or_else(|| "the installed version".into());
    report.insert("set".into(), set_report(set));
    report.insert(
        "node".into(),
        json!({
            "installed": node_installed,
            "target": target.to_string(),
            "asset": { "url": asset.url, "sha256": asset.sha256, "size": asset.size },
        }),
    );

    let download = format!(
        "download {} into a new versioned folder and check its size and sha256 against the \
         signed manifest",
        asset.file_name()
    );
    let cmns = format!("update cmns to {target} with `cmns update apply`, the same set");
    let (compatibility, steps): (&str, Vec<String>) = if node_version
        .as_ref()
        .is_some_and(|node| *node >= target)
    {
        ("current", Vec::new())
    } else if set.format_change {
        (
            "format-change",
            vec![
                download,
                "keep the running node and its data directory as they are; nothing is migrated, \
                 downgraded or deleted"
                    .into(),
                format!("install cmn and cmn-http {target} beside {from}, in their own versioned folder"),
                format!(
                    "start node {target} with a new, empty data directory (requires_data_dir: new); \
                     the old data directory stays with {from}"
                ),
                cmns,
            ],
        )
    } else {
        (
            "same-data-directory",
            vec![
                download,
                "confirm a backup of the node's data directory (--backup-confirmed)".into(),
                "stop the node".into(),
                format!(
                    "install cmn and cmn-http {target} into versions/{target} and switch the \
                     current link, keeping {from}"
                ),
                "start the node".into(),
                format!("health check: `cmns node status` answers ready and version {target}"),
                format!("if the health check fails, switch back to {from} and start it again"),
                cmns,
            ],
        )
    };
    report.insert("compatibility".into(), json!(compatibility));
    report.insert("steps".into(), json!(steps));
    let message = match compatibility {
        "current" => format!("the node already runs {from}; nothing to do"),
        _ if node_installed.is_none() => format!(
            "the steps to bring a node to set {target}; give --ticket and --key to compare the \
             node on this machine. Nothing was changed."
        ),
        _ => format!("the steps from {from} to set {target}. Nothing was changed."),
    };
    report.insert("message".into(), json!(message));
    Ok(Outcome {
        code: CURRENT,
        report: Value::Object(report),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use commons_release_verify::manifest::{Asset, Component, Components};
    use std::collections::BTreeMap;

    fn component(version: &str, targets: &[&str]) -> Component {
        Component {
            version: version.into(),
            commit: "1".repeat(40),
            assets: targets
                .iter()
                .map(|t| {
                    (
                        (*t).to_owned(),
                        Asset {
                            url: format!("https://example.invalid/cmns-{version}-{t}.tar.gz"),
                            sha256: "a".repeat(64),
                            size: 1,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            storage_format: None,
            sync_alpn: None,
            notarized: None,
        }
    }

    fn set(version: &str, format_change: bool, targets: &[&str]) -> Set {
        Set {
            id: version.into(),
            format_change,
            requires_data_dir: if format_change { "new" } else { "same" }.into(),
            components: Components {
                cmns: component(version, targets),
                node: component(version, targets),
                app: None,
            },
            notes_url: "https://example.invalid/notes".into(),
            build_profile: commons_release_verify::manifest::RELEASE_PROFILE.into(),
        }
    }

    #[test]
    fn the_newest_set_with_a_build_for_this_target_is_chosen() {
        let sets = vec![
            set("0.9.48", false, &[TARGET]),
            set("0.9.50", false, &["some-other-target"]),
            set("0.9.49", false, &[TARGET]),
            set("0.9.49-rc.1", false, &[TARGET]),
        ];
        let (chosen, version) = newest(&sets, has_cmns).unwrap().unwrap();
        assert_eq!(chosen.id, "0.9.49");
        assert_eq!(version, Version::new(0, 9, 49));
        assert!(newest(&sets[1..2], has_cmns).unwrap().is_none());
    }

    /// The set rule as `apply` applies it: a format change always moves the
    /// node; otherwise the node moves when it is known and at another
    /// version, and an unnamed node is not compared.
    #[test]
    fn the_node_moves_on_a_format_change_or_when_it_is_at_another_version() {
        let target = Version::new(0, 9, 49);
        let plain = set("0.9.49", false, &[TARGET]);
        let format = set("0.9.49", true, &[TARGET]);
        let older = Version::new(0, 9, 48);
        assert!(!node_moves(&plain, None, &target));
        assert!(!node_moves(&plain, Some(&target), &target));
        assert!(node_moves(&plain, Some(&older), &target));
        assert!(node_moves(&format, None, &target));
        assert!(node_moves(&format, Some(&target), &target));
    }

    #[test]
    fn a_suggested_path_is_quoted_for_the_shell() {
        assert_eq!(shell_quote(Path::new("/a b/c")), "'/a b/c'");
        assert_eq!(shell_quote(Path::new("/it's")), r"'/it'\''s'");
    }

    #[test]
    fn the_human_report_escapes_keys_and_values() {
        let report = json!({ "set": { "id": "a\u{1b}[2K\u{202e}b\u{2028}c" }, "steps": ["x"] });
        let text = render_human(&report);
        assert!(
            !text.chars().any(|c| crate::must_escape(c) && c != '\n'),
            "{text:?}"
        );
        assert_eq!(
            text,
            "set.id: a\\u{1b}[2K\\u{202e}b\\u{2028}c\nsteps.0: x\n"
        );
    }

    fn archive(dir: &Path, entries: &[(&str, tar::EntryType, &[u8])]) -> PathBuf {
        let path = dir.join("a.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            fs::File::create(&path).unwrap(),
            flate2::Compression::default(),
        );
        let mut builder = tar::Builder::new(gz);
        for (name, kind, data) in entries {
            let mut header = tar::Header::new_ustar();
            // Written into the header's bytes, as a hostile archive would
            // carry it: `set_path` refuses a `..` name.
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*kind);
            header.set_mode(0o755);
            header.set_size(data.len() as u64);
            if *kind == tar::EntryType::Symlink {
                header.set_link_name("/etc/passwd").unwrap();
            }
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cmns-upd-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn only_the_named_regular_file_is_extracted() {
        let dir = scratch("extract");
        let a = archive(
            &dir,
            &[
                ("../escape", tar::EntryType::Regular, b"no"),
                ("v/BUILD-INFO.json", tar::EntryType::Regular, b"{}"),
                ("v/cmns", tar::EntryType::Regular, b"binary"),
            ],
        );
        let out = dir.join("out");
        extract(&a, "v/cmns", &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"binary");
        assert!(!dir.parent().unwrap().join("escape").exists());
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names.len(),
            2,
            "only the archive and the one file: {names:?}"
        );

        let err = extract(&a, "v/missing", &dir.join("none")).unwrap_err();
        assert!(err.to_string().contains("holds no v/missing"), "{err}");
        assert!(!dir.join("none").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_link_where_the_binary_should_be_is_refused() {
        let dir = scratch("link");
        let a = archive(&dir, &[("v/cmns", tar::EntryType::Symlink, b"")]);
        let out = dir.join("out");
        let err = extract(&a, "v/cmns", &out).unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(fs::symlink_metadata(&out).is_err(), "nothing was written");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_switch_keeps_the_previous_version_linked() {
        let root = scratch("switch");
        assert_eq!(switch(&root, "0.9.48").unwrap(), None);
        assert_eq!(
            fs::read_link(root.join("current")).unwrap(),
            Path::new("versions/0.9.48")
        );
        assert!(fs::symlink_metadata(root.join("previous")).is_err());
        assert_eq!(
            switch(&root, "0.9.49").unwrap(),
            Some(PathBuf::from("versions/0.9.48"))
        );
        assert_eq!(
            fs::read_link(root.join("current")).unwrap(),
            Path::new("versions/0.9.49")
        );
        assert_eq!(
            fs::read_link(root.join("previous")).unwrap(),
            Path::new("versions/0.9.48")
        );
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_recorded_sequence_only_rises_and_a_broken_state_is_an_error() {
        let root = scratch("state");
        assert_eq!(last_sequence(&root, "beta").unwrap(), None);
        record_sequence(&root, "beta", 8).unwrap();
        record_sequence(&root, "beta", 7).unwrap();
        record_sequence(&root, "dev", 3).unwrap();
        assert_eq!(last_sequence(&root, "beta").unwrap(), Some(8));
        assert_eq!(last_sequence(&root, "dev").unwrap(), Some(3));
        fs::write(root.join("state.json"), "not json").unwrap();
        assert!(last_sequence(&root, "beta").is_err());
        fs::remove_dir_all(&root).ok();
    }
}
