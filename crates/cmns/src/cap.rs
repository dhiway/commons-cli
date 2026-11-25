//! `cmns cap list|show`: the node's capabilities, read over its private local
//! admin socket.
//!
//! The node answers these from its own methods (`plugin_list`, `plugin_show`,
//! `dataset_list`, `dataset_show`) on `<data-dir>/admin/admin.sock`, which only
//! the node's own user may open. The only way in is
//! `commons_node_client::local::local_admin_call`; this module adds no method
//! and reads no key.
//!
//! Every call passes its parameters as a one-element array, because the
//! node's methods read `params.one()` and refuse a bare object.

use std::{
    future::Future,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde_json::{json, Map, Value};

/// The node's own default data directory (`commons-node`,
/// `crates/node/src/config.rs`, `default_data_dir`).
pub const DEFAULT_DATA_DIR: &str = "./data";

/// The node's refusal when `plugin_show` names a store that is not one of its
/// plugin documents (`commons-node` `RpcError::NotPluginDocument`). The local
/// client returns a refusal as text only, so the fallback to `dataset_show`
/// is keyed on this message.
const NOT_PLUGIN_DOCUMENT: &str = "not a plugin document";

#[derive(Debug, Subcommand)]
pub enum CapCommand {
    /// The node's plugin documents and one page of its datasets.
    List {
        /// Continue the datasets after the cursor a previous page returned.
        #[arg(long)]
        cursor: Option<String>,
    },
    /// One plugin document or dataset, by namespace.
    Show {
        /// The namespace, as `cap list` prints it.
        namespace: String,
    },
}

/// Where the node's local admin socket lives under a data directory.
pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("admin").join("admin.sock")
}

/// Refuse before calling when the data directory holds no admin socket, naming
/// the path looked in and the flag that changes it.
pub fn require_socket(data_dir: &Path) -> Result<()> {
    let socket = socket_path(data_dir);
    if std::fs::symlink_metadata(&socket).is_err() {
        bail!(
            "no node admin socket at {}: is a node running with this data directory? \
             Pass the node's data directory with --data-dir <dir> (default {DEFAULT_DATA_DIR}).",
            socket.display()
        );
    }
    Ok(())
}

/// Runs one `cap` command against the node under `data_dir`.
pub fn run(data_dir: &Path, command: CapCommand, human: bool) -> Result<()> {
    require_socket(data_dir)?;
    let runtime = tokio::runtime::Runtime::new().context("starting tokio")?;
    let caller = |method: &'static str, params: Value| {
        let data_dir = data_dir.to_path_buf();
        async move {
            commons_node_client::local::local_admin_call(&data_dir, method, params)
                .await
                .with_context(|| format!("{method} on {}", socket_path(&data_dir).display()))
        }
    };
    match command {
        CapCommand::List { cursor } => {
            let answer = runtime.block_on(list(caller, cursor))?;
            if human {
                print_list(&answer);
            } else {
                println!("{}", serde_json::to_string_pretty(&answer)?);
            }
        }
        CapCommand::Show { namespace } => {
            let (kind, answer) = runtime.block_on(show(caller, &namespace))?;
            if human {
                print_shown(kind, &answer);
            } else {
                println!("{}", serde_json::to_string_pretty(&answer)?);
            }
        }
    }
    Ok(())
}

/// `plugin_list` and one page of `dataset_list`, their fields side by side
/// unchanged: `plugins` from the first, `datasets` and `cursor` from the second.
pub async fn list<F, Fut>(call: F, cursor: Option<String>) -> Result<Value>
where
    F: Fn(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let plugins = call("plugin_list", json!([{}])).await?;
    let page = match cursor {
        Some(cursor) => json!([{ "cursor": cursor }]),
        None => json!([{}]),
    };
    let datasets = call("dataset_list", page).await?;
    let mut merged = Map::new();
    for answer in [plugins, datasets] {
        match answer {
            Value::Object(fields) => merged.extend(fields),
            other => bail!("the node answered a list with {other}, not an object"),
        }
    }
    Ok(Value::Object(merged))
}

/// What `show` found the namespace to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Plugin,
    Dataset,
}

/// `plugin_show`, and `dataset_show` when the node says the namespace is not
/// one of its plugin documents. Any other refusal from `plugin_show` (a
/// namespace that does not parse, say) is the answer.
pub async fn show<F, Fut>(call: F, namespace: &str) -> Result<(Kind, Value)>
where
    F: Fn(&'static str, Value) -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    let params = json!([{ "namespace": namespace }]);
    let plugin_refusal = match call("plugin_show", params.clone()).await {
        Ok(answer) => return Ok((Kind::Plugin, answer)),
        Err(err) if format!("{err:#}").contains(NOT_PLUGIN_DOCUMENT) => err,
        Err(err) => return Err(err),
    };
    match call("dataset_show", params).await {
        Ok(answer) => Ok((Kind::Dataset, answer)),
        Err(dataset_refusal) => bail!(
            "{namespace} is neither a plugin document nor a dataset of this node. \
             The node said: {plugin_refusal:#}; {dataset_refusal:#}"
        ),
    }
}

fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
}

fn print_list(answer: &Value) {
    let plugins = answer["plugins"].as_array().cloned().unwrap_or_default();
    println!("plugin documents: {}", plugins.len());
    for plugin in &plugins {
        println!(
            "  {}  {}  current {}",
            text(&plugin["namespace"]),
            text(&plugin["title"]),
            text(&plugin["current"])
        );
    }
    let datasets = answer["datasets"].as_array().cloned().unwrap_or_default();
    println!("datasets: {}", datasets.len());
    for dataset in &datasets {
        println!(
            "  {}  versioned {}  retired {}",
            text(&dataset["namespace"]),
            text(&dataset["versioned"]),
            text(&dataset["retired"])
        );
    }
    if !answer["cursor"].is_null() {
        println!("more datasets: --cursor {}", text(&answer["cursor"]));
    }
}

fn print_shown(kind: Kind, answer: &Value) {
    println!(
        "kind: {}",
        match kind {
            Kind::Plugin => "plugin document",
            Kind::Dataset => "dataset",
        }
    );
    if let Some(fields) = answer.as_object() {
        for (k, v) in fields {
            println!("{k}: {}", text(v));
        }
    } else {
        println!("{}", text(answer));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[tokio::test]
    async fn list_sends_one_element_arrays_and_keeps_both_answers() {
        let calls: Mutex<Vec<(String, Value)>> = Mutex::new(Vec::new());
        let call = |method: &'static str, params: Value| {
            calls.lock().unwrap().push((method.into(), params));
            let result = match method {
                "plugin_list" => {
                    json!({"plugins": [{"namespace": "p1", "title": "T", "current": null}]})
                }
                "dataset_list" => json!({"datasets": [{"namespace": "d1"}], "cursor": "d1"}),
                other => panic!("unexpected {other}"),
            };
            async move { Ok(result) }
        };
        let merged = list(call, Some("c0".into())).await.unwrap();
        assert_eq!(merged["plugins"][0]["namespace"], "p1");
        assert_eq!(merged["datasets"][0]["namespace"], "d1");
        assert_eq!(merged["cursor"], "d1");
        let calls = calls.into_inner().unwrap();
        assert_eq!(
            calls,
            vec![
                ("plugin_list".into(), json!([{}])),
                ("dataset_list".into(), json!([{"cursor": "c0"}])),
            ]
        );
    }

    #[tokio::test]
    async fn show_falls_back_to_the_dataset_only_on_not_a_plugin_document() {
        let calls: Mutex<Vec<(String, Value)>> = Mutex::new(Vec::new());
        let call = |method: &'static str, params: Value| {
            calls.lock().unwrap().push((method.into(), params));
            let result = match method {
                "plugin_show" => Err(anyhow::anyhow!(
                    "local Admin RPC: not a plugin document of this node"
                )),
                "dataset_show" => {
                    Ok(json!({"namespace": "n", "ingestion": null, "materializers": []}))
                }
                other => panic!("unexpected {other}"),
            };
            async move { result }
        };
        let (kind, shown) = show(call, "n").await.unwrap();
        assert_eq!(kind, Kind::Dataset);
        assert_eq!(shown["materializers"], json!([]));
        let calls = calls.into_inner().unwrap();
        assert_eq!(
            calls,
            vec![
                ("plugin_show".into(), json!([{"namespace": "n"}])),
                ("dataset_show".into(), json!([{"namespace": "n"}])),
            ]
        );
    }

    #[tokio::test]
    async fn show_answers_a_plugin_document_without_asking_for_a_dataset() {
        let call = |method: &'static str, _params: Value| async move {
            assert_eq!(method, "plugin_show", "no second call");
            Ok(json!({"namespace": "p", "current": "1.0.0"}))
        };
        let (kind, shown) = show(call, "p").await.unwrap();
        assert_eq!(kind, Kind::Plugin);
        assert_eq!(shown["current"], "1.0.0");
    }

    #[tokio::test]
    async fn show_reports_both_refusals_when_the_node_holds_neither() {
        let call = |method: &'static str, _params: Value| async move {
            match method {
                "plugin_show" => bail!("local Admin RPC: not a plugin document of this node"),
                _ => bail!("local Admin RPC: not an operator dataset of this node"),
            }
        };
        let err = show(call, "zz").await.unwrap_err().to_string();
        assert!(
            err.contains("zz is neither")
                && err.contains("not a plugin document of this node")
                && err.contains("not an operator dataset of this node"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn show_does_not_fall_back_on_another_refusal() {
        let call = |method: &'static str, _params: Value| async move {
            assert_eq!(method, "plugin_show", "no fallback");
            bail!("local Admin RPC: invalid namespace")
        };
        let err = show(call, "bad").await.unwrap_err().to_string();
        assert!(err.contains("invalid namespace"), "{err}");
    }

    #[test]
    fn a_data_directory_without_a_socket_is_refused_naming_the_path_and_flag() {
        let dir = std::env::temp_dir().join(format!("cmns-cap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = require_socket(&dir).unwrap_err().to_string();
        let expected = socket_path(&dir).display().to_string();
        assert!(
            err.contains(&expected) && err.contains("--data-dir"),
            "{err}"
        );
        std::fs::remove_dir(&dir).ok();
    }
}
