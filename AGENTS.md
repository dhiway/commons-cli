# commons-cli — working notes for agents

The command line's plan is `docs/architecture/cli.md` in the sibling
coordination repository; it is the authority for scope. This repository is
its implementation.

## The boundary rule

The CLI never links `commons-node`, directly or through
`commons-node-rpc`. It uses `commons-node-client` (wire types and client) and
builds its own iroh endpoint from a ticket. A change that would need a node
type or a node helper function is a signal that the interface is missing, not
a reason to add the dependency.

## What it may depend on

- `commons-node-client` at a pinned revision, and `origin-protocol` as the
  client requires.
- The transport patches in the root `Cargo.toml` are the node's and must
  match the client's revision, or the client does not compile.

## Scope

Node, sidecar, capability, api, mcp and dataset administration, plus the
identity flows a node or App owner needs. Nothing that administers the chain
or the shared services layer.

## Gates before a head is reported

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Release artefacts are release-profile builds, never debug, when a version is
published.

## Tracking

Tickets, statuses and pull request rules: `~/.commons-hq/tracker.md` (https://github.com/dhiway/commons-hq).
Skills are in `commons-hq/skills`; run `ask-commons` to pick one.
