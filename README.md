# commons-cli

The Commons command line, `cmns`: administer a node, its sidecar and its
capabilities from one binary, with no node source and no data directory
requirement beyond the one being administered.

Status: **pre-release**. The binary exists, its boundary is under test, and
its command set is being built out. The plan behind it is
`docs/architecture/cli.md` in the Commons coordination repository.

## What it is

- One binary per platform, released on its own cycle, stating the node
  versions it works with.
- It reaches a node only over the interfaces the node publishes: the remote
  admin interface over iroh and, for local actions, the local admin socket.
- It does not link the node. It depends on `commons-node-client` for the
  wire types and the client, never on the node's own crate.

## What it is not

- Not the chain or services operator's tool. Relays, lookup, the chain
  broker, registration and publication ceremonies are Dhiway's, with their
  own command line. `cmns identity` carries only the flows a node or App
  owner needs.
- Not the capability author toolkit. Authoring without a node belongs to the
  open SDK's `cap`; `cmns cap` acts on a node, and the toolkit publishes
  through `cmns cap publish`.

## Building

```sh
cargo build --release
```

The toolchain is pinned in `rust-toolchain.toml`. The transport fork
patches in the root `Cargo.toml` are the node's: `origin-protocol` and the
iroh revisions it is built against must match, or the client will not
compile.

## Output

JSON by default, `--human` for one `key: value` line per field. `cmns node
status` prints the node's answer as the node wrote it, so a field's name is
the node's (`version`, not `build`; `startedAt` in Unix seconds, not
milliseconds). Two things a reader should know:

- `relayConnected: null` means the node did not report a relay connection,
  which for an offline node is expected; `cmn` prints `false` for the same
  state.
- A node that reports a version other than 0.9.x is refused, and the message
  says which side is older.

Reaching a node: the ticket carries the addresses the node had when the
ticket was printed — its direct addresses and, when the node was on a relay,
that relay's URL. The caller uses exactly those and no others: a ticket with
a relay names it in the caller's relay map and allowlist, and a ticket with
none keeps the caller direct-only (`RelayMode::Disabled`). A node reachable
only through a relay is reachable while its ticket is fresh; a ticket made
before the node joined a relay, or before it moved to another, names no
relay that can reach it, so print a fresh one.

The signed lookup the node's own profile carries ("node id to its addresses")
is not used: a ticket already names the addresses, and using the lookup would
mean depending on the chain-facing Services stack for that one case.

## Building and dependencies

`commons-node-client` is pinned by revision over `ssh://`, so a builder needs
SSH access to GitHub; the transport forks are fetched over https. The pins in
this repository's `transport-pins.toml` are a copy of the client repository's
canonical file at the pinned revision; `scripts/check-transport-pins.py`
compares them against this repository's `Cargo.lock`, so the copy must be
refreshed in the same commit as a client re-pin.

## Licence

Apache-2.0. See `LICENSE`.
