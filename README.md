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
patches in the root `Cargo.toml` are the node's: the iroh and noq revisions
the client and the profile are built against must match, or the graph will
not compile. The build needs the stock toolchain; the machine's
`~/.cargo/bin/cargo` has been a third-party fork that ignores target
directories.

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

Every value `cmns` prints that came from a node is escaped before it reaches a
terminal or a JSON document. The rule is by Unicode category, not a list: a
character is escaped when it is a control (Cc), a format character (Cf), a line
or paragraph separator (Zl, Zp), or a default-ignorable code point. That covers
C0 and C1 controls, DEL, the bidi overrides and isolates, zero-width marks,
U+2028 and U+2029, variation selectors and the tag characters. The `--human`
output writes them as Rust escapes (`\u{1b}`, `\r`, `\u{202e}`), so a node's
title or refusal cannot recolour, rewrite, reorder, hide or split a line, and
the same applies to error messages. The JSON writes them as `\uXXXX`, with a
UTF-16 surrogate pair above U+FFFF, so it is safe to `cat`. The JSON still
decodes to exactly the node's strings; only the encoded bytes for those
characters differ from the node's. That is a deliberate departure from
byte-identical passthrough. A new command that prints a node's value goes
through `escape` (human) or `encode_json` (JSON) in `crates/cmns/src/main.rs`.

Reaching a node: a Commons program builds its endpoint from the Commons
network profile, not from the ticket (spec node-access 8.1, architecture
principle 1). The profile comes from the client repository
(`commons_node_client::profile`, feature `commons-profile`), which compiles
the same commons-services revision the node pins: the Commons relay pair, its
allowlist, a DNS resolver and the signed lookups. The ticket names which node
to reach; it never chooses the network, and no relay outside the profile is
contacted. The helper is deliberately not assembled here — a caller that
builds its own relay list can drift from the network the node is on, and the
profile is the one place that composition is tested.

The consequence to know: a node must be on the Commons network to be
reachable this way. A throwaway node on loopback with no relay is reached by
its direct address through the same profile, but a node on some other relay
is not, and a ticket made before the node joined a relay names no address
that can reach it — print a fresh one.

## Building and dependencies

`commons-node-client` is pinned by revision over `ssh://`, so a builder needs
SSH access to GitHub; the transport forks are fetched over https. The pins in
this repository's `transport-pins.toml` are a copy of the client repository's
canonical file at the pinned revision; `scripts/check-transport-pins.py`
compares them against this repository's `Cargo.lock`, so the copy must be
refreshed in the same commit as a client re-pin.

## Licence

Apache-2.0. See `LICENSE`.
