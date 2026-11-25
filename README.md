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
- A node that reports a version other than 0.9.x is refused, not guessed at.

## Licence

Apache-2.0. See `LICENSE`.
