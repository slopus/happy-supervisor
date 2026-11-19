# Working on happy-supervisor

## The contract

`docs/` is the contract. `api.md` is the wire, `policy.md` is the sandbox, `node-info.md` is the
machine description, and `architecture.md` is the module map. A behavior change updates the doc
in the same commit. If code and doc disagree, one of them is a bug. Decide which, and fix it in
that commit.

`src/protocol.rs` models every wire shape. Its tests round-trip each api.md and node-info.md
example as literal JSON, and `api_md_kinds_are_all_modeled` fails when api.md gains a command
heading that `CommandKind` lacks, or an `(event)` heading that `Event` lacks.

`src/link.rs` holds every link-protocol rule (queue, acks, dedup, resume, lost sessions) as a
sans-IO state machine. Transport code only moves frames and calls it. Do not reimplement a
protocol rule in `client` or `testing`.

## Module ownership

| Module | Owner |
|---|---|
| `protocol`, `wire`, `ws`, `error`, `policy`, `helper`, `link`, `dispatch`, `serve`, `controller`, `testkit`, `lib.rs`, `sandbox/mod.rs`, `Cargo.toml`, `Cargo.lock`, CI | scaffold |
| `state`, `enroll`, `client`, `testing`, `main.rs` | transport track |
| `exec`, `process/*` | exec track |
| `sandbox/linux.rs`, `sandbox/placeholders.rs` | Linux sandbox track |
| `sandbox/macos.rs` | macOS sandbox track |
| `sandbox/windows.rs` | Windows sandbox track |
| `fs` (bodies of `perform` and `handle`), `watch` | files track |
| `proxy/*`, `streams`, `tunnel` | proxy track |
| `node_info/*` | node-info track |

Stay inside your files. A change to a frozen signature, a shared type, or a dependency goes
through the scaffold owner, not into your track's diff. Every stub is implemented now; a new
seam gets a real implementation in the same change, not a stub.

## Conventions

* Parse at the boundary. `dispatch` turns params into `protocol` types and `access` into a
  `Confinement`. Code behind it trusts those types.
* Model variants as enums, not optional-field bags. Wire enums use serde tags that match the docs.
* No `todo!()`, `unimplemented!()` or `dbg!()` (clippy denies them). Every `unsafe` block gets a
  `// SAFETY:` comment.
* Tests call the real code and assert literal values.
* A placeholder for a missing deny path is the only thing the supervisor creates to apply a
  policy, and it removes it afterwards (policy.md, Paths that do not exist).

## Building and testing

This host's linker needs a writable temp dir, and the Zig and xwin caches in `$HOME` are
read-only in the agent sandbox:

```
export TMPDIR=$PWD/.context/tmp ZIG_GLOBAL_CACHE_DIR=$PWD/.context/zig ZIG_LOCAL_CACHE_DIR=$PWD/.context/zig XWIN_CACHE_DIR=$PWD/.context/xwin
mkdir -p $TMPDIR
cargo fmt --check
cargo clippy --offline --all-targets --all-features -- -D warnings
cargo test --offline --all-features
cargo xwin clippy --offline --target x86_64-pc-windows-msvc --all-targets --all-features -- -D warnings
cargo zigbuild --offline --target aarch64-unknown-linux-musl --all-targets --all-features
```

Network is blocked, but every dependency is in `~/.cargo`, so `--offline` works. For xwin, copy
`~/.cache/cargo-xwin/{xwin,cmake}` into `.context/xwin/` once, and no download is needed.

## Testing on the Mac

Kirill's Mac mini (arm64) runs the macOS tests. Work only under
`/Volumes/HappyScratch400/<taskId>/<track>/`. Never create folders in `~`, and never use the
speaker. Rust there needs:

```
export CARGO_HOME=/Volumes/HappyScratch400/nmwmk88dj0mjsl46fbzmjxfu/cargo RUSTUP_HOME=/Volumes/HappyScratch400/nmwmk88dj0mjsl46fbzmjxfu/rustup PATH=/Volumes/HappyScratch400/nmwmk88dj0mjsl46fbzmjxfu/cargo/bin:$PATH
```

Rsync the checkout without `target/` and `.git/`, using the ssh options of the task's `mac.sh`
helper, then run `cargo test --all-features` there.

## Commits

Author and committer email `steve@korshakov.com`:

```
git -c user.name="Steve Korshakov" -c user.email=steve@korshakov.com commit ...
```
