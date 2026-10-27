# CI overview

CI runs on GitHub Actions, in [`ci.yml`](.github/workflows/ci.yml). Benchmarks
run from [`benchmarks.yml`](.github/workflows/benchmarks.yml).
[`gpu-test.yml`](.github/workflows/gpu-test.yml) runs the CUDA kernels on a
`gpu` fleet box, built for `sm_86`, when a pull request or a push to `staging`
changes `algorithms/` or the manifests, and nightly.

Jobs run in one of two places:

- **GitHub-hosted runners** for cheap jobs: formatting, `cargo deny`,
  `cargo machete`, wasm, the Windows checks and the lighter crates' tests.
  These restore `~/.cargo` and `target/` with `Swatinem/rust-cache`, saved
  only from `staging`.
- **The aleo-labs-protocol `cpu` fleet** for heavy jobs: clippy, release checks
  and the heavier crates' tests. `start-cpu-runners` starts the 32-vCPU boxes
  the run needs; they stop themselves when idle. Each box keeps a persistent
  `target/` and sccache, so builds there are incremental.

## Triggers

| Event | Runs |
|---|---|
| Pull request | `fmt`, `deny`, `wasm`, `lint`, `test`, `ci-ok` |
| Push to `staging`, `canary`, `testnet`, `mainnet`, or manual dispatch | the above, plus `test-merge`, `machete` |
| Push to `canary`, `testnet`, `mainnet`, or manual dispatch | the above, plus `windows` |

## Jobs

A job marked "merge" runs only on the second and third rows of the table
above. A job marked "release" runs only on the third row. The other jobs run
on every event.

| Job | Runner | Trigger | Timeout (min) | What it runs | CircleCI job |
|---|---|---|---|---|---|
| `start-cpu-runners` | hosted | all | | starts fleet boxes | |
| `ci-ok` | hosted | all | | fails unless every pull-request job above and every `test` entry succeeded; the check to require | |
| `check-shared-refs` | hosted | all | | checks that each `aleo-labs-protocol/gh-actions` ref is a release tag | |
| `fmt` | hosted | all | | `cargo fmt --check` on `FMT_TOOLCHAIN` | `check-fmt` |
| `deny` | hosted | all | | `cargo deny check bans licenses sources`; advisories are checked nightly by [`bump-advisories.yml`](.github/workflows/bump-advisories.yml) | `check-cargo-deny` |
| `wasm` | hosted | all | | `wasm-pack test --node` in `wasm` | `wasm` |
| `lint` | `cpu` | all | 90 | clippy, default and `--all-features`; on release, also `cargo check --release --workspace --all-targets` | `check-clippy`, `check-all-targets`, `parameters-large` |
| `test (console)` | hosted | all | 90 | `snarkvm-console` and its sub-crates, except `-collections` | `console`, `console-account`, `console-algorithms`, `console-network`, `console-network-environment`, `console-program`, `console-types`, `console-types-address`, `console-types-boolean`, `console-types-field`, `console-types-group`, `console-types-integers`, `console-types-scalar`, `console-types-string` |
| `test (circuit)` | hosted | all | 90 | `snarkvm-circuit` and its sub-crates, except `-collections`, `-types-integers` and `-program`; then `snarkvm-circuit-environment` | `circuit`, `circuit-account`, `circuit-algorithms`, `circuit-network`, `circuit-types`, `circuit-types-address`, `circuit-types-boolean`, `circuit-types-field`, `circuit-types-group`, `circuit-types-scalar`, `circuit-types-string`, `circuit-environment` |
| `test (narwhal)` | hosted | all | 90 | `snarkvm-ledger-authority`, `-ledger-committee`, `-ledger-narwhal` and its sub-crates except `-data`, `-ledger-query`, `-synthesizer-snark`, `-curves`, `-fields`, `-utilities`, `-utilities-derives` | `ledger-authority`, `ledger-committee`, `ledger-narwhal`, `ledger-narwhal-batch-certificate`, `ledger-narwhal-batch-header`, `ledger-narwhal-subdag`, `ledger-narwhal-transmission`, `ledger-narwhal-transmission-id`, `ledger-query`, `synthesizer-snark`, `curves`, `fields`, `utilities`, `utilities-derives` |
| `test (crates)` | `cpu` | all | 90 | `snarkvm`, `-algorithms`, `-circuit-collections`, `-circuit-types-integers`, `-console-collections` | `snarkvm`, `algorithms`, `circuit-collections`, `circuit-types-integers`, `console-collections` |
| `test (ledger)` | `cpu` | all | 90 | `snarkvm-ledger`; then its `valid_solutions` tests with `test` | `ledger`, `ledger-with-valid-solutions` |
| `test (ledger-store)` | `cpu` | all | 90 | `snarkvm-ledger-store` with `rocks`; then its genesis commitment test with `dev_genesis_state_root,test`; then `-ledger-narwhal-data` and `-ledger-test-helpers`; then `-ledger-puzzle` and `-ledger-puzzle-epoch` | `ledger-store`, `ledger-narwhal-data`, `ledger-test-helpers`, `ledger-puzzle`, `ledger-puzzle-epoch` |
| `test (synthesizer)` | `cpu` | all | 90 | `snarkvm-synthesizer` lib and bins | `synthesizer` |
| `test (synthesizer-process)` | `cpu` | all | 90 | `snarkvm-synthesizer-process`; then `-synthesizer-program` lib and bins; then `-circuit-program` | `synthesizer-process`, `synthesizer-program`, `circuit-program` |
| `test (ledger-rocks)` | `cpu` | merge | 90 | `snarkvm-ledger` with `rocks`, release | `ledger-with-rocksdb-partition1`, `ledger-with-rocksdb-partition2` |
| `test (ledger-merge)` | `cpu` | merge | 90 | the ignored `valid_solutions` tests of `snarkvm-ledger`; the ignored tests of `-ledger-store`; `-ledger-block` | `ledger-with-valid-solutions-prerelease`, `ledger-store-prerelease`, `ledger-block` |
| `test (parameters)` | `cpu` | merge | 90 | `snarkvm-parameters` | `parameters` |
| `test (parameters-uncached)` | `cpu` | merge | 90 | the ignored tests of `snarkvm-parameters`, in an empty home directory | `parameters-uncached` |
| `test (synthesizer-release)` | `cpu` | merge | 90 | `snarkvm-synthesizer` lib and bins with `test`, release | `synthesizer-test-partition1`, `synthesizer-test-partition2` |
| `test (synthesizer-prerelease)` | `cpu` | merge | 90 | the ignored tests of `snarkvm-synthesizer` with `test`; `-synthesizer-process` with `rocks` | `synthesizer-prerelease`, `synthesizer-process-with-rocksdb` |
| `test (synthesizer-integration)` | `cpu` | merge | 90 | the `snarkvm-synthesizer` parse, process and VM tests with `test,dev-print` | `synthesizer-integration` |
| `test (synthesizer-program)` | `cpu` | merge | 90 | the `snarkvm-synthesizer-program` integration tests, in three runs split by test name | `synthesizer-program-integration`, `synthesizer-program-integration-keccak`, `synthesizer-program-integration-psd`, `synthesizer-program-integration-sha`, `synthesizer-program-integration-instruction-is`, `synthesizer-program-integration-instruction-commit` |
| `machete` | hosted | merge | | `cargo machete` | `check-unused-dependencies` |
| `windows` | hosted (Windows) | release | | `cargo check --examples --benches --tests` in `algorithms`, `circuit`, `console`, `curves`, `fields`, `ledger`, `parameters`, `synthesizer`, `utilities` | `verify-windows` |

`check-cargo-semver-checks` has no job here. It had not passed for months.
`synthesizer-program-integration-instruction-equal` has none either: its
filter matched no test.

A job with no timeout gets the GitHub default of six hours. Only hosted jobs
have none, and a hosted job holds no fleet box.

## Test groups

Each `test` and `test-merge` entry is one cargo build. `cargo test -p a -p b`
unifies the features of `a` and `b`, and several crates enable `test`,
`rocks` or `test_consensus_heights` on their dependencies, which changes what
those dependencies compute. So crates share an entry only where that
unification enables none of those features, nor `wasm` or `large_params`, on
any snarkvm crate. Helper features such as `test-helpers` can still be
unified, so a test may compile in its entry that would not under
`cargo test -p <crate>` alone. Check this before moving a crate between
entries.

Each entry uploads nextest's JUnit report as the artifact `junit-<entry>`,
with the time of each test.

## Forks

A fork's pull request runs nothing on the fleet. Every self-hosted job checks
that the head repository is this one. The hosted jobs, including the hosted
`test` entries, still run, but `ci-ok` fails, so a fork's change merges only
after it is pushed to a branch here. The fleet's `target/` and sccache
persist between jobs, so anyone who can push a branch here can affect later
builds there. That is the same trust as push access; do not widen the guard.
