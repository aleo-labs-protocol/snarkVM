# CI overview

CI runs on GitHub Actions, in [`ci.yml`](.github/workflows/ci.yml). Benchmarks
run from [`benchmarks.yml`](.github/workflows/benchmarks.yml).
[`gpu-test.yml`](.github/workflows/gpu-test.yml) runs the CUDA kernels on a
`gpu` fleet box, built for `sm_86`, when a pull request changes `algorithms/` or
the manifests, and nightly on `staging`.

Jobs run in one of two places:

- **GitHub-hosted runners** for cheap jobs: formatting, `cargo deny`,
  `cargo machete`, wasm, the Windows checks and the lighter crates' tests.
  These restore `~/.cargo` and `target/` with `Swatinem/rust-cache`, saved
  only from `staging`.
- **The aleo-labs-protocol `cpu` fleet** for heavy jobs: clippy, release checks
  and the heavier crates' tests. The org's fleet starter starts the 32-vCPU
  boxes when GitHub queues their jobs; they stop themselves when idle. Each box keeps a persistent
  `target/` and sccache, so builds there are incremental.

## Triggers

| Event | Runs |
|---|---|
| Pull request | `fmt`, `deny`, `source-checks`, `wasm`, `lint`, `lint-locktick`, `test`, `ci-ok` |
| Schedule, every 6 hours, on the head of `staging` | `schedule-due`; unless it finds a verdict, the above plus `test-merge`, `each-feature`, `machete`; then `notify` |
| Push to or pull request into `release/**`, or manual dispatch | the pull request set, plus `test-merge`, `each-feature`, `machete`, `test-release`, `windows` |
| Push to `staging` | nothing |

## Jobs

A job marked "merge" runs only on the second and third rows of the table
above. A job marked "release" runs only on the third row. A job marked
"schedule" runs only on the second row. The other jobs run on the first three
rows.

| Job | Runner | Trigger | Timeout (min) | What it runs | CircleCI job |
|---|---|---|---|---|---|
| `ci-ok` | hosted | all | | fails unless every job that runs on the event succeeded, and every `test` entry; on a release branch or a pull request into one, also fails if a merge or release job was skipped; on a scheduled run that `schedule-due` lets through, also fails if a merge job was skipped; the check to require | |
| `schedule-due` | hosted | schedule | | decides whether the scheduled run tests the head of `staging`; see [Schedule](#schedule) | |
| `notify` | hosted | schedule | | posts to Slack when the scheduled run turns red, and once when it turns green again | |
| `check-shared-refs` | hosted | all | | checks that each `aleo-labs-protocol/gh-actions` ref is a release tag, and that each matrix `name` axis lists the same names as its `include` | |
| `fmt` | hosted | all | | `cargo fmt --check` on `FMT_TOOLCHAIN` | `check-fmt` |
| `deny` | hosted | all | | `cargo deny check bans licenses sources`; advisories are checked nightly by [`bump-advisories.yml`](.github/workflows/bump-advisories.yml) | `check-cargo-deny` |
| `source-checks` | hosted | all | | `scripts/check_sources.py`: the license header in each tracked `.rs` file, and on Linux the header's year | |
| `wasm` | hosted | all | | `wasm-pack test --node` in `wasm` | `wasm` |
| `lint` | `cpu` | all | 90 | clippy, default and `--all-features`; `cargo doc --all-features`; on release, also `cargo check --release --workspace --all-targets` | `check-clippy`, `check-all-targets`, `parameters-large` |
| `lint-locktick` | `cpu` | all | 90 | clippy `--all-features` under `--cfg locktick` (`locktick-clippy` alias) | |
| `test (console)` | hosted | all | 90 | `snarkvm-console` and its sub-crates, except `-collections` | `console`, `console-account`, `console-algorithms`, `console-network`, `console-network-environment`, `console-program`, `console-types`, `console-types-address`, `console-types-boolean`, `console-types-field`, `console-types-group`, `console-types-integers`, `console-types-scalar`, `console-types-string` |
| `test (circuit)` | hosted | all | 90 | `snarkvm-circuit` and its sub-crates, except `-collections`, `-types-integers` and `-program`; then `snarkvm-circuit-environment` | `circuit`, `circuit-account`, `circuit-algorithms`, `circuit-network`, `circuit-types`, `circuit-types-address`, `circuit-types-boolean`, `circuit-types-field`, `circuit-types-group`, `circuit-types-scalar`, `circuit-types-string`, `circuit-environment` |
| `test (narwhal)` | hosted | all | 90 | `snarkvm-ledger-authority`, `-ledger-committee`, `-ledger-narwhal` and its sub-crates except `-data`, `-ledger-query`, `-synthesizer-snark`, `-curves`, `-fields`, `-utilities`, `-utilities-derives` | `ledger-authority`, `ledger-committee`, `ledger-narwhal`, `ledger-narwhal-batch-certificate`, `ledger-narwhal-batch-header`, `ledger-narwhal-subdag`, `ledger-narwhal-transmission`, `ledger-narwhal-transmission-id`, `ledger-query`, `synthesizer-snark`, `curves`, `fields`, `utilities`, `utilities-derives` |
| `test (crates)` | `cpu` | all | 90 | `snarkvm`, `-algorithms`, `-circuit-collections`, `-circuit-types-integers`, `-console-collections` | `snarkvm`, `algorithms`, `circuit-collections`, `circuit-types-integers`, `console-collections` |
| `test (ledger)` | `cpu` | all | 90 | `snarkvm-ledger` | `ledger` |
| `test (ledger-store)` | `cpu` | all | 90 | `snarkvm-ledger-store` with `rocks`; then `-ledger-narwhal-data` and `-ledger-test-helpers`; then `-ledger-puzzle` and `-ledger-puzzle-epoch` | `ledger-store`, `ledger-narwhal-data`, `ledger-test-helpers`, `ledger-puzzle`, `ledger-puzzle-epoch` |
| `test (synthesizer)` | `cpu` | all | 90 | `snarkvm-synthesizer` lib and bins | `synthesizer` |
| `test (synthesizer-process)` | `cpu` | all | 90 | `snarkvm-synthesizer-process`; then `-synthesizer-program` lib and bins; then `-circuit-program` | `synthesizer-process`, `synthesizer-program`, `circuit-program` |
| `test-merge (ledger-rocks)` | `cpu` | merge | 90 | `snarkvm-ledger` with `rocks`, release | `ledger-with-rocksdb-partition1`, `ledger-with-rocksdb-partition2` |
| `test-merge (ledger-merge)` | `cpu` | merge | 90 | the `valid_solutions` tests of `snarkvm-ledger` with `test`, ignored ones included, except `test_cumulative_proof_target_correctness`; the ignored tests of `-ledger-store`; its genesis commitment and dev genesis state root tests with `dev_genesis_state_root,test`; the dev genesis state root test of `snarkvm-ledger` with the same features; `-ledger-block` | `ledger-with-valid-solutions`, `ledger-with-valid-solutions-prerelease`, `ledger-store-prerelease`, `ledger-block` |
| `test-merge (parameters)` | `cpu` | merge | 90 | `snarkvm-parameters` | `parameters` |
| `test-merge (parameters-uncached)` | `cpu` | merge | 90 | the ignored tests of `snarkvm-parameters`, in an empty home directory | `parameters-uncached` |
| `test-merge (synthesizer-test-1)`, `-2` | `cpu` | merge | 90 | one half each of the `snarkvm-synthesizer` lib and bins tests, with `test` | `synthesizer-test-partition1`, `synthesizer-test-partition2` |
| `test-merge (synthesizer-prerelease)` | `cpu` | merge | 90 | the ignored tests of `snarkvm-synthesizer` with `test`; `-synthesizer-process` with `rocks` | `synthesizer-prerelease`, `synthesizer-process-with-rocksdb` |
| `test-merge (synthesizer-integration)` | `cpu` | merge | 90 | the `snarkvm-synthesizer` parse, process and VM tests with `test`, printing `snarkvm=debug` events | `synthesizer-integration` |
| `test-merge (synthesizer-program)` | `cpu` | merge | 90 | the `snarkvm-synthesizer-program` integration tests, in three runs split by test name | `synthesizer-program-integration`, `synthesizer-program-integration-keccak`, `synthesizer-program-integration-psd`, `synthesizer-program-integration-sha`, `synthesizer-program-integration-instruction-is`, `synthesizer-program-integration-instruction-commit` |
| `each-feature` | `cpu` | merge | 90 | `cargo hack clippy --each-feature` on each crate, without `cuda`, `no-embedded-srs` and `dev_skip_checks`: each crate with no features and with each feature alone | |
| `test-release (old-consensus-versions-1)` to `-3` | `cpu` | release | 120 | one third each of the V8 to V14 tests of `snarkvm-synthesizer`, ignored ones included, with `test-old-consensus-versions`, release | |
| `test-release (integers-exhaustive)` | `cpu` | release | 120 | the ignored tests of `snarkvm-circuit-types-integers`, which check every 8-bit input | |
| `test-release (synthesizer-rocks)` | `cpu` | release | 120 | `snarkvm-synthesizer` lib and bins with `rocks`, release; again with `test,rocks`, then the ignored tests; then `test_vm_execute_and_finalize` with `test,rocks` | |
| `machete` | hosted | merge | | `cargo machete` | `check-unused-dependencies` |
| `windows` | hosted (Windows) | release | | `cargo check --examples --benches --tests` in `algorithms`, `circuit`, `console`, `curves`, `fields`, `ledger`, `parameters`, `synthesizer`, `utilities` | `verify-windows` |

`check-cargo-semver-checks` has no job here. It had not passed for months.
`synthesizer-program-integration-instruction-equal` has none either: its
filter matched no test.

A job with no timeout gets the GitHub default of six hours. Only hosted jobs
have none, and a hosted job holds no fleet box.

A pull request that changes only Markdown files starts no run, so it gets no
`ci-ok` check. The files under `curves/documentation` do not count: they are
compiled into `snarkvm-curves`. A push to a release branch runs everything. If
a branch rule ever requires `ci-ok`, such a pull request cannot merge until a
workflow reports that check for it.

## Schedule

A push to `staging` starts no run. A branch rule does not require a pull
request to be up to date with `staging`, so two pull requests that each pass
can still fail together once both are merged. The scheduled run catches that.
It runs at minute 17 of every sixth hour (UTC), on the head of `staging`.

`schedule-due` first lists the earlier scheduled runs on the same commit. If
one of them passed or failed, and its `fmt` ran, that commit has a verdict, and
every other job is skipped. The step summary links that run. A run that was
cancelled, that `schedule-due` skipped, or whose `schedule-due` failed gives no
verdict, so the next scheduled run tests the same commit. A commit that failed
is not tested again on the schedule. To test it again, rerun its failed run: a
rerun always tests. If `schedule-due` cannot read the earlier runs, it warns and
the run tests. A scheduled run is never
cancelled, and it waits for the scheduled run before it to end.

`notify` reports each scheduled run to the Slack channel in the
`CI_SLACK_CHANNEL` variable, `#ci` by default. It posts only when the run turns
red, and once when it turns green again. A run that `schedule-due` skips posts
nothing.

The schedule fires on the default branch of every copy of this repository.
`schedule-due` and `notify` run only in this repository, and every other job
of a scheduled run needs `schedule-due`, so a scheduled run in a mirror, such
as snarkVM-internal, runs nothing.

## Test groups

Each line of a `test`, `test-merge` or `test-release` entry's `runs` is one
cargo build, and the entry runs its lines in order. `cargo test -p a -p b`
unifies the features of `a` and `b`, and several crates enable `test`, `rocks`
or `test_consensus_heights` on their dependencies, which changes what those
dependencies compute. So crates share a line only where that unification
enables none of those features, nor `wasm` or `large_params`, on any snarkvm
crate. Helper features such as `test-helpers` can still be unified, so a test
may compile in its line that would not under `cargo test -p <crate>` alone.
Check this before moving a crate between lines.

Each entry uploads nextest's JUnit reports, one for each line, as the artifact
`junit-<entry>`, with the time of each test.

## Forks

A fork's pull request runs nothing on the fleet. Every self-hosted job checks
that the head repository is this one. The hosted jobs, including the hosted
`test` entries, still run, but `ci-ok` fails, so a fork's change merges only
after it is pushed to a branch here. The fleet's `target/` and sccache
persist between jobs, so anyone who can push a branch here can affect later
builds there. That is the same trust as push access; do not widen the guard.
