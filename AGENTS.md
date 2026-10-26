# snarkVM

## Before Writing Code
- Search for existing implementations.
- Read the target module and match its patterns exactly.
- Scope out necessary tests ahead of time.
- If uncertain, ask.
- Think very hard in your planning process.
- New files, crates, dependencies, abstractions, traits, or error types require approval.

## Architecture

snarkVM is a virtual machine for zero-knowledge proof execution on the Aleo blockchain.

**Crate dependencies:**
- `snarkvm-utilities` - no deps, macros and parallel primitives
- `snarkvm-fields` - depends on utilities, finite field arithmetic
- `snarkvm-curves` - depends on fields, elliptic curve implementations
- `snarkvm-algorithms` - depends on curves/fields, cryptographic primitives (Poseidon, Marlin, Polycommit)
- `snarkvm-console` - depends on algorithms, plaintext VM types (Address, Field, Group, Scalar, programs)
- `snarkvm-circuit` - depends on console, circuit/constraint equivalents of console types
- `snarkvm-ledger` - depends on synthesizer, blockchain state (blocks, transactions, storage)
- `snarkvm-synthesizer` - depends on console/circuit/algorithms, program execution and proof generation

**console / circuit sync requirement:**
- These crate families must stay in sync. Same structure, same API.
- When modifying one, check the other.
- Test circuit equivalence by comparing constraint counts.

## Rules
- All changes must be backwards compatible — no consensus forks.
- New files, crates, dependencies, abstractions, or traits require approval.
- `unwrap`s must have a comment justifying why they can't panic.

### Forking Risk
There are deployed versions of this software in the wild. Changes that alter consensus behavior (same inputs producing different outputs) will fork the network. All changes must either be backwards compatible or gated behind a consensus version so they can be rolled in at the appropriate time. Not all code has been released publicly, so if you are unsure whether a change is safe on a PR, ask before proceeding.

## Code and Patterns
- Test-driven development: write failing tests first.
- `unwrap`s must be commented with justification.
- Prefer `zip_eq` over `zip` when lengths must match.
- Pre-allocate with `with_capacity` when final size is known.
- Prefer `into_iter()` over `iter().cloned()`. Prefer references over `.clone()`.
- Use iterators; avoid intermediate `.collect()` when a single pass follows.
- Trait impls (ToBits, FromBits, ToField, FromField) should follow existing patterns in the same file.

See @CONTRIBUTING.md for detailed memory and performance guidelines.

## Code comments

Comments must describe the state of the code today -- not a previous state or an
alternative state.

Exception: Comments may describe an alternative possible state of the code,
*if* they are documenting a hazard that a future developer may otherwise walk into.

Comments must not describe the rationale for a change.

**Rationale may appear in: the commit message and the pull request.**
You may self-comment on your own github pull request at select positions in the code to aide reviewers.

Comments must help someone who has never heard of this change you are making.

Comments must not state the obvious. Comments that explain what attributes
do or how language constructs work are unhelpful.

## Testing

**Synthesizer tests are slow** — run only the specific test function.
Use `--features test,dev-print` for integration tests.

```bash
cargo test -p <crate>                                           # Run crate tests
cargo test -p <crate> -- test_name                              # Run specific test
cargo test -p snarkvm-synthesizer --features test,dev-print     # Integration tests
```

## Validation

Run in order:
```bash
cargo check -p <crate>
cargo clippy -p <crate> -- -D warnings
cargo +nightly-2026-04-02 fmt --check
cargo test -p <crate>
```

Clippy warnings are errors. Formatting requires the nightly `.github/workflows/ci.yml` pins as
`FMT_TOOLCHAIN` (`cargo +nightly-2026-04-02 fmt --all` to fix) -- `.rustfmt.toml` uses
nightly-only options, and plain `cargo fmt` drops them silently rather than refusing.

Pre-commit hook runs workspace-wide: `cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo +nightly-2026-04-02 fmt --all -- --check`

## Git
- Never commit unless explicitly asked.
- Stage with `git add` only if requested.
- Run `cargo +nightly-2026-04-02 fmt --all` before staging.

## Pull requests
- Follow `.github/PULL_REQUEST_TEMPLATE.md`.
- Write the PR README in Simplified Technical English. Use short sentences, the active voice, and one idea per sentence.
- Keep the pull request description succinct and DRY.
- Explain each commit in one line.

## Style
- One blank line between functions.
- No trailing whitespace.
- Imports: std first, external crates second, crate-local third.
- Match existing file patterns exactly — if the file uses `Self::`, you use `Self::`.
- Comments must be concise, complete, punctuated sentences.
- `#![forbid(unsafe_code)]` in all crates unless approved.
- License header required (enforced by `tests/sources.rs`).

## Review Checklist

### Correctness
- [ ] Logic traced step-by-step.
- [ ] Boundary conditions handled: zero, empty, max, off-by-one.
- [ ] Error handling correct; no panics in production paths.
- [ ] Serialization/deserialization roundtrips verified.

### Crypto-Specific
- [ ] Field operations use checked arithmetic where needed.
- [ ] Randomness sources are cryptographically secure.
- [ ] No consensus-breaking changes (same inputs must produce same outputs).
- [ ] Circuit constraints match console logic exactly.
- [ ] Proof verification logic is sound.

### Memory & Performance
- [ ] No unnecessary allocations in hot paths.
- [ ] Pre-allocation with `with_capacity` where size known.
- [ ] No unnecessary `.clone()` — prefer references.
- [ ] Iterators used efficiently; no intermediate collections.
- [ ] Parallel execution with rayon where appropriate.

### Security
- [ ] Input validation at trust boundaries.
- [ ] No information leakage in error messages.
- [ ] Fail-closed (reject on uncertainty).

## Deep Analysis Techniques

### Trace Execution
1. Start from program input.
2. Follow through console types -> circuit synthesis -> proof generation.
3. Track field element transformations.
4. Verify output matches expected proof/execution result.

### Enumerate Failure Modes
For each operation, ask:
- What if input is zero/empty/max?
- What if field elements overflow?
- What if serialization format changes?
- What if circuit constraints don't match console logic?

### Check Invariants
- Console and circuit types produce identical outputs for identical inputs.
- Serialization is deterministic and backwards compatible.
- Proof verification succeeds for valid proofs and fails for invalid ones.
- All randomness is derived from cryptographically secure sources.
