# snarkvm-utilities

[![Crates.io](https://img.shields.io/crates/v/snarkvm-utilities.svg?color=neon)](https://crates.io/crates/snarkvm-utilities)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Timing

snarkVM marks the regions of code that it times with [`tracing`](https://docs.rs/tracing) spans.
`timing_span!` opens a span, and `timing_event!` marks a step inside a span.
Both use the `TRACE` level and the target `timing::<module path>`, for example `timing::snarkvm_algorithms::snark::varuna::varuna`.

A span costs a few nanoseconds when no subscriber accepts its target.
The arguments of a span or an event are only evaluated when a subscriber accepts it.

To print the duration of each span, install a subscriber that accepts the `timing` targets and logs when a span closes.
This needs `tracing-subscriber` with the `env-filter` feature:

```rust
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan};

tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("timing=trace"))
    .with_span_events(FmtSpan::CLOSE)
    .init();
```

Each line names the span, its parent spans, and their fields. `time.busy` is the time spent inside the span:

```text
2026-11-13T18:49:55.250700Z TRACE Committing to polynomial{degree=8 hiding_bound=None}:MSM to compute commitment to plaintext poly: timing::snarkvm_algorithms::polycommit::kzg10: close time.busy=1.56ms time.idle=1.68µs
```

A filter selects the timings by module:

| Filter | Timings |
|---|---|
| `timing=trace` | All of snarkVM |
| `timing::snarkvm_algorithms=trace` | Polynomial commitments and Varuna |
| `timing::snarkvm_algorithms::snark::varuna=trace` | Varuna |
| `timing::snarkvm_console_collections=trace` | Merkle trees |
| `timing::snarkvm_synthesizer=trace` | The VM and the process |
| `timing::snarkvm_ledger=trace` | The ledger and the puzzle |

Other `tracing` layers also read these spans, for example `tracing-flame` and `tracing-chrome`.

A subscriber that accepts every target at `TRACE` also accepts the `timing` targets.
Add the directive `timing=off` to such a filter to leave the timings out.

A binary can remove the spans at compile time with a `tracing` feature such as `release_max_level_debug`.
This also removes every other `TRACE` span and event in the binary.

A span that is opened on another thread, for example in a `rayon` task, does not have the caller's span as its parent.
