# Contributing

Thank you for your interest in contributing to snarkVM! Below you can find some guidelines that the project strives to follow.

## Pull requests

Please follow the instructions below when filing a pull request:

- Ensure that your branch is forked from the current [staging](https://github.com/aleo-labs-protocol/snarkVM/tree/staging) branch.
- Use the git commit hook, which ensures `cargo fmt` and `cargo clippy` are run with appropriate parameters. [`.rustfmt.toml`](https://github.com/aleo-labs-protocol/snarkVM/blob/staging/.rustfmt.toml) specifies some of the formatting conventions.
- The pre-commit hook reads `rusty-hook.toml`. To change it locally, copy it to `.rusty-hook.toml`, which git ignores and rusty-hook prefers.
- Do not rebase your PR after substantial reviews have taken place. The only exception is when there has been a substantial architectural overhaul which requires new reviews.
- When you fix someone's comment, reply with the relevant commit hash.

## Performance pull requests

CI does not benchmark pull requests. If your pull request claims a speedup, you measure it and post the results in the pull request. A reviewer must be able to repeat your measurement. If you cannot show a measurable improvement, or we cannot reproduce your result, we may close the pull request.

### What to measure

The right measurement depends on the change. Measure at the highest level that the change moves.

- **A high-level operation is the strongest evidence.** Examples are `VM::check_transaction`, deployment verification, reading a checked block, `Process::execute` and proving a transaction.
- **A lower-level function can also be convincing**, for example a field operation, an MSM or a hash. Explain which high-level paths call it and how often. A large microbenchmark gain often moves the high-level operation by much less, or not at all. If you can, also give the high-level number.
- **If the change removes allocations, count them.** Give the allocation count and the bytes allocated before and after, as #3670 did.
- **Include a control.** A control is a measurement that the change should not move. Choose it before you run. If the control moves, the run measured something other than your change.
- **Measure what production runs.** `VM::check_transaction` caches each transaction it accepts, so a loop over one transaction times the cache. A ledger at a low height uses old consensus versions, and with them an old Varuna version.

### How to measure

- **Use one quiet machine.** We use an AWS `c7i.4xlarge` (Sapphire Rapids, 16 vCPUs). Do not compare results from different machines or different CPU vendors. Nothing else may run on the machine during a measurement, including your own builds.
- **Build first, then wait.** Wait until the load average falls and no `cargo` or `rustc` process runs. We have seen results taken straight after a build run 25–40% slow for several runs.
- **Record the load average during the run.** If something disturbs a run, discard the run and take it again. Do not keep a disturbed run because the disturbance looks small.
- **Prefer one binary with a switch.** For example, read an environment variable that selects the old or the new code path. Then both arms have the same code layout. The switch can live on a measurement branch. The pull request does not need to keep it.
- **If you must compare two builds,** build both with the same toolchain, features and `RUSTFLAGS`. `RUSTFLAGS` replaces the `rustflags` in `.cargo/config.toml`, so repeat `-C target-cpu`. Check that the two binaries differ, and that each one was built from the commit you expect. Code layout alone can move a result by a few percent. To control for layout, use several builds per arm with randomized layouts, for example with LLD's `--shuffle-sections`.
- **Interleave the arms.** A block is one run of each arm. Take at least 6 blocks, and alternate the order: A then B, B then A, and so on. Do not run all of A and then all of B, because a slow period on the machine then lands on one arm only. Criterion's saved baselines compare runs taken at different times, so do not use them as your A/B.
- **Pin single-threaded measurements.** Use `taskset` to pin the run to one core, set `RAYON_NUM_THREADS=1`, and keep the core's hyperthread sibling idle. Measure throughput separately, with every thread busy.

### How to report

- **Give a table** with the baseline, the change and the difference, and the median and the range across blocks.
- **State the significance, and name the test.** With 6 interleaved blocks, a change that has the same sign in all 6 gives `p_sign = 0.031` with an exact two-sided sign test. Say what you did with ties.
- **A change below 1% is usually within the measurement noise.** Treat it as no change, unless it has the same sign in every block and the control does not move.
- **Describe the method in a short paragraph.** Give the machine and CPU, the pinning, the number of builds and blocks, the load during the run, and the commits that you measured. If you rebased after you measured, say so.
- **Give the commands** that a reviewer can run to repeat the measurement.

## Coding conventions

snarkVM is a big project, so (non-)adherence to best practices related to performance can have a considerable impact; below are the rules we try to follow at all times in order to ensure high quality of the code:

### Error handling
- prefer the use of `checked_div` when dividing polynomials.

### Memory handling
- if the final size is known, pre-allocate the collections (`Vec`, `HashMap` etc.) using `with_capacity` or `reserve` - this ensures that there are both fewer allocations (which involve system calls) and that the final allocated capacity is as close to the required size as possible
- create the collections right before they are populated/used, as opposed to e.g. creating a few big ones at the beginning of a function and only using them later on; this reduces the amount of time they occupy memory
- if an intermediate vector is avoidable, use an `Iterator` instead; most of the time this just amounts to omitting the call to `.collect()` if a single-pass iteration follows afterwards, or returning an `impl Iterator<Item = T>` from a function when the caller only needs to iterate over that result once
- when possible, fill/resize collections "in bulk" instead of pushing a single element in a loop; this is usually (but not always) detected by `clippy`, suggesting to create vectors containing a repeated value with `vec![x; N]` or extending them with `.resize(N, x)`
- when a value is to eventually be consumed in a chain of function calls, pass it by value instead of by reference; this has the following benefits:
  * it makes the fact that the value is needed by value clear to the caller, who can then potentially reclaim it from the object afterwards if it is "heavy", limiting allocations
  * it often enables the value to be cloned fewer times (whenever it's no longer needed at the callsite)
  * when the value is consumed and is not needed afterwards, the memory it occupies is freed, improving memory utilization
- if a slice may or may _not_ be extended (which requires a promotion to a vector) and does not need to be consumed afterwards, consider using a [`Cow<'a, [T]>`](https://doc.rust-lang.org/std/borrow/enum.Cow.html) combined with `Cow::to_mut` instead to potentially avoid an extra allocation; an example in snarkVM could be conditional padding of bits
- prefer arrays and temporary slices to vectors where possible; arrays are often a good choice if their final size is known in advance and isn't too great (as they are stack-bound), and a small temporary slice `&[x, y, z]` is preferable to a `vec![x, y, z]` if it's applicable
- if a reference is sufficient, don't use `.clone()`/`to_vec()`, which is often the case with methods on `struct`s that provide access to their contents; if they only need to be referenced, there's no need for the extra allocation
- use `into_iter()` instead of `iter().cloned()` where possible, i.e. whenever the values being iterated over can be consumed altogether
- if possible, reuse collections; an example would be a loop that needs a clean vector on each iteration: instead of creating and allocating it over and over, create it _before_ the loop and use `.clear()` on every iteration instead
- try to keep the sizes of `enum` variants uniform; use `Box<T>` on ones that are large

### Misc. performance

- avoid the `format!()` macro; if it is used only to convert a single value to a `String`, use `.to_string()` instead, which is also available to all the implementors of `Display`
- don't check if an element belongs to a map (using `contains` or `get`) if you want to conditionally insert it too, as the return value of `insert` already indicates whether the value was present or not; use that or the `Entry` API instead
- if a reference is sufficient as a function parameter, use:
  * `&[T]` instead of `&Vec<T>`
  * `&str` instead of `&String`
  * `&Path` instead of `&PathBuf`
- if a lot of computational power is needed, consider parallelizing that workload with [`rayon`](https://crates.io/crates/rayon) - it's not always a viable solution, but can yield great performance improvements when used in the right context; the [`cfg_*` macros](https://github.com/aleo-labs-protocol/snarkVM/blob/staging/utilities/src/parallel.rs) wrap the common `rayon` iterators; to run single-threaded, a caller runs snarkVM inside a 1-thread `rayon` pool
- for `struct`s that can be compared/discerned based on some specific field(s), consider hand-written implementations of `PartialEq` **and** `Hash` ([they must match](https://doc.rust-lang.org/std/hash/trait.Hash.html#hash-and-eq)) for faster comparison and hashing
- if possible, ensure that the results of your changes are not detrimental to performance using [`criterion`](https://crates.io/crates/criterion) (for smaller, fine-grained adjustments) and [`valgrind --tool={cachegrind | massif}`](https://valgrind.org/info/tools.html) (for larger-scale changes); to claim a speedup, follow [Performance pull requests](#performance-pull-requests)
