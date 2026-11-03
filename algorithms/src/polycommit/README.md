# snarkvm-algorithms/polycommit

This module implements (univariate) *polynomial commitment schemes*. This library was initially developed as part of the [Marlin paper][marlin].

## Overview

A (univariate) polynomial commitment scheme is a cryptographic primitive that enables a party to commit to a univariate polynomial and then, later on, to reveal desired evaluations of the polynomial along with cryptographic proofs attesting to their correctness.

This library provides various constructions of polynomial commitment schemes. These constructions support committing to multiple polynomials at a time with differing degree bounds, batching multiple evaluation proofs for the same evaluation point into a single one, and batch verification of proofs.

The key properties satisfied by the polynomial commitment schemes are **succinctness**, **extractability**, and **hiding**. See [the Marlin paper][marlin] for definitions of these properties.

[kzg10]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf

## The universal SRS

SonicKZG10 uses one universal structured reference string (SRS) for every circuit.
`kzg10::UniversalParams` holds it, and `PowersOfG` in `parameters/src/mainnet/powers.rs` holds its points.
In the formulas below, `G` generates G1, `H` generates G2, and `β` and `γ` are the secret values of the setup.

The SRS has these parts:

- **Powers of β in G1**: `β^i G` for `i` in `0..MAX_NUM_POWERS`, where `MAX_NUM_POWERS` is `2^28`.
  The SRS keeps two ends of this range: a prefix that starts at `i = 0`, and a shifted suffix that ends at `i = MAX_NUM_POWERS - 1`.
  A commitment uses the prefix. A degree-bound check uses the suffix.
- **Powers of β times γ in G1**: `β^i γ G`, a sparse map.
  It holds only the entries that hiding needs: a few low powers, and a few powers at each shifted degree bound.
- **Negative powers of β in G2**: `β^(d - max_degree) H` for each supported degree bound `d`, where `max_degree = MAX_NUM_POWERS - 1`.
  A degree bound is `2^k - 2`, because each bound is the size of a power-of-two domain minus 2 (see `AHPForR1CS::get_degree_bounds`).
  A degree-bounded commitment is shifted up by `max_degree - d`. The verifier pairs it with this element to undo the shift.
- **`β H`**, and the G2 generator `H`. The verifier uses both in pairings.

### Files and growth

The SRS is split into files in `parameters/src/mainnet/resources`.

- `powers-of-beta-15` holds the powers `0..2^15`, and `shifted-powers-of-beta-15` holds `MAX_NUM_POWERS - 2^15..MAX_NUM_POWERS`.
- For `k > 15`, `powers-of-beta-k` holds the powers `2^(k-1)..2^k`, and `shifted-powers-of-beta-k` holds `MAX_NUM_POWERS - 2^k..MAX_NUM_POWERS - 2^(k-1)`.
- The SRS adds the files of each end in order of `k`.
- The crate embeds the files for degree 15, shifted degree 15 and 16, the γ powers, the negative powers and `β H`.
  With the `no-embedded-srs` feature, the degree files are remote too.
- Every other degree file is remote. Degrees above 25 also need the `large_params` feature.

The SRS grows on demand. `PowersOfG::download_powers_for` and `download_powers_for_ends` add the files that a degree needs, in order.
With the `filesystem` feature, a download reads `~/.aleo/resources` first.
It fetches a missing file from the remote parameter server and stores it there.
With `wasm`, it fetches the file into memory.
It checks each file's size and SHA-256 checksum.
On a native build without `filesystem`, these functions download nothing. They return `MissingPowers`, which names the files.
The caller then supplies each file through `add_powers_file`.

### Committer keys

`SonicKZG10::trim` cuts a `CommitterKey` from the SRS for one circuit.
The key needs both ends of the powers of β:

- the prefix `0..=supported_degree`, to commit;
- the suffix from `MAX_NUM_POWERS - 1 - d` for the largest degree bound `d`, to check degree bounds.

So a trimmed SRS cannot just drop its high powers.
`trim` downloads both ends first, and the key then shares them with the SRS through `Bases::Shared`. It does not copy them.

The serialized key still writes every point.
`CommitterKey::read_le_with_srs` reads such bytes, skips the points, and shares the SRS points in their place.
A hash of the points in the bytes makes sure the shared points are the same.

The verifier key, `UniversalVerifier`, depends only on the SRS. It is the same for every circuit.

## Profiling

This library is instrumented with profiling infrastructure that prints detailed traces of execution time. To enable this, compile with `cargo build --features profiler`.

[marlin]: https://ia.cr/2019/1047
[sonic]: https://ia.cr/2019/099
[aurora-light]: https://ia.cr/2019/601
[pcd-acc]: https://ia.cr/2020/499

## Reference papers

[Polynomial Commitments][kzg10]     
Aniket Kate, Gregory M. Zaverucha, Ian Goldberg     
ASIACRYPT 2010

[Sonic: Zero-Knowledge SNARKs from Linear-Size Universal and Updateable Structured Reference Strings][sonic]     
Mary Maller, Sean Bowe, Markulf Kohlweiss, Sarah Meiklejohn     
CCS 2019

[AuroraLight: Improved prover efficiency and SRS size in a Sonic-like system][aurora-light]     
Ariel Gabizon     
ePrint, 2019

[Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS][marlin]     
Alessandro Chiesa, Yuncong Hu, Mary Maller, [Pratyush Mishra](https://www.github.com/pratyush), Noah Vesely, [Nicholas Ward](https://www.github.com/npwardberkeley)     
EUROCRYPT 2020

[Proof-Carrying Data from Accumulation Schemes][pcd-acc]     
Benedikt Bünz, Alessandro Chiesa, [Pratyush Mishra](https://www.github.com/pratyush), Nicholas Spooner     
ePrint, 2020
