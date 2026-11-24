// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

use snarkvm_fields::ifma::EdwardsStep;

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> Hash for BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    type Input = bool;
    type Output = Field<E>;

    /// Returns the BHP hash of the given input as a field element.
    fn hash(&self, input: &[Self::Input]) -> Result<Self::Output> {
        Ok(self.hash_uncompressed(input)?.to_x_coordinate())
    }
}

/// An entry of a table of `AffineCurve::add_table_entries_8`: `y - x`, `y + x` and `2 d x y` of the affine point
/// `(x, y)`.
type LaneEntry<E> = [<E as Environment>::Field; 3];

/// The table of one group of consecutive chunks of a window.
#[derive(Debug)]
struct LaneGroup<E: Environment> {
    /// The index of the group's first chunk in the preimage.
    start: usize,
    /// The number of chunks, from 1 to `BHP_NUM_COMBINED_CHUNKS`.
    len: usize,
    /// The entry of the sum that each value of the group's chunks selects, at the index that takes the chunks in
    /// order, 3 bits each, the first chunk highest.
    table: Vec<LaneEntry<E>>,
}

/// The bases of a BHP instance as tables of `AffineCurve::add_table_entries_8`, for the first iteration of a hash.
///
/// The preimage of that iteration starts with the domain, so the leading groups that hold only domain bits select
/// the same sum in every hash, and have no table.
#[derive(Debug)]
pub(super) struct LaneTables<E: Environment> {
    /// The index of the first chunk after the groups that hold only domain bits.
    first_chunk: usize,
    /// The sum that the chunks before `first_chunk` select.
    prefix: E::Affine,
    /// The groups from `first_chunk`, in order: each window in groups of `BHP_NUM_COMBINED_CHUNKS` chunks, with its
    /// last chunks in one shorter group.
    groups: Vec<LaneGroup<E>>,
    /// The entries that each chunk from `first_chunk` selects from, for a group that the preimage ends inside.
    singles: Vec<[LaneEntry<E>; BHP_LOOKUP_SIZE]>,
}

/// Returns the index that chunks `start..start + len` of `bits` select in the table of their group.
fn chunks_index(bits: &[bool], start: usize, len: usize) -> u32 {
    bits[BHP_CHUNK_SIZE * start..BHP_CHUNK_SIZE * (start + len)].chunks_exact(BHP_CHUNK_SIZE).fold(0, |index, chunk| {
        (index << BHP_CHUNK_SIZE) | chunk[0] as u32 | (chunk[1] as u32) << 1 | (chunk[2] as u32) << 2
    })
}

impl<E: Environment> LaneTables<E> {
    /// Returns the tables of `hasher` for preimages that start with `domain`, or `None` if the curve has no lane
    /// path.
    ///
    /// No rayon here: this runs inside a `OnceLock`, and a worker in it could steal a job that waits on it.
    fn new<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(
        hasher: &BHPHasher<E, NUM_WINDOWS, WINDOW_SIZE>,
        domain: &[bool],
    ) -> Option<Self> {
        // With no step, the hook returns `Some` exactly where the curve has a lane path.
        E::Affine::add_table_entries_8(&E::Affine::zero(), &[])?;

        let window_size = WINDOW_SIZE as usize;
        let (bases_lookup, combined_bases_lookup) = (hasher.bases_lookup(), hasher.combined_bases_lookup());
        // The start and the length of every group.
        let layout = (0..NUM_WINDOWS as usize).flat_map(|window| {
            (0..window_size)
                .step_by(BHP_NUM_COMBINED_CHUNKS)
                .map(move |chunk| (window * window_size + chunk, BHP_NUM_COMBINED_CHUNKS.min(window_size - chunk)))
        });
        let domain_chunks = domain.len() / BHP_CHUNK_SIZE;
        let first_chunk =
            layout.clone().map(|(start, len)| start + len).take_while(|end| *end <= domain_chunks).last().unwrap_or(0);

        let prefix = (0..first_chunk)
            .map(|chunk| {
                bases_lookup[chunk / window_size][chunk % window_size][chunks_index(domain, chunk, 1) as usize]
            })
            .sum::<Group<E>>()
            .to_affine();

        let two_d = E::EDWARDS_D.double();
        // One inversion for all of `points`.
        let entries = |points: Vec<E::Projective>| {
            E::Projective::batch_normalization_into_affine(points).into_iter().map(move |point| {
                let (x, y) = (point.to_x_coordinate(), point.to_y_coordinate());
                [y - x, y + x, two_d * x * y]
            })
        };
        let groups = layout
            .skip_while(|(start, _)| *start < first_chunk)
            .map(|(start, len)| {
                let (window, chunk) = (start / window_size, start % window_size);
                let points = if len == BHP_NUM_COMBINED_CHUNKS {
                    combined_bases_lookup[window][chunk / BHP_NUM_COMBINED_CHUNKS].iter().map(|sum| **sum).collect()
                } else {
                    bases_lookup[window][chunk..chunk + len].iter().fold(vec![E::Projective::zero()], |sums, terms| {
                        sums.iter().flat_map(|sum| terms.iter().map(move |term| *sum + **term)).collect()
                    })
                };
                LaneGroup { start, len, table: entries(points).collect() }
            })
            .collect();
        let singles = (first_chunk..NUM_WINDOWS as usize * window_size)
            .map(|chunk| {
                let mut single = [[E::Field::zero(); 3]; BHP_LOOKUP_SIZE];
                let lookup = &bases_lookup[chunk / window_size][chunk % window_size];
                for (single, entry) in single.iter_mut().zip_eq(entries(lookup.iter().map(|point| **point).collect())) {
                    *single = entry;
                }
                single
            })
            .collect();

        Some(Self { first_chunk, prefix, groups, singles })
    }

    /// Returns the start, the length and the table of each run of chunks that selects one entry, for a preimage of
    /// `num_chunks` chunks: every group that the preimage holds whole, and each chunk of a group that it ends
    /// inside.
    fn runs(&self, num_chunks: usize) -> impl Iterator<Item = (usize, usize, &[LaneEntry<E>])> + Clone {
        self.groups.iter().take_while(move |group| group.start < num_chunks).flat_map(move |group| {
            let whole = group.start + group.len <= num_chunks;
            let count = if whole { 1 } else { num_chunks - group.start };
            (group.start..group.start + count).map(move |chunk| match whole {
                true => (group.start, group.len, group.table.as_slice()),
                false => (chunk, 1, self.singles[chunk - self.first_chunk].as_slice()),
            })
        })
    }
}

impl<E: Environment, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BHP<E, NUM_WINDOWS, WINDOW_SIZE> {
    /// Returns `self.hash(inputs[l])` for each `l`.
    ///
    /// The 8 hashes run in lockstep in AVX-512 IFMA lanes where `hash_8_lanes` takes them, and one by one
    /// otherwise. The outputs are the same either way.
    ///
    /// The first call that runs in lanes builds the lane tables, which takes tens of milliseconds. This instance
    /// and its clones then hold them: 10 MiB for BHP256, 18 MiB for BHP512, 24 MiB for BHP768 and 34 MiB for
    /// BHP1024.
    pub fn hash_8(&self, inputs: [&[bool]; 8]) -> Result<[Field<E>; 8]> {
        if let Some(outputs) = self.hash_8_lanes(inputs) {
            return Ok(outputs);
        }
        let mut outputs = [Field::zero(); 8];
        for (output, input) in outputs.iter_mut().zip_eq(inputs) {
            *output = self.hash(input)?;
        }
        Ok(outputs)
    }

    /// Returns `self.hash(inputs[l])` for each `l`, with the 8 sums of bases added in lockstep; or `None` if the
    /// inputs differ in length, are empty or take more than one iteration, or the curve's `add_table_entries_8`
    /// declines, as it does on a CPU without AVX-512 IFMA.
    #[doc(hidden)]
    pub fn hash_8_lanes(&self, inputs: [&[bool]; 8]) -> Option<[Field<E>; 8]> {
        let len = inputs[0].len();
        // The most input bits of one iteration. An instance whose iteration holds less than one field element
        // takes no input here.
        let max_len = (NUM_WINDOWS as usize * WINDOW_SIZE as usize * BHP_CHUNK_SIZE)
            .checked_sub(Field::<E>::size_in_data_bits())?;
        if !(1..=max_len).contains(&len) || inputs.iter().any(|input| input.len() != len) {
            return None;
        }
        let tables = self.lane_tables.get_or_init(|| LaneTables::new(&self.hasher, &self.domain)).as_ref()?;

        // The preimage is [ 0...0 || DOMAIN || LENGTH(INPUT) || INPUT ], padded with zeros to whole chunks.
        let num_chunks = (self.domain.len() + 64 + len).div_ceil(BHP_CHUNK_SIZE);
        let mut preimage = Vec::with_capacity(num_chunks * BHP_CHUNK_SIZE);
        preimage.extend(&self.domain);
        (len as u64).write_bits_le(&mut preimage);
        let header_len = preimage.len();

        let runs = tables.runs(num_chunks);
        let mut steps: Vec<EdwardsStep<'_, E::Field>> = runs.clone().map(|(_, _, table)| (table, [0; 8])).collect();
        for (l, input) in inputs.iter().enumerate() {
            preimage.truncate(header_len);
            preimage.extend_from_slice(input);
            preimage.resize(num_chunks * BHP_CHUNK_SIZE, false);
            for ((_, indices), (start, chunks, _)) in steps.iter_mut().zip_eq(runs.clone()) {
                indices[l] = chunks_index(&preimage, start, chunks);
            }
        }

        let mut sums = E::Affine::add_table_entries_8(&tables.prefix, &steps)?;
        // One inversion for the 8 sums.
        E::Projective::batch_normalization(&mut sums);
        Some(sums.map(|sum| Field::new(sum.to_affine().to_x_coordinate())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_types::environment::Console;

    /// Whether `hash_8_lanes` runs an input of one iteration in lanes on this CPU, from the CPU's features and the
    /// environment.
    fn lanes_expected() -> bool {
        #[cfg(target_arch = "x86_64")]
        let expected = std::is_x86_feature_detected!("avx512f")
            && std::is_x86_feature_detected!("avx512ifma")
            && std::env::var_os("SNARKVM_NO_IFMA").is_none_or(|value| value.is_empty());
        #[cfg(not(target_arch = "x86_64"))]
        let expected = false;
        expected
    }

    /// Checks `hash_8` and `hash_8_lanes` on `inputs` against `hash` on each input, and that the lanes run exactly
    /// when `lanes` says.
    fn check_hash_8<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(
        bhp: &BHP<Console, NUM_WINDOWS, WINDOW_SIZE>,
        inputs: &[Vec<bool>; 8],
        lanes: bool,
    ) {
        let lengths = inputs.each_ref().map(Vec::len);
        let inputs = inputs.each_ref().map(Vec::as_slice);
        let expected = inputs.map(|input| bhp.hash(input).unwrap());
        let hashes = bhp.hash_8(inputs).unwrap();
        let in_lanes = bhp.hash_8_lanes(inputs);
        assert_eq!(in_lanes.is_some(), lanes, "{lengths:?}");
        for l in 0..8 {
            assert_eq!(hashes[l], expected[l], "{lengths:?} lane {l}");
            if let Some(in_lanes) = in_lanes {
                assert_eq!(in_lanes[l], expected[l], "{lengths:?} lane {l}");
            }
        }
    }

    /// Checks the hashes of 8 inputs at once for every input length of one iteration: the inputs of all zeros and
    /// of all ones with two equal and four other random inputs, and 8 random inputs. Then checks the inputs that
    /// stay out of the lanes: the empty input, inputs of two iterations, and one input of another length.
    fn check_hash_8_lengths<const NUM_WINDOWS: u8, const WINDOW_SIZE: u8>(domain: &str, rng: &mut TestRng) {
        let bhp = BHP::<Console, NUM_WINDOWS, WINDOW_SIZE>::setup(domain).unwrap();
        let random = |rng: &mut TestRng, len: usize| (0..len).map(|_| bool::rand(rng)).collect::<Vec<_>>();
        let max_len =
            NUM_WINDOWS as usize * WINDOW_SIZE as usize * BHP_CHUNK_SIZE - Field::<Console>::size_in_data_bits();
        for len in 1..=max_len {
            let same = random(rng, len);
            let edges: [Vec<bool>; 8] = std::array::from_fn(|l| match l {
                0 => vec![false; len],
                1 => vec![true; len],
                2 | 3 => same.clone(),
                _ => random(rng, len),
            });
            check_hash_8(&bhp, &edges, lanes_expected());
            check_hash_8(&bhp, &std::array::from_fn(|_| random(rng, len)), lanes_expected());
        }

        check_hash_8(&bhp, &std::array::from_fn(|_| vec![]), false);
        for len in [max_len + 1, 2 * max_len, 2 * max_len + 1] {
            check_hash_8(&bhp, &std::array::from_fn(|_| random(rng, len)), false);
        }
        for l in [0, 3, 7] {
            for (len, other) in [(max_len, max_len - 1), (1, 2), (2, 1), (max_len, max_len + 1), (100, 0)] {
                let mut inputs: [Vec<bool>; 8] = std::array::from_fn(|_| random(rng, len));
                inputs[l] = random(rng, other);
                check_hash_8(&bhp, &inputs, false);
            }
        }
    }

    #[test]
    fn test_hash_8_bhp256() {
        check_hash_8_lengths::<3, 57>("AleoBHP256", &mut TestRng::default());
    }

    #[test]
    fn test_hash_8_bhp512() {
        let rng = &mut TestRng::default();
        check_hash_8_lengths::<6, 43>("AleoBHP512", rng);
        check_hash_8_lengths::<6, 43>("LanesOther", rng);
    }

    #[test]
    fn test_hash_8_bhp768() {
        check_hash_8_lengths::<15, 23>("AleoBHP768", &mut TestRng::default());
    }

    #[test]
    fn test_hash_8_bhp1024() {
        check_hash_8_lengths::<8, 54>("AleoBHP1024", &mut TestRng::default());
    }

    /// An instance whose iteration holds less than one field element stays out of the lanes.
    #[test]
    fn test_hash_8_lanes_declines_a_small_instance() {
        let bhp = BHP::<Console, 1, 57>::setup("Small").unwrap();
        assert!(bhp.hash_8_lanes([[true; 5].as_slice(); 8]).is_none());
        assert!(bhp.lane_tables.get().is_none());
    }

    /// The lane tables exist only after a call that `hash_8_lanes` takes, and only where the lanes run.
    #[test]
    fn test_lane_tables_are_built_on_first_use() {
        let rng = &mut TestRng::default();
        let bhp = BHP512::<Console>::setup("LaneTables").unwrap();
        let input: Vec<bool> = (0..507).map(|_| bool::rand(rng)).collect();
        let long = vec![true; 523];
        assert!(bhp.lane_tables.get().is_none());

        bhp.hash(&input).unwrap();
        bhp.hash_8([&[]; 8]).unwrap();
        bhp.hash_8([&long; 8]).unwrap();
        let mut ragged = [input.as_slice(); 8];
        ragged[5] = &input[1..];
        bhp.hash_8(ragged).unwrap();
        assert!(bhp.lane_tables.get().is_none());

        bhp.hash_8([&input; 8]).unwrap();
        let tables = bhp.lane_tables.get().unwrap();
        assert_eq!(tables.is_some(), lanes_expected());
        // The domain fills 62 chunks: the 11 groups of the first window and 4 of the second.
        if let Some(tables) = tables {
            assert_eq!(tables.first_chunk, 59);
            assert_eq!(tables.groups.len(), 6 * 11 - 15);
            assert_eq!(tables.singles.len(), 6 * 43 - 59);
        }
        // An instance with tables equals one without, and a clone shares the tables.
        assert_eq!(bhp, BHP512::<Console>::setup("LaneTables").unwrap());
        assert!(Arc::ptr_eq(&bhp.lane_tables, &bhp.clone().lane_tables));
    }
}
