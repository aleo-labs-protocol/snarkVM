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

use core::convert::Infallible;
use rand::{
    Rng,
    RngExt,
    SeedableRng,
    TryCryptoRng,
    TryRng,
    distr::{Distribution, StandardUniform},
};
use rand_chacha::ChaCha20Rng;
use rand_xorshift::XorShiftRng;

/// A trait for a uniform random number generator.
pub trait Uniform: Sized {
    /// Samples a random value from a uniform distribution.
    fn rand<R: RngExt + ?Sized>(rng: &mut R) -> Self;
}

impl<T> Uniform for T
where
    StandardUniform: Distribution<T>,
{
    #[inline]
    fn rand<R: RngExt + ?Sized>(rng: &mut R) -> Self {
        rng.random()
    }
}

// The rand 0.8 default implementation.
pub trait UniformExt: Uniform {
    /// Generates a random Option<Self> (50/50 chance of Some or None)
    fn rand_option<R: Rng + ?Sized>(rng: &mut R) -> Option<Self> {
        if rng.random() { Some(Self::rand(rng)) } else { None }
    }
}

// Blanket implement it for anything that already implements Uniform
impl<T: Uniform> UniformExt for T {}

/// A fast RNG used **solely** for testing and benchmarking, **not** for any real world purposes.
///
/// Its output for a seed may change between versions. Use [`FixedRng`] where it must not.
pub struct TestRng {
    seed: u64,
    rng: XorShiftRng,
    calls: usize,
}

impl Default for TestRng {
    fn default() -> Self {
        // Obtain the initial seed using entropy provided by the OS.
        let seed: u64 = rand::random();

        // Use it as the basis for the underlying Rng.
        Self::fixed(seed)
    }
}

impl TestRng {
    pub fn fixed(seed: u64) -> Self {
        // Print the seed, so it's displayed if any of the tests using `test_rng` fails.
        println!("\nInitializing 'TestRng' with seed '{seed}'\n");

        // Use the seed to initialize a fast, non-cryptographic Rng.
        Self::from_seed(seed)
    }

    // This is the preferred method to use once the main instance of TestRng had already
    // been initialized in a test or benchmark and an auxiliary one is desired without
    // spamming the stdout.
    pub fn from_seed(seed: u64) -> Self {
        Self { seed, rng: XorShiftRng::seed_from_u64(seed), calls: 0 }
    }

    /// Returns a randomly-sampled `String`, given the maximum size in bytes and an RNG.
    ///
    /// Some of the snarkVM internal tests involve the random generation of strings,
    /// which are parsed and tested against the original ones. However, since the string parser
    /// rejects certain characters, if those characters are randomly generated, the tests fail.
    ///
    /// To prevent these failures, as we randomly generate the characters,
    /// we ensure that they are not among the ones rejected by the parser;
    /// if they are, we adjust them to be allowed characters.
    ///
    /// Note that the randomness of the characters is strictly for **testing** purposes;
    /// also note that the disallowed characters are a small fraction of the total set of characters,
    /// and thus the adjustments rarely occur.
    pub fn next_string(&mut self, max_bytes: u32, is_fixed_size: bool) -> String {
        /// Adjust an unsafe character.
        ///
        /// As our parser rejects certain potentially unsafe characters (see `Sanitizer::parse_safe_char`),
        /// we need to avoid generating them randomly. This function acts as an adjusting filter:
        /// it changes an unsafe character to `'0'` (other choices are possible), and leaves other
        /// characters unchanged.
        fn adjust_unsafe_char(ch: char) -> char {
            let code = ch as u32;
            if code < 9
                || code == 11
                || code == 12
                || (14..=31).contains(&code)
                || code == 127
                || (0x202a..=0x202e).contains(&code)
                || (0x2066..=0x2069).contains(&code)
            {
                '0'
            } else {
                ch
            }
        }

        /// Adjust a backslash and a double quote.
        ///
        /// Aside from the characters rejected through the function [adjust_unsafe_char],
        /// the syntax of strings allows backslash and double quotes only in certain circumstances:
        /// backslash is used to introduce an escape, and there are constraints on what can occur
        /// after a backslash; double quotes is only used in escaped form just after a backslash.
        ///
        /// If we randomly sample characters, we may end up generating backslashes with
        /// malformed escape syntax, or double quotes not preceded by backslash. Thus,
        /// we also adjust backslashes and double quotes as we randomly sample characters.
        ///
        /// Note that, this way, we do not test the parsing of any escape sequences;
        /// to do that, we would need to reify the possible elements of strings,
        /// namely characters and escapes, and randomly generate such elements.
        fn adjust_backslash_and_doublequote(ch: char) -> char {
            if ch == '\\' || ch == '\"' { '0' } else { ch }
        }

        let range = match is_fixed_size {
            true => 0..max_bytes,
            false => 0..self.random_range(0..max_bytes),
        };

        range.map(|_| self.random::<char>()).map(adjust_unsafe_char).map(adjust_backslash_and_doublequote).collect()
    }
}

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.calls += 1;
        Ok(self.rng.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.calls += 1;
        Ok(self.rng.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.calls += 1;
        self.rng.fill_bytes(dest);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

impl Drop for TestRng {
    fn drop(&mut self) {
        println!("Called TestRng with seed {} {} times", self.seed, self.calls);
    }
}

/// A ChaCha20 RNG whose output for a given seed is the same on every version and platform.
///
/// Tools whose runs must be reproducible, such as the circuit key setup, use it.
/// Its output for a seed must never change. Values sampled through `rand`'s
/// distributions can still change when `rand` does.
pub struct FixedRng(ChaCha20Rng);

impl FixedRng {
    /// Initializes the RNG with the given seed.
    pub fn new(seed: [u8; 32]) -> Self {
        Self(ChaCha20Rng::from_seed(seed))
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl TryCryptoRng for FixedRng {}

/// This impl is Lemire's method with approximate zone. It reproduces rand 0.8's
/// `rng.gen_range(low..=high)` for `usize` on 64-bit. It mustn't be modified
/// to maintain backwards compatibility. It is a direct reimplementation of
/// `sample_single_inclusive` for a concrete type (`usize`) an inlined widening multiply
/// from https://github.com/rust-random/rand/blob/937320c/src/distributions/uniform.rs.
pub fn gen_range_inclusive_legacy(low: usize, high: usize, rng: &mut impl Rng) -> usize {
    debug_assert!(low <= high);

    let range = high.wrapping_sub(low).wrapping_add(1);
    // The range is 0..=usize::MAX.
    if range == 0 {
        return rng.random::<u64>() as usize;
    }

    // Approximate zone: conservative but avoids division.
    let zone = (range << range.leading_zeros()).wrapping_sub(1);

    loop {
        let v = rng.next_u64() as usize;
        // Widening multiply: v * range as u128, split into (hi, lo).
        let wide = (v as u128) * (range as u128);
        let hi = (wide >> 64) as usize;
        let lo = wide as usize;
        if lo <= zone {
            return low.wrapping_add(hi);
        }
    }
}

/// This impl reproduces rand 0.8's `slice.choose_weighted(rng, weight_fn)` for u16 weights.
/// It mustn't be modified to maintain backwards compatibility. It is a direct, "collapsed"
/// reimplementation of `WeightedIndex::new(weights).sample(rng)` specifically for `u16` weights
/// from https://github.com/rust-random/rand/blob/937320c/src/distributions/weighted_index.rs.
pub fn choose_weighted_legacy<'a, T, R: Rng>(slice: &'a [T], weight_fn: impl Fn(&T) -> u16, rng: &mut R) -> &'a T {
    // WeightedIndex::new.
    let mut iter = slice.iter();
    let first = iter.next().unwrap();
    let mut total: u16 = weight_fn(first);
    let mut cumulative: Vec<u16> = Vec::with_capacity(slice.len() - 1);
    for item in iter {
        cumulative.push(total);
        total += weight_fn(item);
    }
    assert!(total > 0);

    // Uniform::new(0u16, total) -> new_inclusive(0, total - 1)
    // range as u16, then promoted to u32 for zone math.
    let range = total as u32;
    let ints_to_reject = (u32::MAX - range + 1) % range;
    let zone = u32::MAX - ints_to_reject;

    // Uniform::sample (exact Lemire, u32 sample space).
    let chosen: u16 = loop {
        let v = rng.next_u32();
        let wide = (v as u64) * (range as u64);
        let hi = (wide >> 32) as u32;
        let lo = wide as u32;
        if lo <= zone {
            break hi as u16;
        }
    };

    // Binary search (partition_point).
    let idx = cumulative.partition_point(|w| *w <= chosen);
    &slice[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ChaCha20 with an all-zero key and nonce, from test vectors 1 and 2 of
    // https://tools.ietf.org/html/draft-nir-cfrg-chacha20-poly1305-04.
    const FIRST_BLOCK: [u32; 16] = [
        0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b, 0x7c5941da,
        0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
    ];
    const SECOND_BLOCK_START: u32 = 0xbee7079f;

    #[test]
    fn test_fixed_rng_next_u32() {
        let mut rng = FixedRng::new([0u8; 32]);
        for expected in FIRST_BLOCK {
            assert_eq!(rng.next_u32(), expected);
        }
        assert_eq!(rng.next_u32(), SECOND_BLOCK_START);
    }

    #[test]
    fn test_fixed_rng_next_u64() {
        let mut rng = FixedRng::new([0u8; 32]);
        for pair in FIRST_BLOCK.chunks_exact(2) {
            assert_eq!(rng.next_u64(), (pair[1] as u64) << 32 | pair[0] as u64);
        }
    }

    #[test]
    fn test_fixed_rng_fill_bytes() {
        let mut rng = FixedRng::new([0u8; 32]);
        let mut bytes = [0u8; 68];
        rng.fill_bytes(&mut bytes);
        let expected = FIRST_BLOCK.into_iter().chain([SECOND_BLOCK_START]).flat_map(u32::to_le_bytes);
        assert!(bytes.into_iter().eq(expected));
    }
}
