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

use console::{account::ComputeKey, types::Scalar};

use lru::LruCache;
use parking_lot::Mutex;
use std::{
    any::{Any, TypeId},
    collections::HashMap,
    num::NonZeroUsize,
    sync::LazyLock,
};

/// The number of decoded compute keys kept per network: a few full committees, in both read modes.
// 256 is non-zero, so the `unwrap` cannot panic.
const CAPACITY: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// The serialized size of a compute key: two x-coordinates.
const COMPUTE_KEY_SIZE: usize = 64;

/// A cache key: whether the read is unchecked, and the exact compute-key bytes.
type CacheKey = (bool, [u8; COMPUTE_KEY_SIZE]);

/// One `LruCache<CacheKey, ComputeKey<N>>` per network, stored under `TypeId::of::<N>()`.
type Caches = Mutex<HashMap<TypeId, Box<dyn Any + Send>>>;

/// The process-wide compute-key caches.
static CACHES: LazyLock<Caches> = LazyLock::new(Default::default);

/// Reads a signature as `Signature::read_le_with_unchecked` does, reusing recently decoded compute keys.
pub fn read_signature_cached<N: Network>(bytes: &[u8], unchecked: bool) -> IoResult<Signature<N>> {
    read_signature(&CACHES, CAPACITY, bytes, unchecked)
}

/// Reads a signature, looking up its compute key in `caches`.
fn read_signature<N: Network>(
    caches: &Caches,
    capacity: NonZeroUsize,
    mut bytes: &[u8],
    unchecked: bool,
) -> IoResult<Signature<N>> {
    // This must stay in step with `Signature::read_le_with_unchecked`.
    let challenge = Scalar::new(FromBytes::read_le(&mut bytes)?);
    let response = Scalar::new(FromBytes::read_le(&mut bytes)?);
    let compute_key = read_compute_key(caches, capacity, bytes, unchecked)?;
    Ok(Signature::from((challenge, response, compute_key)))
}

/// Reads a compute key, decoding it only if `caches` holds no earlier decode of the same bytes in the same mode.
fn read_compute_key<N: Network>(
    caches: &Caches,
    capacity: NonZeroUsize,
    bytes: &[u8],
    unchecked: bool,
) -> IoResult<ComputeKey<N>> {
    // A short input fails in the decoder, exactly as without the cache.
    let Some(key_bytes) = bytes.first_chunk::<COMPUTE_KEY_SIZE>() else {
        return ComputeKey::read_le_with_unchecked(bytes, unchecked);
    };
    let key = (unchecked, *key_bytes);
    if let Some(compute_key) = with_cache::<N, _>(caches, capacity, |cache| cache.get(&key).copied()) {
        return Ok(compute_key);
    }
    // The decode runs outside the lock. Concurrent misses on one key insert the same value twice.
    let compute_key = ComputeKey::read_le_with_unchecked(&key_bytes[..], unchecked)?;
    with_cache::<N, _>(caches, capacity, |cache| cache.put(key, compute_key));
    Ok(compute_key)
}

/// Runs `f` on the cache for network `N`, creating the cache if needed.
fn with_cache<N: Network, T>(
    caches: &Caches,
    capacity: NonZeroUsize,
    f: impl FnOnce(&mut LruCache<CacheKey, ComputeKey<N>>) -> T,
) -> T {
    let mut caches = caches.lock();
    let cache =
        caches.entry(TypeId::of::<N>()).or_insert_with(|| Box::new(LruCache::<CacheKey, ComputeKey<N>>::new(capacity)));
    // The entry for `TypeId::of::<N>()` is only ever created with this type, so the `unwrap` cannot panic.
    f(cache.downcast_mut().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::{
        account::PrivateKey,
        network::{MainnetV0, TestnetV0},
        types::Group,
    };

    type CurrentNetwork = MainnetV0;

    /// Returns a cache registry that no other test shares.
    fn new_caches() -> Caches {
        Mutex::new(HashMap::new())
    }

    /// Returns the number of entries in the cache for network `N`.
    fn cache_len<N: Network>(caches: &Caches) -> usize {
        with_cache::<N, _>(caches, CAPACITY, |cache| cache.len())
    }

    /// Returns `true` if the cache for network `N` holds the compute key of `bytes` in the given mode.
    fn is_cached<N: Network>(caches: &Caches, bytes: &[u8], unchecked: bool) -> bool {
        let key_bytes = *bytes.last_chunk::<COMPUTE_KEY_SIZE>().unwrap();
        with_cache::<N, _>(caches, CAPACITY, |cache| cache.contains(&(unchecked, key_bytes)))
    }

    /// Returns the serialized signatures of `num_keys` keys over `num_messages` messages each.
    fn sample_signature_bytes<N: Network>(num_keys: usize, num_messages: usize, rng: &mut TestRng) -> Vec<Vec<u8>> {
        let mut signatures = Vec::with_capacity(num_keys * num_messages);
        for _ in 0..num_keys {
            let private_key = PrivateKey::<N>::new(rng).unwrap();
            for _ in 0..num_messages {
                let signature = private_key.sign(&[Field::rand(rng)], rng).unwrap();
                signatures.push(signature.to_bytes_le().unwrap());
            }
        }
        signatures
    }

    /// Asserts that a cached read gives the same result as `Signature::read_le_with_unchecked`.
    fn assert_matches_cold<N: Network>(caches: &Caches, capacity: NonZeroUsize, bytes: &[u8], unchecked: bool) {
        let cold = Signature::<N>::read_le_with_unchecked(bytes, unchecked);
        let cached = read_signature::<N>(caches, capacity, bytes, unchecked);
        match (cold, cached) {
            (Ok(cold), Ok(cached)) => {
                assert_eq!(cold, cached);
                // `ComputeKey` equality ignores `sk_prf`, so compare the full field set.
                assert_eq!(format!("{:?}", cold.compute_key()), format!("{:?}", cached.compute_key()));
                assert_eq!(cold.to_bytes_le().unwrap(), cached.to_bytes_le().unwrap());
            }
            (Err(cold), Err(cached)) => {
                assert_eq!(cold.kind(), cached.kind());
                assert_eq!(cold.to_string(), cached.to_string());
            }
            (cold, cached) => panic!("cold read {cold:?} and cached read {cached:?} disagree"),
        }
    }

    /// Returns the bytes of `signature` with the x-coordinate at `offset` in its compute key set to `x`.
    fn with_compute_key_x(signature: &[u8], offset: usize, x: &[u8]) -> Vec<u8> {
        let start = signature.len() - COMPUTE_KEY_SIZE + offset;
        let mut bytes = signature.to_vec();
        bytes[start..start + x.len()].copy_from_slice(x);
        bytes
    }

    /// Returns an x-coordinate with no point on the curve, and one whose points lie outside the prime-order subgroup.
    fn sample_invalid_x_coordinates<N: Network>() -> (Vec<u8>, Vec<u8>) {
        let mut off_curve = None;
        let mut off_subgroup = None;
        for i in 1u64.. {
            let x = Field::<N>::from_u64(i);
            match N::Affine::pair_from_x_coordinate(*x) {
                None => off_curve = off_curve.or(Some(x)),
                Some(_) if Group::<N>::from_x_coordinate(x).is_err() => off_subgroup = off_subgroup.or(Some(x)),
                Some(_) => (),
            }
            if let (Some(off_curve), Some(off_subgroup)) = (off_curve, off_subgroup) {
                return (off_curve.to_bytes_le().unwrap(), off_subgroup.to_bytes_le().unwrap());
            }
        }
        unreachable!()
    }

    #[test]
    fn test_compute_key_size() {
        assert_eq!(ComputeKey::<CurrentNetwork>::size_in_bytes(), COMPUTE_KEY_SIZE);
        assert_eq!(Signature::<CurrentNetwork>::size_in_bytes(), 64 + COMPUTE_KEY_SIZE);
    }

    #[test]
    fn test_cached_reads_match_cold_reads() {
        let rng = &mut TestRng::default();
        let signatures = sample_signature_bytes::<CurrentNetwork>(5, 3, rng);

        // Both mode orders, so neither mode can be served an entry decoded in the other.
        for modes in [[false, true], [true, false]] {
            let caches = new_caches();
            for unchecked in modes {
                // The first pass decodes and the second pass hits.
                for _ in 0..2 {
                    for bytes in &signatures {
                        assert_matches_cold::<CurrentNetwork>(&caches, CAPACITY, bytes, unchecked);
                        assert!(is_cached::<CurrentNetwork>(&caches, bytes, unchecked));
                    }
                }
            }
            // One entry per key per mode.
            assert_eq!(cache_len::<CurrentNetwork>(&caches), 2 * 5);
        }
    }

    #[test]
    fn test_networks_do_not_share_entries() {
        let rng = &mut TestRng::default();
        let mainnet = sample_signature_bytes::<MainnetV0>(1, 1, rng);
        let caches = new_caches();
        assert_matches_cold::<MainnetV0>(&caches, CAPACITY, &mainnet[0], false);
        assert_eq!(cache_len::<MainnetV0>(&caches), 1);
        assert_eq!(cache_len::<TestnetV0>(&caches), 0);
        // The same bytes read for another network decode for that network.
        assert_matches_cold::<TestnetV0>(&caches, CAPACITY, &mainnet[0], false);
        assert_eq!(cache_len::<TestnetV0>(&caches), 1);
    }

    #[test]
    fn test_full_cache_evicts_least_recently_used() {
        let rng = &mut TestRng::default();
        let signatures = sample_signature_bytes::<CurrentNetwork>(3, 1, rng);
        let (a, b, c) = (&signatures[0], &signatures[1], &signatures[2]);
        let capacity = NonZeroUsize::new(2).unwrap();
        let caches = new_caches();

        for bytes in [a, b, a, c] {
            assert_matches_cold::<CurrentNetwork>(&caches, capacity, bytes, false);
        }
        // `b` is the least recently used when `c` arrives.
        assert_eq!(cache_len::<CurrentNetwork>(&caches), 2);
        assert!(is_cached::<CurrentNetwork>(&caches, a, false));
        assert!(!is_cached::<CurrentNetwork>(&caches, b, false));
        assert!(is_cached::<CurrentNetwork>(&caches, c, false));

        // An evicted key decodes again, the same as before.
        assert_matches_cold::<CurrentNetwork>(&caches, capacity, b, false);
        assert!(is_cached::<CurrentNetwork>(&caches, b, false));
        assert_eq!(cache_len::<CurrentNetwork>(&caches), 2);
    }

    #[test]
    fn test_invalid_compute_keys_are_rejected() {
        let rng = &mut TestRng::default();
        let signatures = sample_signature_bytes::<CurrentNetwork>(1, 2, rng);
        let (good, other) = (&signatures[0], &signatures[1]);
        let (off_curve, off_subgroup) = sample_invalid_x_coordinates::<CurrentNetwork>();
        let non_canonical = [0xFF; COMPUTE_KEY_SIZE / 2];

        let mut invalid = Vec::new();
        for x in [&off_curve[..], &off_subgroup[..], &non_canonical[..]] {
            // A bad `pk_sig`, and a bad `pr_sig` after a good `pk_sig`.
            invalid.push(with_compute_key_x(good, 0, x));
            invalid.push(with_compute_key_x(good, COMPUTE_KEY_SIZE / 2, x));
        }
        // Truncated inputs.
        invalid.push(good[..good.len() - 1].to_vec());
        invalid.push(good[..good.len() - COMPUTE_KEY_SIZE / 2].to_vec());
        invalid.push(with_compute_key_x(good, 0, &off_curve)[..good.len() - 1].to_vec());

        for unchecked in [false, true] {
            let caches = new_caches();
            // A good key first, then each bad key twice.
            assert_matches_cold::<CurrentNetwork>(&caches, CAPACITY, good, unchecked);
            for bytes in &invalid {
                assert!(Signature::<CurrentNetwork>::read_le_with_unchecked(&bytes[..], unchecked).is_err());
                for _ in 0..2 {
                    assert_matches_cold::<CurrentNetwork>(&caches, CAPACITY, bytes, unchecked);
                }
            }
            // Only the good key is cached, and it still reads the same.
            assert_eq!(cache_len::<CurrentNetwork>(&caches), 1);
            assert_matches_cold::<CurrentNetwork>(&caches, CAPACITY, other, unchecked);
            assert_eq!(cache_len::<CurrentNetwork>(&caches), 1);
        }
    }

    #[test]
    fn test_concurrent_reads_match_cold_reads() {
        let rng = &mut TestRng::default();
        let mut signatures = sample_signature_bytes::<CurrentNetwork>(8, 4, rng);
        let (off_curve, _) = sample_invalid_x_coordinates::<CurrentNetwork>();
        signatures.push(with_compute_key_x(&signatures[0], 0, &off_curve));
        let small = NonZeroUsize::new(4).unwrap();
        let caches = new_caches();

        // Each thread walks the signatures from a different start, so threads hit, miss, and evict together.
        std::thread::scope(|scope| {
            for start in 0..8 {
                let (signatures, caches) = (&signatures, &caches);
                scope.spawn(move || {
                    for i in 0..4 * signatures.len() {
                        let bytes = &signatures[(start + i) % signatures.len()];
                        let unchecked = (start + i) % 3 == 0;
                        // A small private cache that evicts constantly, and the process-wide cache.
                        assert_matches_cold::<CurrentNetwork>(caches, small, bytes, unchecked);
                        assert_matches_cold::<CurrentNetwork>(&CACHES, CAPACITY, bytes, unchecked);
                    }
                });
            }
        });
        assert!(cache_len::<CurrentNetwork>(&caches) <= small.get());
    }
}
