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
#[cfg(feature = "signature")]
use crate::Signature;

use std::{collections::HashMap, sync::Arc};

/// The serialized size of a compute key: the x-coordinates of `pk_sig` and `pr_sig`.
const COMPUTE_KEY_SIZE: usize = 64;

/// The number of verifications that ask for a key's `pk_sig` table before the cache builds it.
///
/// A table costs about as much to build as it saves over this many verifications.
const PK_SIG_TABLE_MIN_VERIFICATIONS: u32 = 4;

/// Compute keys decoded by earlier reads, keyed by their serialized bytes.
///
/// The cache holds only successful decodes, so a read through it returns the same compute key,
/// or the same error, as `ComputeKey::read_le_with_unchecked`.
#[derive(Clone, Debug)]
pub struct ComputeKeyCache<N: Network> {
    /// The decoded compute keys and what verification has derived from them.
    keys: HashMap<[u8; COMPUTE_KEY_SIZE], CacheEntry<N>>,
    /// The number of entries at which the cache is cleared before the next insert.
    capacity: usize,
}

/// A decoded compute key and what verification has derived from it.
#[derive(Clone, Debug)]
struct CacheEntry<N: Network> {
    /// The compute key. It holds `sk_prf` once a checked read has needed it.
    compute_key: ComputeKey<N>,
    /// The number of verifications that have asked for `pk_sig_table`.
    verifications: u32,
    /// The window table of `pk_sig`, built once `PK_SIG_TABLE_MIN_VERIFICATIONS` verifications have asked for it.
    pk_sig_table: Option<Arc<GroupWindowTable<N>>>,
}

impl<N: Network> Default for ComputeKeyCache<N> {
    /// Returns an empty cache that holds four committees of the maximum size.
    ///
    /// Reading blocks signed by one committee fills about one committee's worth of entries.
    /// The extra room lets a cache that is kept across many blocks survive committee changes
    /// without a clear. An entry with a `pk_sig` table takes about 50 KB, so a full cache stays under 10 MB on mainnet.
    fn default() -> Self {
        Self::new(4 * usize::from(N::LATEST_MAX_CERTIFICATES()))
    }
}

impl<N: Network> ComputeKeyCache<N> {
    /// Returns an empty cache that holds at most `capacity` compute keys.
    pub fn new(capacity: usize) -> Self {
        Self { keys: HashMap::new(), capacity }
    }

    /// Returns the number of cached compute keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns `true` if the cache holds no compute keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Reads a compute key as `ComputeKey::read_le_with_unchecked` does, decoding it only if
    /// this cache holds no earlier decode of the same bytes.
    pub fn read_compute_key<R: Read>(&mut self, mut reader: R, unchecked: bool) -> IoResult<ComputeKey<N>> {
        const { assert!(COMPUTE_KEY_SIZE == 2 * Field::<N>::SIZE_IN_BYTES) };
        let mut bytes = [0u8; COMPUTE_KEY_SIZE];
        let (pk_sig_bytes, pr_sig_bytes) = bytes.split_at_mut(COMPUTE_KEY_SIZE / 2);
        reader.read_exact(pk_sig_bytes)?;
        if let Err(eof) = reader.read_exact(pr_sig_bytes) {
            // The decoder rejects a bad `pk_sig` before it reads `pr_sig`.
            Group::<N>::read_le(&pk_sig_bytes[..])?;
            return Err(eof);
        }

        if let Some(entry) = self.keys.get_mut(&bytes) {
            let compute_key = &mut entry.compute_key;
            if unchecked {
                return Ok(ComputeKey { sk_prf: None, ..*compute_key });
            }
            if compute_key.sk_prf.is_none() {
                *compute_key = ComputeKey::try_from((compute_key.pk_sig, compute_key.pr_sig)).map_err(into_io_error)?;
            }
            return Ok(*compute_key);
        }

        let compute_key = ComputeKey::read_le_with_unchecked(&bytes[..], unchecked)?;
        if self.keys.len() >= self.capacity {
            tracing::warn!("Clearing the compute-key cache, which is full at {} keys", self.capacity);
            self.keys.clear();
        }
        self.keys.insert(bytes, CacheEntry { compute_key, verifications: 0, pk_sig_table: None });
        Ok(compute_key)
    }

    /// Counts a successful verification of a signature by `compute_key`, and builds the key's `pk_sig` table
    /// once enough verifications have been counted.
    ///
    /// Call it only once the data the signature covers has passed every other check, so that rejected data
    /// builds nothing. A compute key that no read through this cache returned is ignored.
    pub fn count_verification(&mut self, compute_key: &ComputeKey<N>) {
        let Some(entry) = Self::key_bytes(compute_key)
            .and_then(|bytes| self.keys.get_mut(&bytes))
            .filter(|entry| entry.compute_key == *compute_key)
        else {
            return;
        };
        if entry.pk_sig_table.is_none() {
            entry.verifications += 1;
            if entry.verifications >= PK_SIG_TABLE_MIN_VERIFICATIONS {
                entry.pk_sig_table = Some(Arc::new(GroupWindowTable::new(&entry.compute_key.pk_sig)));
            }
        }
    }

    /// Returns `true` if `count_verification` has built a `pk_sig` table for `compute_key`.
    pub fn has_pk_sig_table(&self, compute_key: &ComputeKey<N>) -> bool {
        self.entry(compute_key).is_some_and(|entry| entry.pk_sig_table.is_some())
    }

    /// Returns the entry of `compute_key`, if a read through this cache returned it.
    ///
    /// Compute keys with the same bytes can differ in the sign of `y` if one was built in memory without checks,
    /// so the entry must hold `compute_key` itself.
    fn entry(&self, compute_key: &ComputeKey<N>) -> Option<&CacheEntry<N>> {
        Self::key_bytes(compute_key)
            .and_then(|bytes| self.keys.get(&bytes))
            .filter(|entry| entry.compute_key == *compute_key)
    }

    /// Returns the serialized `compute_key`, which keys the cache.
    fn key_bytes(compute_key: &ComputeKey<N>) -> Option<[u8; COMPUTE_KEY_SIZE]> {
        let mut bytes = [0u8; COMPUTE_KEY_SIZE];
        compute_key.write_le(&mut bytes[..]).ok()?;
        Some(bytes)
    }
}

#[cfg(feature = "signature")]
impl<N: Network> ComputeKeyCache<N> {
    /// Returns the signer's address if `signature` is valid for `message`, and `None` otherwise,
    /// as `Signature::verify_and_recover_signer` does.
    ///
    /// The check uses what `count_verification` has derived for the signer's compute key.
    pub fn verify_and_recover_signer(&self, signature: &Signature<N>, message: &[Field<N>]) -> Option<Address<N>> {
        let pk_sig_table = self.entry(&signature.compute_key()).and_then(|entry| entry.pk_sig_table.as_deref());
        // A normalized address converts to affine, for hashing and comparison, without an inversion.
        let address = Address::new(signature.to_address().normalized());
        signature.verify_challenge(&address, message, pk_sig_table).then_some(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    use tracing_test::traced_test;

    type CurrentNetwork = MainnetV0;

    /// Returns the serialized compute keys of `num_keys` new accounts.
    fn sample_compute_key_bytes(num_keys: usize, rng: &mut TestRng) -> Vec<Vec<u8>> {
        (0..num_keys)
            .map(|_| {
                ComputeKey::<CurrentNetwork>::try_from(PrivateKey::new(rng).unwrap()).unwrap().to_bytes_le().unwrap()
            })
            .collect()
    }

    /// Asserts that a read through `cache` gives the same result as `ComputeKey::read_le_with_unchecked`.
    fn assert_matches_cold(cache: &mut ComputeKeyCache<CurrentNetwork>, bytes: &[u8], unchecked: bool) {
        let cold = ComputeKey::<CurrentNetwork>::read_le_with_unchecked(bytes, unchecked);
        let cached = cache.read_compute_key(bytes, unchecked);
        match (cold, cached) {
            // `ComputeKey` equality ignores `sk_prf`.
            (Ok(cold), Ok(cached)) => assert_eq!((cold, cold.sk_prf), (cached, cached.sk_prf)),
            (Err(cold), Err(cached)) => {
                assert_eq!(cold.kind(), cached.kind());
                assert_eq!(cold.to_string(), cached.to_string());
            }
            (cold, cached) => panic!("cold read {cold:?} and cached read {cached:?} disagree"),
        }
    }

    /// Returns an x-coordinate with no point on the curve, and one whose points lie outside the prime-order subgroup.
    fn sample_invalid_x_coordinates() -> (Vec<u8>, Vec<u8>) {
        let mut off_curve = None;
        let mut off_subgroup = None;
        for i in 1u64.. {
            let x = Field::<CurrentNetwork>::from_u64(i);
            match <CurrentNetwork as Environment>::Affine::pair_from_x_coordinate(*x) {
                None => off_curve = off_curve.or(Some(x)),
                Some(_) if Group::<CurrentNetwork>::from_x_coordinate(x).is_err() => {
                    off_subgroup = off_subgroup.or(Some(x))
                }
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
    }

    #[test]
    fn test_cached_reads_match_cold_reads() {
        let rng = &mut TestRng::default();
        let keys = sample_compute_key_bytes(5, rng);

        // Both mode orders, so each mode reads entries that the other mode inserted.
        for modes in [[false, true], [true, false]] {
            let mut cache = ComputeKeyCache::default();
            for unchecked in modes {
                for _ in 0..2 {
                    for bytes in &keys {
                        assert_matches_cold(&mut cache, bytes, unchecked);
                    }
                }
            }
            // One entry per key, whatever the modes that read it.
            assert_eq!(cache.len(), keys.len());
        }
    }

    #[test]
    fn test_read_consumes_only_the_compute_key() {
        let rng = &mut TestRng::default();
        let mut bytes = sample_compute_key_bytes(1, rng).remove(0);
        bytes.extend_from_slice(&[1, 2, 3]);
        let mut cache = ComputeKeyCache::<CurrentNetwork>::default();
        for _ in 0..2 {
            let mut reader = &bytes[..];
            cache.read_compute_key(&mut reader, false).unwrap();
            assert_eq!(reader, &[1, 2, 3]);
        }
    }

    #[test]
    #[traced_test]
    fn test_full_cache_clears() {
        let rng = &mut TestRng::default();
        let keys = sample_compute_key_bytes(3, rng);
        let mut cache = ComputeKeyCache::new(2);

        for bytes in &keys[..2] {
            assert_matches_cold(&mut cache, bytes, false);
        }
        assert!(!logs_contain("Clearing the compute-key cache"));
        assert_matches_cold(&mut cache, &keys[2], false);
        // The third insert found the cache full.
        assert_eq!(cache.len(), 1);
        assert!(logs_contain("Clearing the compute-key cache, which is full at 2 keys"));
        // A cleared key decodes the same again.
        assert_matches_cold(&mut cache, &keys[0], false);
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_pk_sig_table_is_built_after_enough_verifications() {
        let rng = &mut TestRng::default();
        let keys = sample_compute_key_bytes(2, rng);
        let mut cache = ComputeKeyCache::<CurrentNetwork>::default();
        let compute_key = cache.read_compute_key(&keys[0][..], false).unwrap();
        // A key the cache never read.
        let unread = ComputeKey::<CurrentNetwork>::read_le(&keys[1][..]).unwrap();

        for i in 1..=PK_SIG_TABLE_MIN_VERIFICATIONS {
            cache.count_verification(&compute_key);
            cache.count_verification(&unread);
            assert_eq!(cache.has_pk_sig_table(&compute_key), i == PK_SIG_TABLE_MIN_VERIFICATIONS);
        }
        assert_eq!(
            cache.entry(&compute_key).and_then(|entry| entry.pk_sig_table.as_deref()).map(GroupWindowTable::base),
            Some(compute_key.pk_sig())
        );
        assert_eq!(cache.len(), 1);

        // An unchecked read of the same bytes finds the same table.
        let unchecked = cache.read_compute_key(&keys[0][..], true).unwrap();
        assert!(cache.has_pk_sig_table(&unchecked));
    }

    #[test]
    fn test_cached_verification_matches_signature() {
        let rng = &mut TestRng::default();
        let private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let mut cache = ComputeKeyCache::<CurrentNetwork>::default();
        let compute_key_bytes = ComputeKey::try_from(&private_key).unwrap().to_bytes_le().unwrap();
        let compute_key = cache.read_compute_key(&compute_key_bytes[..], false).unwrap();

        for i in 0..2 * PK_SIG_TABLE_MIN_VERIFICATIONS {
            let message = [Field::rand(rng)];
            let signature = private_key.sign(&message, rng).unwrap();
            let expected = signature.verify_and_recover_signer(&message);
            assert!(expected.is_some());
            assert_eq!(cache.verify_and_recover_signer(&signature, &message), expected);
            assert_eq!(cache.verify_and_recover_signer(&signature, &[Field::rand(rng)]), None);
            assert_eq!(cache.has_pk_sig_table(&compute_key), i >= PK_SIG_TABLE_MIN_VERIFICATIONS);
            cache.count_verification(&compute_key);
        }
    }

    #[test]
    fn test_invalid_compute_keys_are_rejected() {
        let rng = &mut TestRng::default();
        let good = sample_compute_key_bytes(1, rng).remove(0);
        let (off_curve, off_subgroup) = sample_invalid_x_coordinates();
        let non_canonical = [0xFF; COMPUTE_KEY_SIZE / 2];

        let mut invalid = Vec::new();
        for x in [&off_curve[..], &off_subgroup[..], &non_canonical[..]] {
            // A bad `pk_sig`, and a bad `pr_sig` after a good `pk_sig`.
            for offset in [0, COMPUTE_KEY_SIZE / 2] {
                let mut bytes = good.clone();
                bytes[offset..offset + x.len()].copy_from_slice(x);
                invalid.push(bytes);
            }
            // A bad `pk_sig` with `pr_sig` cut short.
            let mut bytes = good[..COMPUTE_KEY_SIZE - 1].to_vec();
            bytes[..x.len()].copy_from_slice(x);
            invalid.push(bytes);
        }
        for end in [0, 1, COMPUTE_KEY_SIZE / 2 - 1, COMPUTE_KEY_SIZE / 2, COMPUTE_KEY_SIZE - 1] {
            invalid.push(good[..end].to_vec());
        }

        for unchecked in [false, true] {
            let mut cache = ComputeKeyCache::default();
            assert_matches_cold(&mut cache, &good, unchecked);
            for bytes in &invalid {
                assert!(ComputeKey::<CurrentNetwork>::read_le_with_unchecked(&bytes[..], unchecked).is_err());
                for _ in 0..2 {
                    assert_matches_cold(&mut cache, bytes, unchecked);
                }
            }
            // Only the good key is cached, and it still reads the same.
            assert_eq!(cache.len(), 1);
            assert_matches_cold(&mut cache, &good, unchecked);
        }
    }
}
