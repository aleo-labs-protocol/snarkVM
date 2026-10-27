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
use crate::errors::ParameterError;
use snarkvm_curves::traits::{PairingCurve, PairingEngine};
use snarkvm_utilities::CanonicalDeserialize;

use anyhow::{Result, anyhow, bail, ensure};
#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{self, BufReader, Read},
    ops::Range,
    sync::Arc,
};

#[cfg(all(feature = "no-embedded-srs", not(feature = "filesystem"), not(feature = "wasm")))]
compile_error!("`no-embedded-srs` needs `filesystem` or `wasm` to load the powers that are not embedded");

const NUM_POWERS_15: usize = 1 << 15;
const NUM_POWERS_16: usize = 1 << 16;
const NUM_POWERS_17: usize = 1 << 17;
const NUM_POWERS_18: usize = 1 << 18;
const NUM_POWERS_19: usize = 1 << 19;
const NUM_POWERS_20: usize = 1 << 20;
const NUM_POWERS_21: usize = 1 << 21;
const NUM_POWERS_22: usize = 1 << 22;
const NUM_POWERS_23: usize = 1 << 23;
const NUM_POWERS_24: usize = 1 << 24;
const NUM_POWERS_25: usize = 1 << 25;
// TODO (nkls): restore on CI.
// The SRS is only used for proving and we don't currently support provers of
// this size. When a users wants to create a proof, they load the appropriate
// powers for the circuit in `batch_circuit_setup` which calls `max_degree`
// based on the domain size.
#[cfg(feature = "large_params")]
const NUM_POWERS_26: usize = 1 << 26;
#[cfg(feature = "large_params")]
const NUM_POWERS_27: usize = 1 << 27;
const NUM_POWERS_28: usize = 1 << 28;

/// The maximum degree supported by the SRS.
pub const MAX_NUM_POWERS: usize = NUM_POWERS_28;

lazy_static::lazy_static! {
    static ref POWERS_OF_BETA_G_15: Vec<u8> = Degree15::load_bytes().expect("Failed to load powers of beta in universal SRS");
    static ref SHIFTED_POWERS_OF_BETA_G_15: Vec<u8> = ShiftedDegree15::load_bytes().expect("Failed to load powers of beta in universal SRS");
    static ref POWERS_OF_BETA_GAMMA_G: Vec<u8> = Gamma::load_bytes().expect("Failed to load powers of beta wrt gamma * G in universal SRS");
    static ref NEG_POWERS_OF_BETA_H: Vec<u8> = NegBeta::load_bytes().expect("Failed to load negative powers of beta in universal SRS");
    static ref BETA_H: Vec<u8> = BetaH::load_bytes().expect("Failed to load negative powers of beta in universal SRS");
}

/// One SRS degree file. The prefix file of `num_powers` holds the powers
/// `num_powers / 2..num_powers`, and the shifted one the powers
/// `MAX_NUM_POWERS - num_powers..MAX_NUM_POWERS - num_powers / 2`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PowersFile {
    shifted: bool,
    num_powers: usize,
    name: String,
    checksum: String,
    size: usize,
}

impl PowersFile {
    fn new(shifted: bool, num_powers: usize) -> Result<Self> {
        let metadata = match (shifted, num_powers) {
            (false, NUM_POWERS_16) => Degree16::METADATA,
            (false, NUM_POWERS_17) => Degree17::METADATA,
            (false, NUM_POWERS_18) => Degree18::METADATA,
            (false, NUM_POWERS_19) => Degree19::METADATA,
            (false, NUM_POWERS_20) => Degree20::METADATA,
            (false, NUM_POWERS_21) => Degree21::METADATA,
            (false, NUM_POWERS_22) => Degree22::METADATA,
            (false, NUM_POWERS_23) => Degree23::METADATA,
            (false, NUM_POWERS_24) => Degree24::METADATA,
            (false, NUM_POWERS_25) => Degree25::METADATA,
            // TODO (nkls): restore on CI.
            #[cfg(feature = "large_params")]
            (false, NUM_POWERS_26) => Degree26::METADATA,
            #[cfg(feature = "large_params")]
            (false, NUM_POWERS_27) => Degree27::METADATA,
            #[cfg(feature = "large_params")]
            (false, NUM_POWERS_28) => Degree28::METADATA,
            #[cfg(feature = "no-embedded-srs")]
            (true, NUM_POWERS_16) => ShiftedDegree16::METADATA,
            (true, NUM_POWERS_17) => ShiftedDegree17::METADATA,
            (true, NUM_POWERS_18) => ShiftedDegree18::METADATA,
            (true, NUM_POWERS_19) => ShiftedDegree19::METADATA,
            (true, NUM_POWERS_20) => ShiftedDegree20::METADATA,
            (true, NUM_POWERS_21) => ShiftedDegree21::METADATA,
            (true, NUM_POWERS_22) => ShiftedDegree22::METADATA,
            (true, NUM_POWERS_23) => ShiftedDegree23::METADATA,
            (true, NUM_POWERS_24) => ShiftedDegree24::METADATA,
            (true, NUM_POWERS_25) => ShiftedDegree25::METADATA,
            // TODO (nkls): restore on CI.
            #[cfg(feature = "large_params")]
            (true, NUM_POWERS_26) => ShiftedDegree26::METADATA,
            #[cfg(feature = "large_params")]
            (true, NUM_POWERS_27) => ShiftedDegree27::METADATA,
            _ => bail!("Cannot download an invalid degree of '{num_powers}'"),
        };
        let metadata: serde_json::Value = serde_json::from_str(metadata)?;
        let checksum = metadata["checksum"].as_str().ok_or_else(|| anyhow!("Failed to parse checksum"))?.to_string();
        let size = metadata["size"].as_u64().ok_or_else(|| anyhow!("Failed to retrieve the file size"))? as usize;
        let prefix = if shifted { "shifted-" } else { "" };
        let name = format!("{prefix}powers-of-beta-{}.usrs.{}", num_powers.trailing_zeros(), &checksum[..7]);
        Ok(Self { shifted, num_powers, name, checksum, size })
    }

    /// The name snarkVM fetches the file by.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The SHA-256 of the file, in hex.
    pub fn checksum(&self) -> &str {
        &self.checksum
    }

    /// The size of the file in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Whether the file holds shifted powers, which grow downward from
    /// `MAX_NUM_POWERS`, rather than prefix powers, which grow upward from 0.
    pub fn shifted(&self) -> bool {
        self.shifted
    }

    /// The number of powers on the file's side once it is added. The file
    /// holds the upper half of them, counted from its side's end.
    pub fn num_powers(&self) -> usize {
        self.num_powers
    }

    /// Reads the length-prefixed powers in the file, rejecting any other number of them.
    fn read_powers<E: PairingEngine>(&self, mut reader: impl Read) -> Result<Vec<E::G1Affine>> {
        let expected = self.num_powers / 2;
        let len = u64::deserialize_uncompressed_unchecked(&mut reader)?;
        ensure!(len == expected as u64, "{} holds {len} powers, not {expected}", self.name());
        let mut powers = Vec::with_capacity(expected);
        for _ in 0..expected {
            powers.push(E::G1Affine::deserialize_uncompressed_unchecked(&mut reader)?);
        }
        Ok(powers)
    }

    /// Reads the powers in the file from `reader`, rejecting it unless it has the
    /// file's size and checksum.
    fn read_checked_powers<E: PairingEngine>(&self, reader: impl Read) -> Result<Vec<E::G1Affine>> {
        let size = self.size;
        let mut hashed = Sha256Reader { reader: reader.take(size as u64 + 1), hasher: Sha256::new(), len: 0 };
        let mut buffered = BufReader::new(&mut hashed);
        let powers = self.read_powers::<E>(&mut buffered);
        io::copy(&mut buffered, &mut io::sink())?;
        ensure!(hashed.len == size, ParameterError::SizeMismatch(size, hashed.len));
        let checksum = hex::encode(hashed.hasher.finalize());
        ensure!(checksum == self.checksum, ParameterError::ChecksumMismatch(self.checksum.clone(), checksum));
        powers
    }
}

/// Hashes and counts the bytes read through it.
struct Sha256Reader<R> {
    reader: R,
    hasher: Sha256,
    len: usize,
}

impl<R: Read> Read for Sha256Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.reader.read(buf)?;
        self.hasher.update(&buf[..len]);
        self.len += len;
        Ok(len)
    }
}

/// Loads `file` as `load()` does, through the `Degree*` and `ShiftedDegree*`
/// `load_bytes`. With `wasm`, it fetches the file into memory. Otherwise, it
/// reads `~/.aleo/resources`, else fetches the file from the remote parameter
/// URLs and stores it there. The bytes have the file's size and checksum.
#[cfg(any(feature = "filesystem", feature = "wasm"))]
pub fn default_load_powers_file_sync(file: &PowersFile) -> Result<Vec<u8>> {
    Ok(match (file.shifted, file.num_powers) {
        (false, NUM_POWERS_16) => Degree16::load_bytes()?,
        (false, NUM_POWERS_17) => Degree17::load_bytes()?,
        (false, NUM_POWERS_18) => Degree18::load_bytes()?,
        (false, NUM_POWERS_19) => Degree19::load_bytes()?,
        (false, NUM_POWERS_20) => Degree20::load_bytes()?,
        (false, NUM_POWERS_21) => Degree21::load_bytes()?,
        (false, NUM_POWERS_22) => Degree22::load_bytes()?,
        (false, NUM_POWERS_23) => Degree23::load_bytes()?,
        (false, NUM_POWERS_24) => Degree24::load_bytes()?,
        (false, NUM_POWERS_25) => Degree25::load_bytes()?,
        // TODO (nkls): restore on CI.
        #[cfg(feature = "large_params")]
        (false, NUM_POWERS_26) => Degree26::load_bytes()?,
        #[cfg(feature = "large_params")]
        (false, NUM_POWERS_27) => Degree27::load_bytes()?,
        #[cfg(feature = "large_params")]
        (false, NUM_POWERS_28) => Degree28::load_bytes()?,
        #[cfg(feature = "no-embedded-srs")]
        (true, NUM_POWERS_16) => ShiftedDegree16::load_bytes()?,
        (true, NUM_POWERS_17) => ShiftedDegree17::load_bytes()?,
        (true, NUM_POWERS_18) => ShiftedDegree18::load_bytes()?,
        (true, NUM_POWERS_19) => ShiftedDegree19::load_bytes()?,
        (true, NUM_POWERS_20) => ShiftedDegree20::load_bytes()?,
        (true, NUM_POWERS_21) => ShiftedDegree21::load_bytes()?,
        (true, NUM_POWERS_22) => ShiftedDegree22::load_bytes()?,
        (true, NUM_POWERS_23) => ShiftedDegree23::load_bytes()?,
        (true, NUM_POWERS_24) => ShiftedDegree24::load_bytes()?,
        (true, NUM_POWERS_25) => ShiftedDegree25::load_bytes()?,
        // TODO (nkls): restore on CI.
        #[cfg(feature = "large_params")]
        (true, NUM_POWERS_26) => ShiftedDegree26::load_bytes()?,
        #[cfg(feature = "large_params")]
        (true, NUM_POWERS_27) => ShiftedDegree27::load_bytes()?,
        _ => bail!("{} has no built-in loader", file.name()),
    })
}

/// The error the SRS returns, on a native build without `filesystem`, for
/// powers it does not hold, naming the files that hold them.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("The SRS lacks the powers files {}", .files.iter().map(PowersFile::name).collect::<Vec<_>>().join(", "))]
pub struct MissingPowers {
    /// The files, in the order `add_powers_file` accepts them.
    pub files: Vec<PowersFile>,
}

/// One end of the powers of beta G: immutable once made, and replaced by a
/// longer one when more powers are fetched.
pub type PowersSnapshot<E> = Arc<Vec<<E as PairingEngine>::G1Affine>>;

/// A vector of powers of beta G.
#[derive(Debug)]
pub struct PowersOfG<E: PairingEngine> {
    /// The powers of beta G. Each end is an immutable snapshot, replaced, never
    /// mutated, when more powers are fetched, so a key may share one for as
    /// long as it lives.
    powers_of_beta_g: RwLock<PowersOfBetaG<E>>,
    /// Group elements of form `{ \beta^i \gamma G }`, where `i` is from 0 to `degree`,
    /// This is used for hiding.
    powers_of_beta_times_gamma_g: BTreeMap<usize, E::G1Affine>,
    /// Group elements of form `{ \beta^{max_degree - i} H }`, where `i`
    /// is of the form `2^k - 1` for `k` in `1` to `log_2(max_degree)`.
    negative_powers_of_beta_h: BTreeMap<usize, E::G2Affine>,
    /// Information required to enforce degree bounds. Each pair is of the form `(degree_bound, shifting_advice)`.
    /// Each pair is in the form `(degree_bound, \beta^{max_degree - i} H),` where `H` is the generator of G2,
    /// and `i` is of the form `2^k - 1` for `k` in `1` to `log_2(max_degree)`.
    prepared_negative_powers_of_beta_h: Arc<BTreeMap<usize, <E::G2Affine as PairingCurve>::Prepared>>,
    /// beta * h
    beta_h: E::G2Affine,
}

impl<E: PairingEngine> PowersOfG<E> {
    /// Initializes the hard-coded instance of the powers.
    pub fn load() -> Result<Self> {
        let powers_of_beta_g = RwLock::new(PowersOfBetaG::load()?);

        // Reconstruct powers of beta_times_gamma_g.
        let powers_of_beta_times_gamma_g = BTreeMap::deserialize_uncompressed_unchecked(&**POWERS_OF_BETA_GAMMA_G)?;

        // Reconstruct negative powers of beta_h.
        let negative_powers_of_beta_h: BTreeMap<usize, E::G2Affine> =
            BTreeMap::deserialize_uncompressed_unchecked(&**NEG_POWERS_OF_BETA_H)?;

        // Compute the prepared negative powers of beta_h.
        let prepared_negative_powers_of_beta_h: Arc<BTreeMap<usize, <E::G2Affine as PairingCurve>::Prepared>> =
            Arc::new(negative_powers_of_beta_h.iter().map(|(d, affine)| (*d, affine.prepare())).collect());

        let beta_h = E::G2Affine::deserialize_uncompressed_unchecked(&**BETA_H)?;

        // Return the powers.
        Ok(Self {
            powers_of_beta_g,
            powers_of_beta_times_gamma_g,
            negative_powers_of_beta_h,
            prepared_negative_powers_of_beta_h,
            beta_h,
        })
    }

    /// Download the powers of beta G specified by `range`. On a native build
    /// without `filesystem`, it downloads nothing, and returns `MissingPowers`
    /// naming the files that `missing_files_for` lists.
    pub fn download_powers_for(&self, range: Range<usize>) -> Result<()> {
        if range.is_empty() || self.powers_of_beta_g.read().contains_powers(&range) {
            return Ok(());
        }
        ensure!(range.end <= MAX_NUM_POWERS, "Upper bound must be less than the maximum number of powers");
        self.powers_of_beta_g.write().download_powers_for(&[range])
    }

    /// Downloads the first `prefix` and the last `suffix` powers of beta G. On a
    /// native build without `filesystem`, it downloads nothing, and returns one
    /// `MissingPowers` naming the files of both.
    pub fn download_powers_for_ends(&self, prefix: usize, suffix: usize) -> Result<()> {
        ensure!(prefix.max(suffix) <= MAX_NUM_POWERS, "Upper bound must be less than the maximum number of powers");
        let ranges = [0..prefix, MAX_NUM_POWERS - suffix..MAX_NUM_POWERS];
        if self.powers_of_beta_g.read().missing_files_for(&ranges)?.is_empty() {
            return Ok(());
        }
        self.powers_of_beta_g.write().download_powers_for(&ranges)
    }

    /// The files this SRS still needs to hold `range`, in the order `add_powers_file` accepts them.
    /// An embedded file is never listed.
    pub fn missing_files_for(&self, range: Range<usize>) -> Result<Vec<PowersFile>> {
        self.powers_of_beta_g.read().missing_files_for(&[range])
    }

    /// Reads `file` from `reader`, checks its size and checksum, and appends its
    /// powers. A file already held is not read. `reader` need not be buffered.
    pub fn add_powers_file(&self, file: &PowersFile, reader: impl Read) -> Result<()> {
        if !self.powers_of_beta_g.read().accepts(file)? {
            return Ok(());
        }
        let powers = file.read_checked_powers::<E>(reader)?;
        self.powers_of_beta_g.write().extend(file, powers)
    }

    /// Returns the number of contiguous powers of beta G starting from the 0-th power.
    pub fn num_powers(&self) -> usize {
        self.powers_of_beta_g.read().num_powers()
    }

    /// Returns the maximum possible number of contiguous powers of beta G starting from the 0-th power.
    pub fn max_num_powers(&self) -> usize {
        MAX_NUM_POWERS
    }

    /// Returns the powers of beta * gamma G.
    pub fn powers_of_beta_gamma_g(&self) -> &BTreeMap<usize, E::G1Affine> {
        &self.powers_of_beta_times_gamma_g
    }

    /// Returns the `index`-th power of beta * G.
    pub fn power_of_beta_g(&self, index: usize) -> Result<E::G1Affine> {
        self.download_powers_for(index..index + 1)?;
        Ok(self.powers_of_beta_g.read().held_powers(index..index + 1)?[0])
    }

    /// Returns the powers of `beta * G` that lie within `range`.
    pub fn powers_of_beta_g(&self, range: Range<usize>) -> Result<Vec<E::G1Affine>> {
        self.download_powers_for(range.clone())?;
        Ok(self.powers_of_beta_g.read().held_powers(range)?.to_vec())
    }

    /// The powers of `beta * G` in `range`, as the snapshot holding them and
    /// their range within it, fetching them first if needed. The snapshot never
    /// changes, so a caller may hold it, and slice it, for as long as it likes.
    pub fn shared_powers_of_beta_g(&self, range: Range<usize>) -> Result<(PowersSnapshot<E>, Range<usize>)> {
        self.download_powers_for(range.clone())?;
        self.held_shared_powers_of_beta_g(range)
            .ok_or_else(|| anyhow!("Requested range is not contained in the available powers"))
    }

    /// The powers of `beta * G` in `range`, as `shared_powers_of_beta_g` gives
    /// them, if they are already held; downloads nothing.
    pub fn held_shared_powers_of_beta_g(&self, range: Range<usize>) -> Option<(PowersSnapshot<E>, Range<usize>)> {
        if range.is_empty() {
            return Some((Arc::new(Vec::new()), 0..0));
        }
        let powers = self.powers_of_beta_g.read();
        let (store, within) = powers.locate(range).ok()?;
        Some((store.clone(), within))
    }

    pub fn negative_powers_of_beta_h(&self) -> &BTreeMap<usize, E::G2Affine> {
        &self.negative_powers_of_beta_h
    }

    pub fn prepared_negative_powers_of_beta_h(&self) -> Arc<BTreeMap<usize, <E::G2Affine as PairingCurve>::Prepared>> {
        self.prepared_negative_powers_of_beta_h.clone()
    }

    pub fn beta_h(&self) -> E::G2Affine {
        self.beta_h
    }
}

#[derive(Debug)]
pub struct PowersOfBetaG<E: PairingEngine> {
    /// Group elements of form `[G, \beta * G, \beta^2 * G, ..., \beta^d G]`.
    powers_of_beta_g: PowersSnapshot<E>,
    /// Group elements of form `[\beta^i * G, \beta^2 * G, ..., \beta^D G]`.
    /// where D is the maximum degree supported by the SRS.
    shifted_powers_of_beta_g: PowersSnapshot<E>,
}

impl<E: PairingEngine> PowersOfBetaG<E> {
    /// Returns the number of contiguous powers of beta G starting from the 0-th power.
    pub fn num_powers(&self) -> usize {
        self.powers_of_beta_g.len()
    }

    /// Initializes the hard-coded instance of the powers.
    fn load() -> Result<Self> {
        // Deserialize the group elements.
        let powers_of_beta_g = Vec::deserialize_uncompressed_unchecked(&**POWERS_OF_BETA_G_15)?;

        // Ensure the number of elements is correct.
        ensure!(powers_of_beta_g.len() == NUM_POWERS_15, "Incorrect number of powers in the recovered SRS");

        let shifted_powers_of_beta_g: Vec<E::G1Affine> = Vec::deserialize_uncompressed_unchecked(&**SHIFTED_POWERS_OF_BETA_G_15)?;
        ensure!(shifted_powers_of_beta_g.len() == NUM_POWERS_15, "Incorrect number of powers in the recovered SRS");
        // The embedded shifted file is held from the start, so `missing_files_for` never lists it.
        #[cfg(not(feature = "no-embedded-srs"))]
        let shifted_powers_of_beta_g = {
            let lower: Vec<E::G1Affine> = Vec::deserialize_uncompressed_unchecked(&*ShiftedDegree16::load_bytes()?)?;
            ensure!(lower.len() == NUM_POWERS_15, "Incorrect number of powers in the recovered SRS");
            [lower, shifted_powers_of_beta_g].concat()
        };
        Ok(PowersOfBetaG {
            powers_of_beta_g: Arc::new(powers_of_beta_g),
            shifted_powers_of_beta_g: Arc::new(shifted_powers_of_beta_g),
        })
    }

    /// Returns the range of powers of beta G.
    /// In detail, it returns the range of the available "normal" powers of beta G, i.e. the
    /// contiguous range of powers of beta G starting from G, and, the range of shifted_powers.
    ///
    /// For example, if the output of this function is `(0..8, 24..32)`, then `self`
    /// contains the powers
    /// * `beta^0 * G, beta^1 * G, ..., beta^7 * G`, and
    /// * `beta^24 * G, ..., beta^31 * G`.
    pub fn available_powers(&self) -> (Range<usize>, Range<usize>) {
        if !self.shifted_powers_of_beta_g.is_empty() {
            let lower_shifted_bound = MAX_NUM_POWERS - self.shifted_powers_of_beta_g.len();
            ((0..self.powers_of_beta_g.len()), (lower_shifted_bound..MAX_NUM_POWERS))
        } else {
            // We can only be in this case if have downloaded all possible powers.
            assert_eq!(self.powers_of_beta_g.len(), MAX_NUM_POWERS, "Incorrect number of powers in the recovered SRS");
            ((0..MAX_NUM_POWERS), (0..MAX_NUM_POWERS))
        }
    }

    fn contains_in_normal_powers(&self, range: &Range<usize>) -> bool {
        let (normal, _) = self.available_powers();
        normal.contains(&range.start) && (normal.end >= range.end)
    }

    fn contains_in_shifted_powers(&self, range: &Range<usize>) -> bool {
        let (_, shifted) = self.available_powers();
        shifted.contains(&range.start) && (shifted.end >= range.end)
    }

    fn contains_powers(&self, range: &Range<usize>) -> bool {
        self.contains_in_normal_powers(range) || self.contains_in_shifted_powers(range)
    }

    /// Which snapshot holds the powers in `range`, and where in it, if they
    /// are already held; downloads nothing.
    fn locate(&self, range: Range<usize>) -> Result<(&PowersSnapshot<E>, Range<usize>)> {
        if range.is_empty() {
            return Ok((&self.powers_of_beta_g, 0..0));
        }
        ensure!(range.end <= MAX_NUM_POWERS, "Upper bound must be less than the maximum number of powers");
        if self.contains_in_normal_powers(&range) {
            return Ok((&self.powers_of_beta_g, range));
        }
        ensure!(self.contains_in_shifted_powers(&range), "Requested range is not contained in the available powers");
        if range.start < MAX_NUM_POWERS / 2 {
            ensure!(self.shifted_powers_of_beta_g.is_empty());
            // In this case, we have downloaded all the powers, and so
            // all the powers reside in self.powers_of_beta_g.
            Ok((&self.powers_of_beta_g, range))
        } else {
            // In this case, the shifted powers still reside in self.shifted_powers_of_beta_g.
            let lower = self.shifted_powers_of_beta_g.len() - (MAX_NUM_POWERS - range.start);
            let upper = self.shifted_powers_of_beta_g.len() - (MAX_NUM_POWERS - range.end);
            Ok((&self.shifted_powers_of_beta_g, lower..upper))
        }
    }

    /// The powers in `range`, if they are already held; downloads nothing.
    fn held_powers(&self, range: Range<usize>) -> Result<&[E::G1Affine]> {
        let (store, within) = self.locate(range)?;
        Ok(&store[within])
    }

    /// Downloads the files that `missing_files_for` lists for `ranges`. On a
    /// native build without `filesystem`, it downloads nothing, and returns
    /// `MissingPowers` naming them.
    pub fn download_powers_for(&mut self, ranges: &[Range<usize>]) -> Result<()> {
        let files = self.missing_files_for(ranges)?;
        #[cfg(not(any(feature = "filesystem", feature = "wasm")))]
        {
            ensure!(files.is_empty(), MissingPowers { files });
            Ok(())
        }
        #[cfg(any(feature = "filesystem", feature = "wasm"))]
        self.download_files(files)
    }

    /// Downloads `files` with `default_load_powers_file_sync` and appends them.
    #[cfg(any(feature = "filesystem", feature = "wasm"))]
    fn download_files(&mut self, files: Vec<PowersFile>) -> Result<()> {
        if let Some(last) = files.iter().rfind(|file| !file.shifted) {
            self.prefix_mut(last.num_powers);
        }
        // A file that fails leaves the ones before it appended, so a retry
        // resumes from them rather than fetching them again.
        for file in files {
            snarkvm_utilities::dev_println!("Loading {}", file.name());
            let powers = file.read_powers::<E>(&*default_load_powers_file_sync(&file)?)?;
            self.extend(&file, powers)?;
        }
        Ok(())
    }

    /// The files `download_powers_for` fetches to hold `ranges`, in the order
    /// `extend` accepts them: prefix files upward, then shifted files downward
    /// from the top.
    fn missing_files_for(&self, ranges: &[Range<usize>]) -> Result<Vec<PowersFile>> {
        let half_max = MAX_NUM_POWERS / 2;
        let (held, held_shifted) = (self.powers_of_beta_g.len(), self.shifted_powers_of_beta_g.len());
        let (mut target, mut target_shifted) = (held, held_shifted);
        let shifted_start = MAX_NUM_POWERS - held_shifted;
        for range in ranges {
            if range.is_empty() || range.end <= held || (range.start >= shifted_start && range.end <= MAX_NUM_POWERS) {
                continue;
            }
            ensure!(range.end <= MAX_NUM_POWERS, "Upper bound must be less than the maximum number of powers");
            // Shifted files hold only powers above the midpoint, so a range starting at or below it needs the
            // prefix, which rounds up to a power of two.
            if range.start <= half_max || range.end.abs_diff(held) <= range.start.abs_diff(shifted_start) {
                target = target.max(range.end.next_power_of_two());
            } else {
                target_shifted = target_shifted.max((MAX_NUM_POWERS - range.start).next_power_of_two());
            }
        }
        // A full prefix holds the shifted powers too.
        if target == MAX_NUM_POWERS {
            target_shifted = held_shifted;
        }
        // Each side holds a power of two, or nothing, whose `trailing_zeros` exceeds any target's.
        let files = |shifted, held: usize, target: usize| {
            (held.trailing_zeros() + 1..=target.trailing_zeros()).map(move |k| PowersFile::new(shifted, 1 << k))
        };
        files(false, held, target).chain(files(true, held_shifted, target_shifted)).collect()
    }

    /// Whether `file` is the next one to append: `false` if it is already held,
    /// and an error if the file before it is not.
    fn accepts(&self, file: &PowersFile) -> Result<bool> {
        let held = if file.shifted { self.shifted_powers_of_beta_g.len() } else { self.powers_of_beta_g.len() };
        // An empty shifted side means the prefix holds every power.
        if held >= file.num_powers || (file.shifted && held == 0) {
            return Ok(false);
        }
        if held != file.num_powers / 2 {
            bail!("Add {} before {}", PowersFile::new(file.shifted, held * 2)?.name(), file.name());
        }
        Ok(true)
    }

    /// Appends the powers read from `file`, if it is the next one to append.
    fn extend(&mut self, file: &PowersFile, powers: Vec<E::G1Affine>) -> Result<()> {
        if !self.accepts(file)? {
            return Ok(());
        }
        if file.shifted {
            self.shifted_powers_of_beta_g = Arc::new([&powers[..], &self.shifted_powers_of_beta_g[..]].concat());
        } else {
            self.prefix_mut(file.num_powers).extend(powers);
            if self.powers_of_beta_g.len() == MAX_NUM_POWERS {
                self.shifted_powers_of_beta_g = Arc::new(Vec::new());
            }
        }
        Ok(())
    }

    /// The prefix, with room for `capacity` powers. A snapshot a key shares
    /// never changes, so a shared one is first replaced by a copy. Not
    /// `Arc::make_mut`, whose clone is sized to the old length, so growing it
    /// would copy a shared snapshot a second time.
    fn prefix_mut(&mut self, capacity: usize) -> &mut Vec<E::G1Affine> {
        if Arc::get_mut(&mut self.powers_of_beta_g).is_none() {
            let mut copy = Vec::with_capacity(capacity);
            copy.extend_from_slice(&self.powers_of_beta_g);
            self.powers_of_beta_g = Arc::new(copy);
        }
        // `&mut self` excludes every other reference to the `Arc`, and it is
        // unshared by now, so it stays so.
        let powers = Arc::get_mut(&mut self.powers_of_beta_g).expect("an unshared snapshot stays unshared under &mut self");
        powers.reserve(capacity.saturating_sub(powers.len()));
        powers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_curves::bls12_377::Bls12_377;

    type Powers = PowersOfG<Bls12_377>;

    const SHIFTED_16: Range<usize> = MAX_NUM_POWERS - NUM_POWERS_16..MAX_NUM_POWERS;
    const SHIFTED_17: Range<usize> = MAX_NUM_POWERS - NUM_POWERS_17..MAX_NUM_POWERS;

    fn names(files: &[PowersFile]) -> Vec<String> {
        files.iter().map(|file| file.name().to_string()).collect()
    }

    /// The bytes of `file`. Without `filesystem`, they are read from
    /// `~/.aleo/resources`, where a test run with `filesystem` leaves them.
    fn file_bytes(file: &PowersFile) -> Vec<u8> {
        #[cfg(feature = "filesystem")]
        return default_load_powers_file_sync(file).unwrap();
        #[cfg(not(feature = "filesystem"))]
        {
            let path = aleo_std::aleo_dir().join("resources").join(file.name());
            std::fs::read(&path).unwrap_or_else(|error| panic!("Run the tests with `filesystem` first: {path:?}: {error}"))
        }
    }

    fn add_files_for(powers: &Powers, range: Range<usize>) {
        for file in &powers.missing_files_for(range.clone()).unwrap() {
            powers.add_powers_file(file, &*file_bytes(file)).unwrap();
        }
    }

    fn prefix(powers: &Powers) -> PowersSnapshot<Bls12_377> {
        powers.powers_of_beta_g.read().powers_of_beta_g.clone()
    }

    fn shifted(powers: &Powers) -> PowersSnapshot<Bls12_377> {
        powers.powers_of_beta_g.read().shifted_powers_of_beta_g.clone()
    }

    #[test]
    fn each_file_is_named_and_sized_for_its_powers() {
        let top = if cfg!(feature = "large_params") { 28 } else { 25 };
        let shifted_bottom = if cfg!(feature = "no-embedded-srs") { 16 } else { 17 };
        for (shifted, k) in (16..=top).map(|k| (false, k)).chain((shifted_bottom..=top.min(27)).map(|k| (true, k))) {
            let file = PowersFile::new(shifted, 1 << k).unwrap();
            assert_eq!(file.size(), 8 + 96 * (1 << (k - 1)));
            let stem = if shifted { "shifted-powers-of-beta" } else { "powers-of-beta" };
            assert_eq!(file.name(), format!("{stem}-{k}.usrs.{}", &file.checksum()[..7]));
        }
        assert_eq!(PowersFile::new(false, NUM_POWERS_16).unwrap().name(), "powers-of-beta-16.usrs.84631bc");
        assert!(PowersFile::new(false, NUM_POWERS_15).is_err());
        assert_eq!(PowersFile::new(true, NUM_POWERS_16).is_ok(), cfg!(feature = "no-embedded-srs"));
    }

    #[cfg(feature = "filesystem")]
    #[test]
    fn the_default_loader_returns_the_bytes_load_bytes_does() {
        let file = PowersFile::new(false, NUM_POWERS_16).unwrap();
        assert!(!file.shifted() && file.num_powers() == NUM_POWERS_16);
        assert_eq!(default_load_powers_file_sync(&file).unwrap(), Degree16::load_bytes().unwrap());
        let file = PowersFile::new(true, NUM_POWERS_17).unwrap();
        assert!(file.shifted() && file.num_powers() == NUM_POWERS_17);
        assert_eq!(default_load_powers_file_sync(&file).unwrap(), ShiftedDegree17::load_bytes().unwrap());
    }

    #[cfg(not(any(feature = "filesystem", feature = "wasm")))]
    #[test]
    #[ignore = "reads the powers files that a run with `filesystem` caches"]
    fn each_growth_path_names_the_files_it_needs() {
        fn missing_powers(error: anyhow::Error) -> Vec<PowersFile> {
            error.downcast::<MissingPowers>().unwrap().files
        }
        let powers = Powers::load().unwrap();
        let prefix_files = powers.missing_files_for(0..NUM_POWERS_17).unwrap();
        let shifted_files = powers.missing_files_for(SHIFTED_17).unwrap();
        assert_eq!(prefix_files.len(), 2);
        assert!(!shifted_files.is_empty());
        let (before, before_shifted) = (prefix(&powers), shifted(&powers));
        assert_eq!(missing_powers(powers.download_powers_for(0..NUM_POWERS_17).unwrap_err()), prefix_files);
        assert_eq!(missing_powers(powers.powers_of_beta_g(0..NUM_POWERS_17).unwrap_err()), prefix_files);
        assert_eq!(missing_powers(powers.shared_powers_of_beta_g(0..NUM_POWERS_17).unwrap_err()), prefix_files);
        assert_eq!(missing_powers(powers.power_of_beta_g(NUM_POWERS_16).unwrap_err()), prefix_files);
        assert_eq!(missing_powers(powers.powers_of_beta_g(SHIFTED_17).unwrap_err()), shifted_files);
        let both = powers.download_powers_for_ends(NUM_POWERS_17, NUM_POWERS_17).unwrap_err();
        assert_eq!(missing_powers(both), [&prefix_files[..], &shifted_files[..]].concat());
        assert!(powers.download_powers_for_ends(MAX_NUM_POWERS + 1, 0).is_err());
        assert!(Arc::ptr_eq(&before, &prefix(&powers)) && Arc::ptr_eq(&before_shifted, &shifted(&powers)));

        add_files_for(&powers, 0..NUM_POWERS_17);
        add_files_for(&powers, SHIFTED_17);
        powers.download_powers_for_ends(NUM_POWERS_17, NUM_POWERS_17).unwrap();
        assert_eq!(powers.powers_of_beta_g(0..NUM_POWERS_17).unwrap(), prefix(&powers)[..NUM_POWERS_17]);
        let shifted_powers = shifted(&powers);
        assert_eq!(powers.powers_of_beta_g(SHIFTED_17).unwrap(), shifted_powers[shifted_powers.len() - NUM_POWERS_17..]);
    }

    #[test]
    fn missing_powers_survives_context_and_names_its_files() {
        let files = vec![PowersFile::new(false, NUM_POWERS_16).unwrap(), PowersFile::new(true, NUM_POWERS_17).unwrap()];
        let error = anyhow::Error::from(MissingPowers { files: files.clone() }).context("trimming");
        assert_eq!(error.downcast_ref::<MissingPowers>().map(|error| &error.files), Some(&files));
        let message = error.root_cause().to_string();
        assert!(message.contains(files[0].name()) && message.contains(files[1].name()), "{message}");
    }

    #[test]
    #[cfg_attr(not(feature = "filesystem"), ignore = "reads the powers files that a run with `filesystem` caches")]
    fn missing_files_are_listed_in_the_order_they_are_added() {
        let powers = Powers::load().unwrap();
        assert!(powers.missing_files_for(0..0).unwrap().is_empty());
        assert!(powers.missing_files_for(0..NUM_POWERS_15).unwrap().is_empty());
        assert_eq!(powers.missing_files_for(SHIFTED_16).unwrap().is_empty(), cfg!(not(feature = "no-embedded-srs")));
        assert!(powers.missing_files_for(0..MAX_NUM_POWERS + 1).is_err());
        assert_eq!(names(&powers.missing_files_for(0..NUM_POWERS_17).unwrap()), [
            "powers-of-beta-16.usrs.84631bc",
            "powers-of-beta-17.usrs.7c27308",
        ]);
        let shifted_files = names(&powers.missing_files_for(SHIFTED_17).unwrap());
        assert_eq!(shifted_files.len(), if cfg!(feature = "no-embedded-srs") { 2 } else { 1 });
        assert_eq!(shifted_files.last().map(String::as_str), Some(PowersFile::new(true, NUM_POWERS_17).unwrap().name()));
        add_files_for(&powers, 0..NUM_POWERS_16);
        assert_eq!(names(&powers.missing_files_for(0..NUM_POWERS_17).unwrap()), ["powers-of-beta-17.usrs.7c27308"]);
        add_files_for(&powers, 0..NUM_POWERS_17);
        add_files_for(&powers, SHIFTED_17);
        assert!(powers.missing_files_for(0..NUM_POWERS_17).unwrap().is_empty());
        assert!(powers.missing_files_for(SHIFTED_17).unwrap().is_empty());
    }

    #[cfg(feature = "filesystem")]
    #[test]
    fn an_added_file_matches_a_downloaded_one() {
        let (added, downloaded) = (Powers::load().unwrap(), Powers::load().unwrap());
        for range in [0..NUM_POWERS_17, SHIFTED_17] {
            add_files_for(&added, range.clone());
            downloaded.download_powers_for(range).unwrap();
        }
        assert_eq!(prefix(&added).len(), NUM_POWERS_17);
        assert_eq!(prefix(&added), prefix(&downloaded));
        assert_eq!(shifted(&added).len(), NUM_POWERS_17);
        assert_eq!(shifted(&added), shifted(&downloaded));
    }

    #[test]
    #[cfg_attr(not(feature = "filesystem"), ignore = "reads the powers files that a run with `filesystem` caches")]
    fn a_rejected_file_leaves_the_srs_unchanged() {
        let powers = Powers::load().unwrap();
        let (before, before_shifted) = (prefix(&powers), shifted(&powers));
        let file = PowersFile::new(false, NUM_POWERS_16).unwrap();
        let bytes = file_bytes(&file);
        let mut flipped = bytes.clone();
        *flipped.last_mut().unwrap() ^= 1;
        let mut header = bytes.clone();
        header[0] ^= 1;
        let longer = [&bytes[..], &[0]].concat();
        let other = file_bytes(&PowersFile::new(true, NUM_POWERS_17).unwrap());
        for candidate in [&flipped[..], &header, &bytes[..bytes.len() - 1], &longer, &other, &[]] {
            assert!(powers.add_powers_file(&file, candidate).is_err());
        }
        let error = powers.add_powers_file(&PowersFile::new(false, NUM_POWERS_17).unwrap(), &[][..]).unwrap_err();
        assert!(error.to_string().contains("powers-of-beta-16.usrs.84631bc"), "{error}");
        assert!(Arc::ptr_eq(&before, &prefix(&powers)), "a rejected file replaced the prefix");
        assert!(Arc::ptr_eq(&before_shifted, &shifted(&powers)), "a rejected file replaced the shifted powers");
    }

    #[test]
    #[cfg_attr(not(feature = "filesystem"), ignore = "reads the powers files that a run with `filesystem` caches")]
    fn a_held_file_is_not_read() {
        let powers = Powers::load().unwrap();
        add_files_for(&powers, 0..NUM_POWERS_16);
        let before = prefix(&powers);
        powers.add_powers_file(&PowersFile::new(false, NUM_POWERS_16).unwrap(), &[][..]).unwrap();
        assert!(Arc::ptr_eq(&before, &prefix(&powers)));
    }
}
