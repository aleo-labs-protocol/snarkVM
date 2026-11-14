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

use crate::CurrentNetwork;

use console::{
    account::{Address, PrivateKey},
    prelude::*,
};
use snarkvm_ledger_block::Block;

use std::{
    fs,
    io,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

/// A genesis private key and the genesis block that it signs.
type GenesisFixture = (PrivateKey<CurrentNetwork>, Block<CurrentNetwork>);

/// Returns the genesis fixture of the running binary, which `build` builds.
///
/// The processes of one binary share the fixture through the file `<binary>.<extension>`.
/// The file holds the size and the modification time of the binary, so a rebuilt binary builds a new fixture.
/// If the file cannot be used, every process builds its own fixture.
/// `build` must return the same fixture in every process, and its genesis block must be a beacon block.
pub fn load_or_build_genesis_fixture(extension: &str, build: impl FnOnce() -> GenesisFixture) -> GenesisFixture {
    match genesis_fixture_path_and_stamp(extension) {
        Ok((path, stamp)) => load_or_build(&path, &stamp, build),
        Err(_) => build(),
    }
}

/// Returns the path of the genesis fixture file of the running binary, and the stamp of that binary.
///
/// The stamp holds the size and the modification time of the binary.
fn genesis_fixture_path_and_stamp(extension: &str) -> io::Result<(PathBuf, Vec<u8>)> {
    let binary = std::env::current_exe()?;
    let metadata = fs::metadata(&binary)?;
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let mut stamp = Vec::with_capacity(24);
    stamp.extend_from_slice(&metadata.len().to_le_bytes());
    stamp.extend_from_slice(&modified.as_nanos().to_le_bytes());
    Ok((binary.with_added_extension(extension), stamp))
}

/// Reads the genesis fixture at `path`, or builds the fixture and writes it to `path`.
///
/// An exclusive lock on the sibling `.lock` file lets one process build the fixture while the others wait.
/// A file that cannot be read or parsed, or that holds a different stamp, is rebuilt and overwritten.
fn load_or_build(path: &Path, stamp: &[u8], build: impl FnOnce() -> GenesisFixture) -> GenesisFixture {
    if let Some(fixture) = read(path, stamp) {
        return fixture;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_added_extension("lock"))
        .and_then(|file| file.lock().map(|()| file));
    // Without the lock, the fixture is built but not written.
    let Ok(lock) = lock else {
        return build();
    };
    // Another process may have written the fixture while this process waited for the lock.
    if let Some(fixture) = read(path, stamp) {
        return fixture;
    }
    let fixture = build();
    // A failed write leaves the file for a later process to rebuild.
    let _ = write(path, stamp, &fixture);
    drop(lock);
    fixture
}

/// Reads the genesis fixture at `path`, if the file holds a valid fixture with the given stamp.
fn read(path: &Path, stamp: &[u8]) -> Option<GenesisFixture> {
    from_bytes(&fs::read(path).ok()?, stamp)
}

/// Writes the genesis fixture to `path` through a temporary file and a rename.
fn write(path: &Path, stamp: &[u8], fixture: &GenesisFixture) -> io::Result<()> {
    let temporary_path = path.with_added_extension("tmp");
    fs::write(&temporary_path, to_bytes(stamp, fixture)?)?;
    fs::rename(temporary_path, path)
}

/// Returns the stamp, followed by the bytes of the genesis private key and the genesis block.
fn to_bytes(stamp: &[u8], fixture: &GenesisFixture) -> io::Result<Vec<u8>> {
    let mut bytes = stamp.to_vec();
    fixture.write_le(&mut bytes)?;
    Ok(bytes)
}

/// Parses the output of `to_bytes`.
///
/// Returns `None` if the bytes hold a different stamp, fail to parse, have trailing bytes,
/// or hold a block that the private key did not sign as a beacon.
fn from_bytes(bytes: &[u8], stamp: &[u8]) -> Option<GenesisFixture> {
    let mut reader = bytes.strip_prefix(stamp)?;
    let (private_key, block) = GenesisFixture::read_le(&mut reader).ok()?;
    let authority = block.authority();
    let is_signer = authority.is_beacon() && Address::try_from(&private_key).ok()? == authority.to_address();
    (reader.is_empty() && is_signer).then_some((private_key, block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{sample_genesis_block_and_components, sample_genesis_private_key};

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Returns a valid genesis fixture.
    fn sample_fixture() -> GenesisFixture {
        let rng = &mut TestRng::default();
        let (block, _, private_key) = sample_genesis_block_and_components(rng);
        assert_eq!(private_key, sample_genesis_private_key(rng));
        (private_key, block)
    }

    /// Returns a path in the temporary directory that is unique to this process and `name`.
    fn temporary_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("snarkvm-genesis-fixture-{name}-{}", std::process::id()));
        remove_files(&path);
        path
    }

    /// Removes the fixture file at `path` and its lock file.
    fn remove_files(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_added_extension("lock"));
    }

    #[test]
    fn test_hit_matches_miss() {
        let path = temporary_path("hit");
        let stamp = b"stamp";
        let fixture = sample_fixture();
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::Relaxed);
            fixture.clone()
        };

        // The file does not exist yet, so this call builds the fixture and writes the file.
        let miss = load_or_build(&path, stamp, build);
        // This call reads the file that the previous call wrote.
        let hit = load_or_build(&path, stamp, build);
        let bytes = fs::read(&path).expect("Failed to read the fixture file");
        // A different stamp builds the fixture again.
        let rebuilt = load_or_build(&path, b"stamq", build);
        remove_files(&path);

        assert_eq!(miss, fixture);
        assert_eq!(hit, fixture);
        assert_eq!(rebuilt, fixture);
        assert_eq!(bytes, to_bytes(stamp, &fixture).expect("Failed to serialize the fixture"));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_concurrent_callers_build_once() {
        let path = temporary_path("concurrent");
        let stamp = b"stamp";
        let fixture = sample_fixture();
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::Relaxed);
            fixture.clone()
        };

        // Each thread opens its own lock file handle, so the threads exclude each other as processes do.
        let results = std::thread::scope(|scope| {
            let handles = (0..8).map(|_| scope.spawn(|| load_or_build(&path, stamp, build))).collect::<Vec<_>>();
            handles.into_iter().map(|handle| handle.join().expect("A thread panicked")).collect::<Vec<_>>()
        });
        remove_files(&path);

        assert!(results.iter().all(|result| *result == fixture));
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_unusable_path_builds_without_writing() {
        let directory = temporary_path("missing-directory");
        let path = directory.join("genesis");
        let fixture = sample_fixture();

        assert_eq!(load_or_build(&path, b"stamp", || fixture.clone()), fixture);
        assert!(!directory.exists());
    }

    #[test]
    fn test_rejects_invalid_bytes() {
        let stamp = b"stamp";
        let fixture = sample_fixture();
        let (private_key, block) = &fixture;
        let bytes = to_bytes(stamp, &fixture).expect("Failed to serialize the fixture");
        assert_eq!(from_bytes(&bytes, stamp), Some(fixture.clone()));

        // A different stamp.
        assert!(from_bytes(&bytes, b"stamq").is_none());
        // Missing bytes.
        assert!(from_bytes(&[], stamp).is_none());
        assert!(from_bytes(stamp, stamp).is_none());
        assert!(from_bytes(&bytes[..bytes.len() - 1], stamp).is_none());
        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(from_bytes(&extended, stamp).is_none());
        // Bytes that do not encode a fixture.
        let mut garbage = stamp.to_vec();
        garbage.resize(bytes.len(), 0xff);
        assert!(from_bytes(&garbage, stamp).is_none());
        // A private key that did not sign the block.
        let other_private_key =
            PrivateKey::<CurrentNetwork>::new(&mut TestRng::default()).expect("Failed to sample a private key");
        assert_ne!(other_private_key, *private_key);
        let other_bytes =
            to_bytes(stamp, &(other_private_key, block.clone())).expect("Failed to serialize the fixture");
        assert!(from_bytes(&other_bytes, stamp).is_none());
    }
}
