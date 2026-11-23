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

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use crate::{FromBytes, ToBytes};

/// Returns the fixture of the running binary that `build` builds.
///
/// The processes of one binary share the fixture through the file `<binary>.<extension>`.
/// The file holds the size and the modification time of the binary and `key`,
/// so a rebuilt binary or another key builds a new fixture.
/// A fixture in the file that `is_valid` rejects is built again.
/// If the file cannot be used, every process builds its own fixture.
/// `build` must return the same fixture for the same key in every process.
#[doc(hidden)]
pub fn load_or_build_fixture<T: FromBytes + ToBytes>(
    extension: &str,
    key: &[u8],
    is_valid: impl Fn(&T) -> bool,
    build: impl FnOnce() -> T,
) -> T {
    match fixture_path_and_stamp(extension, key) {
        Ok((path, stamp)) => load_or_build(&path, &stamp, is_valid, build),
        Err(_) => build(),
    }
}

/// Returns the path of the fixture file of the running binary, and the stamp of the fixture.
///
/// The stamp holds the size and the modification time of the binary, and the length and the bytes of `key`.
/// With the length, the stamp of one key is never the start of the stamp of another key.
fn fixture_path_and_stamp(extension: &str, key: &[u8]) -> io::Result<(PathBuf, Vec<u8>)> {
    let binary = std::env::current_exe()?;
    let metadata = fs::metadata(&binary)?;
    let modified = metadata.modified()?.duration_since(UNIX_EPOCH).map_err(io::Error::other)?;
    let mut stamp = Vec::with_capacity(32 + key.len());
    stamp.extend_from_slice(&metadata.len().to_le_bytes());
    stamp.extend_from_slice(&modified.as_nanos().to_le_bytes());
    stamp.extend_from_slice(&(key.len() as u64).to_le_bytes());
    stamp.extend_from_slice(key);
    Ok((binary.with_added_extension(extension), stamp))
}

/// Reads the fixture at `path`, or builds the fixture and writes it to `path`.
///
/// An exclusive lock on the sibling `.lock` file lets one process build the fixture while the others wait.
/// A file that cannot be read or parsed, that holds a different stamp, or that holds a fixture
/// that `is_valid` rejects, is rebuilt and overwritten.
fn load_or_build<T: FromBytes + ToBytes>(
    path: &Path,
    stamp: &[u8],
    is_valid: impl Fn(&T) -> bool,
    build: impl FnOnce() -> T,
) -> T {
    if let Some(fixture) = read(path, stamp, &is_valid) {
        return fixture;
    }
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path.with_added_extension("lock"))
        .and_then(|file| file.lock().map(|()| file));
    // Without the lock, the fixture is built but not written.
    let Ok(_lock) = lock else {
        return build();
    };
    // Another process may have written the fixture while this process waited for the lock.
    if let Some(fixture) = read(path, stamp, &is_valid) {
        return fixture;
    }
    let fixture = build();
    // A failed write leaves the file for a later process to rebuild.
    if let Err(error) = write(path, stamp, &fixture) {
        eprintln!("Failed to write the test fixture '{}': {error}", path.display());
    }
    fixture
}

/// Reads the fixture at `path`, if the file holds a valid fixture with the given stamp.
fn read<T: FromBytes>(path: &Path, stamp: &[u8], is_valid: impl Fn(&T) -> bool) -> Option<T> {
    from_bytes(&fs::read(path).ok()?, stamp, is_valid)
}

/// Writes the fixture to `path` through a temporary file and a rename.
fn write<T: ToBytes>(path: &Path, stamp: &[u8], fixture: &T) -> io::Result<()> {
    let temporary_path = path.with_added_extension("tmp");
    // `create_new` neither follows nor reuses an existing file, so remove one that an interrupted write left behind.
    let _ = fs::remove_file(&temporary_path);
    fs::OpenOptions::new().write(true).create_new(true).open(&temporary_path)?.write_all(&to_bytes(stamp, fixture)?)?;
    fs::rename(temporary_path, path)
}

/// Returns the stamp, followed by the bytes of the fixture.
fn to_bytes<T: ToBytes>(stamp: &[u8], fixture: &T) -> io::Result<Vec<u8>> {
    let mut bytes = stamp.to_vec();
    fixture.write_le(&mut bytes)?;
    Ok(bytes)
}

/// Parses the output of `to_bytes`.
///
/// Returns `None` if the bytes hold a different stamp, fail to parse, have trailing bytes,
/// or hold a fixture that `is_valid` rejects.
fn from_bytes<T: FromBytes>(bytes: &[u8], stamp: &[u8], is_valid: impl Fn(&T) -> bool) -> Option<T> {
    let mut reader = bytes.strip_prefix(stamp)?;
    let fixture = T::read_le(&mut reader).ok()?;
    (reader.is_empty() && is_valid(&fixture)).then_some(fixture)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A fixture of two integers, which is valid if the integers are equal.
    type Fixture = (u64, u64);

    const FIXTURE: Fixture = (7, 7);

    fn is_valid(fixture: &Fixture) -> bool {
        fixture.0 == fixture.1
    }

    #[test]
    fn test_stamp_holds_key() {
        let (path, stamp) = fixture_path_and_stamp("fixture", &[1]).expect("Failed to stamp the fixture");
        let (other_path, other_stamp) = fixture_path_and_stamp("fixture", &[2]).expect("Failed to stamp the fixture");
        assert_eq!(path, other_path);
        assert_ne!(stamp, other_stamp);

        // The stamp of a key is not the start of the stamp of a longer key.
        let (_, longer_stamp) = fixture_path_and_stamp("fixture", &[1, 2]).expect("Failed to stamp the fixture");
        assert!(!longer_stamp.starts_with(&stamp));
    }

    #[test]
    fn test_hit_matches_miss() {
        let directory = tempfile::tempdir().expect("Failed to create a temporary directory");
        let path = directory.path().join("fixture");
        let stamp = b"stamp";
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::Relaxed);
            FIXTURE
        };

        // The file does not exist yet, so this call builds the fixture and writes the file.
        let miss = load_or_build(&path, stamp, is_valid, build);
        // This call reads the file that the previous call wrote.
        let hit = load_or_build(&path, stamp, is_valid, build);
        let bytes = fs::read(&path).expect("Failed to read the fixture file");
        // A different stamp builds the fixture again.
        let rebuilt = load_or_build(&path, b"stamq", is_valid, build);

        assert_eq!(miss, FIXTURE);
        assert_eq!(hit, FIXTURE);
        assert_eq!(rebuilt, FIXTURE);
        assert_eq!(bytes, to_bytes(stamp, &FIXTURE).expect("Failed to serialize the fixture"));
        assert_eq!(builds.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_concurrent_callers_build_once() {
        let directory = tempfile::tempdir().expect("Failed to create a temporary directory");
        let path = directory.path().join("fixture");
        let stamp = b"stamp";
        let builds = AtomicUsize::new(0);
        let build = || {
            builds.fetch_add(1, Ordering::Relaxed);
            FIXTURE
        };

        // Each thread opens its own lock file handle, so the threads exclude each other as processes do.
        let results = std::thread::scope(|scope| {
            let handles =
                (0..8).map(|_| scope.spawn(|| load_or_build(&path, stamp, is_valid, build))).collect::<Vec<_>>();
            handles.into_iter().map(|handle| handle.join().expect("A thread panicked")).collect::<Vec<_>>()
        });

        assert!(results.iter().all(|result| *result == FIXTURE));
        assert_eq!(builds.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_unusable_path_builds_without_writing() {
        let directory = tempfile::tempdir().expect("Failed to create a temporary directory");
        let missing_directory = directory.path().join("missing");
        let path = missing_directory.join("fixture");

        assert_eq!(load_or_build(&path, b"stamp", is_valid, || FIXTURE), FIXTURE);
        assert!(!missing_directory.exists());
    }

    #[cfg(unix)]
    #[test]
    fn test_write_replaces_a_temporary_symlink() {
        let directory = tempfile::tempdir().expect("Failed to create a temporary directory");
        let path = directory.path().join("fixture");
        let target = directory.path().join("target");
        fs::write(&target, b"target").expect("Failed to write the target file");
        std::os::unix::fs::symlink(&target, path.with_added_extension("tmp")).expect("Failed to create the symlink");
        let stamp = b"stamp";

        assert_eq!(load_or_build(&path, stamp, is_valid, || FIXTURE), FIXTURE);
        assert_eq!(fs::read(&target).expect("Failed to read the target file"), b"target");
        assert_eq!(
            fs::read(&path).expect("Failed to read the fixture file"),
            to_bytes(stamp, &FIXTURE).expect("Failed to serialize the fixture")
        );
    }

    #[test]
    fn test_invalid_file_is_rebuilt() {
        let directory = tempfile::tempdir().expect("Failed to create a temporary directory");
        let path = directory.path().join("fixture");
        let stamp = b"stamp";
        let bytes = to_bytes(stamp, &FIXTURE).expect("Failed to serialize the fixture");
        let rejected_bytes = to_bytes(stamp, &(7u64, 8u64)).expect("Failed to serialize the fixture");

        // A truncated file, and a file that holds a fixture that `is_valid` rejects.
        for invalid in [&bytes[..bytes.len() - 1], &rejected_bytes[..]] {
            fs::write(&path, invalid).expect("Failed to write the fixture file");
            assert_eq!(load_or_build(&path, stamp, is_valid, || FIXTURE), FIXTURE);
            assert_eq!(fs::read(&path).expect("Failed to read the fixture file"), bytes);
        }
    }

    #[test]
    fn test_rejects_invalid_bytes() {
        let stamp = b"stamp";
        let bytes = to_bytes(stamp, &FIXTURE).expect("Failed to serialize the fixture");
        assert_eq!(from_bytes(&bytes, stamp, is_valid), Some(FIXTURE));

        // A different stamp.
        assert!(from_bytes(&bytes, b"stamq", is_valid).is_none());
        // Missing bytes.
        assert!(from_bytes(&[], stamp, is_valid).is_none());
        assert!(from_bytes(stamp, stamp, is_valid).is_none());
        assert!(from_bytes(&bytes[..bytes.len() - 1], stamp, is_valid).is_none());
        // Trailing bytes.
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(from_bytes(&extended, stamp, is_valid).is_none());
        // A fixture that `is_valid` rejects.
        let other_bytes = to_bytes(stamp, &(7u64, 8u64)).expect("Failed to serialize the fixture");
        assert!(from_bytes(&other_bytes, stamp, is_valid).is_none());
    }
}
