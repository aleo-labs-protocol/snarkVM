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
    ffi::OsStr,
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
    str,
};

use walkdir::WalkDir;

// The following license text that should be present at the beginning of every source file.
const EXPECTED_LICENSE_TEXT: &[u8] = include_bytes!("../.resources/license_header");

// The following directories will be excluded from the license scan.
const DIRS_TO_SKIP: [&str; 4] = [".cargo", ".git", ".github", "target"];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportOfInterest {
    Locktick,
    ParkingLot,
    Tokio,
}

fn check_locktick_imports<P: AsRef<Path>>(path: P) {
    let mut iter = WalkDir::new(path).into_iter();
    while let Some(entry) = iter.next() {
        let entry = entry.unwrap();
        let entry_type = entry.file_type();

        // Skip the specified directories.
        if entry_type.is_dir() && DIRS_TO_SKIP.contains(&entry.file_name().to_str().unwrap_or("")) {
            iter.skip_current_dir();

            continue;
        }

        let path = entry.path();

        // Ignore non-rs
        if path.extension() != Some(OsStr::new("rs")) {
            continue;
        }

        // Read the entire file.
        let file = fs::read_to_string(path).unwrap();

        // Prepare a filtered line iterator.
        let lines = file
            .lines()
            .filter(|l| !l.is_empty()) // Ignore empty lines.
            .skip_while(|l| !l.starts_with("use")) // Skip the license etc.
            .take_while(|l| { // Process the section containing import statements.
                l.starts_with("use")
                    || l.starts_with("#[cfg")
                    || l.starts_with("//")
                    || *l == "};"
                    || l.starts_with(|c: char| c.is_ascii_whitespace())
            });

        // The currently processed import of interest.
        let mut import_of_interest: Option<ImportOfInterest> = None;
        // This value not being zero at the end of the imports suggests a missing locktick import.
        let mut lock_balance: i8 = 0;

        // Process the filtered lines.
        for line in lines {
            // Check if this is a lock-related import.
            if import_of_interest.is_none() {
                if line.starts_with("use locktick::") {
                    import_of_interest = Some(ImportOfInterest::Locktick);
                } else if line.starts_with("use parking_lot::") {
                    import_of_interest = Some(ImportOfInterest::ParkingLot);
                } else if line.starts_with("use tokio::") {
                    import_of_interest = Some(ImportOfInterest::Tokio);
                }
            }

            // Skip irrelevant imports.
            let Some(ioi) = import_of_interest else {
                continue;
            };

            // Modify the lock balance based on the type of the relevant import.
            if [ImportOfInterest::ParkingLot, ImportOfInterest::Tokio].contains(&ioi) {
                lock_balance += line.matches("Mutex").count() as i8;
                lock_balance += line.matches("RwLock").count() as i8;

                // A correction in case of the `use tokio::Mutex as TMutex` convention.
                if line.contains("TMutex") {
                    lock_balance -= 1;
                }

                // Account for lock guards, which do not have a locktick counterpart.
                if line.contains("MutexGuard") {
                    lock_balance -= 1;
                }
                if line.contains("RwLockReadGuard") {
                    lock_balance -= 1;
                }
                if line.contains("RwLockWriteGuard") {
                    lock_balance -= 1;
                }
            } else if ioi == ImportOfInterest::Locktick {
                // Use `matches` instead of just `contains` here, as more than a single
                // lock type entry is possible in a locktick import.
                lock_balance -= line.matches("Mutex").count() as i8;
                lock_balance -= line.matches("RwLock").count() as i8;

                // A correction in case of the `use tokio::Mutex as TMutex` convention.
                if line.contains("TMutex") {
                    lock_balance += 1;
                }
            }

            // Register the end of an import statement.
            if line.ends_with(";") {
                import_of_interest = None;
            }
        }

        // If the file has a lock import "imbalance", print it out and increment the counter.
        assert!(
            lock_balance == 0,
            "The locks in \"{}\" don't seem to have `locktick` counterparts!",
            entry.path().display()
        );
    }
}

fn check_file_licenses<P: AsRef<Path>>(path: P) {
    let path = path.as_ref();

    // Perform the license year check if on Linux.
    if cfg!(target_os = "linux") {
        // Get the current year from the OS
        let os_year = Command::new("date")
            .arg("+%Y") // ask only for the year
            .output()
            .expect("Failed to execute 'date' command");
        let current_year = str::from_utf8(&os_year.stdout).expect("Date output was not valid UTF-8").trim();

        // Check if the end of the year range in the license matches the OS year.
        let license_year = str::from_utf8(&EXPECTED_LICENSE_TEXT[22..][..4]).unwrap();
        assert_eq!(license_year, current_year, "The license year doesn't match the current OS year");
    }

    let mut iter = WalkDir::new(path).into_iter();
    while let Some(entry) = iter.next() {
        let entry = entry.unwrap();
        let entry_type = entry.file_type();

        // Skip the specified directories.
        if entry_type.is_dir() && DIRS_TO_SKIP.contains(&entry.file_name().to_str().unwrap_or("")) {
            iter.skip_current_dir();

            continue;
        }

        // Check all files with the ".rs" extension.
        if entry_type.is_file() && entry.file_name().to_str().unwrap_or("").ends_with(".rs") {
            let file = File::open(entry.path()).unwrap();
            let mut contents = Vec::with_capacity(EXPECTED_LICENSE_TEXT.len());
            file.take(EXPECTED_LICENSE_TEXT.len() as u64).read_to_end(&mut contents).unwrap();

            assert!(
                contents == EXPECTED_LICENSE_TEXT,
                "The license in \"{}\" is either missing or it doesn't match the expected string!",
                entry.path().display()
            );
        }
    }
}

// `CARGO_MANIFEST_DIR` rather than ".": a build script's working directory was
// the package root by definition, a test binary's is only that when cargo runs
// it, and against the wrong tree these walk nothing and pass.

#[test]
fn licenses_are_present() {
    check_file_licenses(env!("CARGO_MANIFEST_DIR"));
}

#[test]
fn locks_have_locktick_counterparts() {
    check_locktick_imports(env!("CARGO_MANIFEST_DIR"));
}
