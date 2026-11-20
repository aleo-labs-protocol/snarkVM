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

use std::{fs::File, io::Read, path::Path, process::Command, str};

use walkdir::WalkDir;

// The following license text that should be present at the beginning of every source file.
const EXPECTED_LICENSE_TEXT: &[u8] = include_bytes!("../.resources/license_header");

// The following directories will be excluded from the license scan.
const DIRS_TO_SKIP: [&str; 4] = [".cargo", ".git", ".github", "target"];

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

// Walks `CARGO_MANIFEST_DIR`: a test binary's working directory is the package root only when
// cargo runs it, and against another tree the walk finds nothing and passes.
#[test]
fn licenses_are_present() {
    check_file_licenses(env!("CARGO_MANIFEST_DIR"));
}
