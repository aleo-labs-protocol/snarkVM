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

use crate::{Constant, Constraints, Measurement, Private, Public};

use core::fmt::Debug;
use std::{
    env,
    fmt::Display,
    fs,
    ops::Range,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};

/// Serializes the read-modify-write cycle that rewrites a source file.
/// Tests in one binary run in parallel, and several of them can reach the same file.
///
/// It is per-process, so it does not cover a runner that gives each test its own process, as `cargo nextest`
/// does. `update_count` writes through a rename so that a reader in another process never observes a partly
/// written file; what such a reader can still do is read before another process writes and then overwrite it,
/// losing that edit and needing the run repeated. Only a cross-process lock would close that.
static UPDATE_LOCK: Mutex<()> = Mutex::new(());

/// The workspace root, which `file!` paths are relative to while a test's working directory is its own package.
/// Recovering it stats a `Cargo.toml` at every level above this crate; an update run resolves hundreds of paths,
/// so the answer is memoized. This is a memo of a pure function of `CARGO_MANIFEST_DIR`, not mutable state.
static WORKSPACE_ROOT: OnceLock<PathBuf> = OnceLock::new();

/// To update the arguments to `count_is!`, run cargo test with the `UPDATE_COUNT` flag set to the name of the file containing the macro invocation.
/// e.g. `UPDATE_COUNT=boolean cargo test
/// See <https://github.com/ProvableHQ/snarkVM/pull/1688> for more details.
#[macro_export]
macro_rules! count_is {
    ($num_constants:literal, $num_public:literal, $num_private:literal, $num_constraints:literal) => {
        $crate::UpdatableCount {
            constant: $crate::Measurement::Exact($num_constants),
            public: $crate::Measurement::Exact($num_public),
            private: $crate::Measurement::Exact($num_private),
            constraints: $crate::Measurement::Exact($num_constraints),
            file: file!(),
            line: line!(),
            column: column!(),
        }
    };
    (<=$num_constants:literal, $num_public:literal, $num_private:literal, $num_constraints:literal) => {
        $crate::UpdatableCount {
            constant: $crate::Measurement::UpperBound($num_constants),
            public: $crate::Measurement::Exact($num_public),
            private: $crate::Measurement::Exact($num_private),
            constraints: $crate::Measurement::Exact($num_constraints),
            file: file!(),
            line: line!(),
            column: column!(),
        }
    };
}

/// To update the arguments to `count_less_than!`, run cargo test with the `UPDATE_COUNT` flag set to the name of the file containing the macro invocation.
/// e.g. `UPDATE_COUNT=boolean cargo test
/// See <https://github.com/ProvableHQ/snarkVM/pull/1688> for more details.
#[macro_export]
macro_rules! count_less_than {
    ($num_constants:literal, $num_public:literal, $num_private:literal, $num_constraints:literal) => {
        $crate::UpdatableCount {
            constant: $crate::Measurement::UpperBound($num_constants),
            public: $crate::Measurement::UpperBound($num_public),
            private: $crate::Measurement::UpperBound($num_private),
            constraints: $crate::Measurement::UpperBound($num_constraints),
            file: file!(),
            line: line!(),
            column: column!(),
        }
    };
}

/// A helper struct for tracking the number of constants, public inputs, private inputs, and constraints.
/// Warning: Do not construct this struct directly outside of this module. Instead, use the `count_is!` and
/// `count_less_than!` macros.
#[derive(Copy, Clone, Debug)]
pub struct UpdatableCount {
    pub constant: Constant,
    pub public: Public,
    pub private: Private,
    pub constraints: Constraints,
    #[doc(hidden)]
    pub file: &'static str,
    #[doc(hidden)]
    pub line: u32,
    #[doc(hidden)]
    pub column: u32,
}

impl Display for UpdatableCount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Constants: {}, Public: {}, Private: {}, Constraints: {}",
            self.constant, self.public, self.private, self.constraints
        )
    }
}

impl UpdatableCount {
    /// Returns `true` if the values matches the `Measurement`s in `UpdatableCount`.
    ///
    /// For an `Exact` metric, `value` must be equal to the exact value defined by the metric.
    /// For a `Range` metric, `value` must be satisfy lower bound and the upper bound.
    /// For an `UpperBound` metric, `value` must be satisfy the upper bound.
    pub fn matches(&self, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) -> bool {
        self.constant.matches(num_constants)
            && self.public.matches(num_public)
            && self.private.matches(num_private)
            && self.constraints.matches(num_constraints)
    }

    /// If all values match, do nothing.
    /// If all values metrics do not match:
    ///    - If the update condition is satisfied, then update the macro invocation that constructed this `UpdatableCount`.
    ///    - Otherwise, panic.
    pub fn assert_matches(&self, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        if self.matches(num_constants, num_public, num_private, num_constraints) {
            return;
        }
        let query_string = env::var("UPDATE_COUNT").ok();
        self.assert_matches_with_query(
            query_string.as_deref(),
            num_constants,
            num_public,
            num_private,
            num_constraints,
        );
    }

    /// Implements `assert_matches` for a given `UPDATE_COUNT` query string, where `None` stands for an unset
    /// `UPDATE_COUNT`, under which nothing is updated.
    ///
    /// The values are assumed not to match; `assert_matches` checks that before calling in, and `Measurement::matches`
    /// reports each mismatching measurement on stderr, so checking again would report every one of them twice.
    fn assert_matches_with_query(
        &self,
        query_string: Option<&str>,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
    ) {
        match query_string {
            // If `UPDATE_COUNT` is set and the `query_string` matches the file containing the macro invocation
            // that constructed this `UpdatableCount`, then update the macro invocation.
            Some(query_string) if self.file.contains(query_string) => {
                self.update_count(num_constants, num_public, num_private, num_constraints);
            }
            // Otherwise, error.
            _ => {
                println!(
                    "\n
\x1b[1m\x1b[91merror\x1b[97m: Count does not match\x1b[0m
   \x1b[1m\x1b[34m-->\x1b[0m {}:{}:{}
\x1b[1mExpected\x1b[0m:
----
{}
----
\x1b[1mActual\x1b[0m:
----
Constants: {}, Public: {}, Private: {}, Constraints: {}
----
",
                    self.file, self.line, self.column, self, num_constants, num_public, num_private, num_constraints,
                );
                // Use resume_unwind instead of panic!() to prevent a backtrace, which is unnecessary noise.
                std::panic::resume_unwind(Box::new(()));
            }
        }
    }

    /// Rewrites the arguments of the macro invocation that constructed this `UpdatableCount` so that they admit
    /// the given measured values.
    ///
    /// The arguments currently in the file, not the ones this binary was compiled with, are the starting point.
    /// A run updates a given invocation many times -- `check_cast` asserts the same count once per sampled input --
    /// and an upper bound has to accumulate the maximum over all of them. Re-reading also makes a second run over
    /// an already-updated file a no-op rather than a revert.
    fn update_count(&self, num_constants: u64, num_public: u64, num_private: u64, num_constraints: u64) {
        // Resolving the path depends on nothing the lock protects, so it stays outside.
        let path = self.absolute_path();
        let position = self.position();

        // Hold the lock across the read and the write: two threads updating the same file would otherwise each
        // write back a copy that lacks the other's edit.
        let guard = UPDATE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut text = fs::read_to_string(&path).unwrap();
        let range = self.locate(&text);
        assert!(
            range.start < range.end,
            "Could not locate the arguments of the macro invocation at {position}. \
             It must be written on one line, with its closing parenthesis after its opening one."
        );
        let arguments = Arguments::parse(&text[range.clone()], &position);

        let updated_count = self.updated(arguments.values, [num_constants, num_public, num_private, num_constraints]);
        let updated_values = updated_count.values();

        // If the arguments in the file already admit these values, there is nothing to write.
        if updated_values == arguments.values {
            return;
        }

        arguments.rewrite(&mut text, range.start, updated_values);
        // Write a sibling file and rename over the original, so that a reader the lock does not cover -- a test
        // in another process -- sees either the old file or the new one, never the truncation `fs::write` leaves
        // in between. The sibling is in the same directory, so the rename is within one filesystem, and its name
        // carries the process id, so two processes cannot collide on it.
        let scratch = path.with_extension(format!("{}.tmp", std::process::id()));
        fs::write(&scratch, &text).unwrap();
        fs::rename(&scratch, &path).unwrap();

        // Nothing below touches the file, so let the next updater in.
        drop(guard);

        // Print the difference between the original and updated counts.
        let difference = updated_count.difference_between(self);
        println!(
            "\n
\x1b[1m\x1b[33mwarning\x1b[97m: Updated count\x1b[0m
   \x1b[1m\x1b[34m-->\x1b[0m {}:{}:{}
\x1b[1mOriginal count\x1b[0m:
----
{}
----
\x1b[1mUpdated count\x1b[0m:
----
{}
----
\x1b[1mDifference between updated and original\x1b[0m:
----
Constants: {}, Public: {}, Private: {}, Constraints: {}
----
",
            self.file,
            self.line,
            self.column,
            self,
            updated_count,
            difference.0,
            difference.1,
            difference.2,
            difference.3
        );
    }

    /// Returns the four measurements as a plain array, in the order the macro takes them.
    fn values(&self) -> [u64; 4] {
        let value = |measurement| match measurement {
            Measurement::Exact(value) | Measurement::UpperBound(value) => value,
            Measurement::Range(..) => panic!("`UpdatableCount` does not support `Measurement::Range`."),
        };
        [value(self.constant), value(self.public), value(self.private), value(self.constraints)]
    }

    /// Returns the count that admits `measured`, starting from `on_disk`, the values currently in the source file.
    /// An exact measurement becomes the measured value; an upper bound becomes the larger of the two, which is how
    /// a bound accumulates the maximum over the many asserts one invocation sees.
    ///
    /// Which measurement each value becomes is decided by `self`, and so by the macro that was invoked:
    /// `count_less_than!` writes no `<=` in the source, so the source text alone does not say.
    fn updated(&self, on_disk: [u64; 4], measured: [u64; 4]) -> Self {
        let updated = |measurement, on_disk, measured| match measurement {
            Measurement::Exact(..) => Measurement::Exact(measured),
            Measurement::UpperBound(..) => Measurement::UpperBound(std::cmp::max(measured, on_disk)),
            Measurement::Range(..) => panic!("`UpdatableCount` does not support `Measurement::Range`."),
        };
        Self {
            constant: updated(self.constant, on_disk[0], measured[0]),
            public: updated(self.public, on_disk[1], measured[1]),
            private: updated(self.private, on_disk[2], measured[2]),
            constraints: updated(self.constraints, on_disk[3], measured[3]),
            ..*self
        }
    }

    /// Returns the path of the file containing the macro invocation that constructed this `UpdatableCount`.
    ///
    /// `file!` expands to a path relative to the workspace root, while a test's working directory is the directory
    /// of the package it belongs to, so the workspace root has to be recovered to make the path usable.
    fn absolute_path(&self) -> PathBuf {
        let path = Path::new(self.file);
        match path.is_absolute() {
            true => path.to_owned(),
            false => WORKSPACE_ROOT
                .get_or_init(|| {
                    // Heuristic, see https://github.com/rust-lang/cargo/issues/3946.
                    // Taken from the `expect-test` crate, MIT OR Apache-2.0.
                    Path::new(&env!("CARGO_MANIFEST_DIR"))
                        .ancestors()
                        .filter(|it| it.join("Cargo.toml").exists())
                        .last()
                        .unwrap()
                        .to_owned()
                })
                .join(path),
        }
    }

    /// Returns `file:line:column`, to say which macro invocation a diagnostic is about.
    fn position(&self) -> String {
        format!("{}:{}:{}", self.file, self.line, self.column)
    }

    /// Given a string containing the contents of a file, `locate` returns a range delimiting the arguments
    /// to the macro invocation that constructed this `UpdatableCount`.
    /// The beginning of the range corresponds to the opening parenthesis of the macro invocation.
    /// The end of the range corresponds to the closing parenthesis of the macro invocation.
    /// ```ignore
    ///              count_is!(0, 1, 2, 3)
    /// ```                   ^          ^
    ///           starting_index     ending_index
    ///
    /// Note: This function must always invoked with the file contents of the same file as the macro invocation.
    fn locate(&self, file: &str) -> Range<usize> {
        // `line_start` is the absolute byte offset from the beginning of the file to the beginning of the current line.
        let mut line_start = 0;
        let mut starting_index = None;
        let mut ending_index = None;
        // `split_inclusive` keeps the line terminators, which `str::lines` strips; `line_start` has to stay an
        // accurate byte offset into `file`.
        for (i, line) in file.split_inclusive('\n').enumerate() {
            if i == self.line as usize - 1 {
                // Seek past the exclamation point, then skip any whitespace and the macro delimiter to get to the opening parentheses.
                let mut argument_character_indices = line.char_indices().skip((self.column - 1).try_into().unwrap())
                    .skip_while(|&(_, c)| c != '!') // Skip up to the exclamation point.
                    .skip(1) // Skip `!`.
                    .skip_while(|(_, c)| c.is_whitespace()); // Skip any whitespace.

                // Set `starting_index` to the absolute position of the opening parenthesis in `file`.
                starting_index = Some(
                    line_start
                        + argument_character_indices
                            .next()
                            .unwrap_or_else(|| {
                                panic!("Could not find the beginning of the macro invocation at {}", self.position())
                            })
                            .0,
                );
            }

            if starting_index.is_some() {
                // At this point, we have found the opening parentheses, so we continue to skip all characters until the closing parentheses.
                match line.char_indices().find(|&(_, c)| c == ')') {
                    None => (), // Do nothing. This means that the closing parentheses was not found on the same line as the opening parentheses.
                    Some((offset, _)) => {
                        // Note that the `+ 1` is to account for the fact that `std::ops::Range` is exclusive on the upper bound.
                        ending_index = Some(line_start + offset + 1);
                        break;
                    }
                }
            }
            line_start += line.len();
        }

        Range {
            start: starting_index.unwrap_or_else(|| {
                panic!("Could not find the beginning of the macro invocation at {}", self.position())
            }),
            end: ending_index
                .unwrap_or_else(|| panic!("Could not find the ending of the macro invocation at {}", self.position())),
        }
    }

    /// Computes the difference between the number of constants, public, private, and constraints of `self` and those of `other`.
    pub fn difference_between(&self, other: &Self) -> (i64, i64, i64, i64) {
        let difference = |self_measurement, other_measurement| match (self_measurement, other_measurement) {
            (Measurement::Exact(self_value), Measurement::Exact(other_value))
            | (Measurement::UpperBound(self_value), Measurement::UpperBound(other_value)) => {
                // Note: This assumes that the number of constants, public, private, and constraints do not exceed `i64::MAX`.
                (self_value as i64) - (other_value as i64)
            }
            _ => panic!(
                "Cannot compute difference for `Measurement::Range` or if both measurements are of different types."
            ),
        };
        (
            difference(self.constant, other.constant),
            difference(self.public, other.public),
            difference(self.private, other.private),
            difference(self.constraints, other.constraints),
        )
    }
}

/// The four arguments of a `count_is!` or `count_less_than!` invocation, located in the source file.
///
/// An update rewrites the integer literals whose values changed and nothing else, so every other byte of the
/// argument list survives it verbatim: the `<=` of the `count_is!(<=N, ..)` arm, the spacing, and the `_`
/// separators of any argument that did not change. Regenerating the whole argument list instead would drop the
/// `<=` and silently rewrite an upper bound into an exact count.
#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    /// The value of each argument.
    values: [u64; 4],
    /// The byte range of each argument's integer literal, relative to the start of the text `parse` was given.
    literals: [(usize, usize); 4],
}

impl Arguments {
    /// Parses the text delimited by `UpdatableCount::locate`, i.e. `(1, 2, 3, 4)` or `(<=1, 2, 3, 4)`.
    /// `position` is `file:line:column`, so that a diagnostic names the malformed invocation.
    fn parse(text: &str, position: &str) -> Self {
        let inner = text.strip_prefix('(').and_then(|text| text.strip_suffix(')')).unwrap_or_else(|| {
            // `macro_rules!` also accepts `[]` and `{}`, which `locate` would run past to some later `)`.
            // Refusing here is the point: the alternative is rewriting whatever span that lands on.
            panic!(
                "The macro invocation at {position} is not delimited by parentheses: `{text}`. \
                 `count_is!` and `count_less_than!` have to be invoked with `(..)` to be updatable."
            )
        });
        let mut values = [0; 4];
        let mut literals = [(0, 0); 4];
        // `inner` begins one byte into `text`, past the opening parenthesis.
        let mut offset = 1;
        let mut arguments = inner.split(',');
        for (i, (value, literal)) in values.iter_mut().zip(literals.iter_mut()).enumerate() {
            let argument = arguments.next().unwrap_or_else(|| panic!("Macro argument {i} is missing at {position}."));
            // Step past the leading whitespace, and past the `<=` of the upper-bound arm of `count_is!`.
            let mut start = argument.len() - argument.trim_start().len();
            if let Some(rest) = argument[start..].strip_prefix("<=") {
                start = argument.len() - rest.trim_start().len();
            }
            let text = argument[start..].trim_end();
            *literal = (offset + start, offset + start + text.len());
            // Rust integer literals admit `_` separators, which `u64::from_str` does not.
            *value = text.replace('_', "").parse().unwrap_or_else(|_| {
                panic!("Macro argument {i} at {position} is not a decimal integer literal: `{text}`")
            });
            // Step past this argument and the comma that `split` consumed.
            offset += argument.len() + 1;
        }
        assert!(arguments.next().is_none(), "The macro invocation at {position} has more than four arguments.");
        Self { values, literals }
    }

    /// Replaces the four integer literals with `values`, leaving every other byte as it was.
    /// A literal whose value has not changed is not rewritten at all, so `1_000` keeps its separator.
    /// `offset` is where the text this was parsed from starts in `source`.
    fn rewrite(&self, source: &mut String, offset: usize, values: [u64; 4]) {
        // Back to front, so that splicing one literal does not shift the range of the ones before it.
        for (i, &(start, end)) in self.literals.iter().enumerate().rev() {
            if values[i] != self.values[i] {
                source.replace_range(offset + start..offset + end, &values[i].to_string());
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    /// A source file that only these tests write to, holding one macro invocation per line and deleted when the
    /// test ends.
    ///
    /// The update path resolves an absolute `UpdatableCount::file` as-is, so a count pointed at this file rewrites
    /// it instead of the test's own source. `line` is 1-based, as in `UpdatableCount`.
    struct Fixture {
        path: &'static str,
        column: u32,
    }

    impl Fixture {
        fn new(macro_name: &str, arguments: &[&str]) -> Self {
            let path = fixture_path();
            let prefix = "        let count = ";
            let text: String =
                arguments.iter().map(|arguments| format!("{prefix}{macro_name}!{arguments};\n")).collect();
            fs::write(&path, text).unwrap();
            Self {
                // `UpdatableCount::file` is `&'static str`, which a path built at runtime is not.
                path: path.into_os_string().into_string().unwrap().leak(),
                column: (prefix.len() + 1) as u32,
            }
        }

        /// Returns a count located at the invocation on the given line.
        fn count(&self, line: u32, measurements: [Measurement<u64>; 4]) -> UpdatableCount {
            UpdatableCount {
                constant: measurements[0],
                public: measurements[1],
                private: measurements[2],
                constraints: measurements[3],
                file: self.path,
                line,
                column: self.column,
            }
        }

        /// Returns the arguments currently written on the given line.
        fn arguments(&self, line: u32) -> String {
            let text = fs::read_to_string(self.path).unwrap();
            let line = text.lines().nth(line as usize - 1).unwrap();
            line[line.find('(').unwrap()..=line.rfind(')').unwrap()].to_string()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(self.path);
        }
    }

    /// Returns a path in the temporary directory that no other test uses.
    fn fixture_path() -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        env::temp_dir().join(format!(
            "snarkvm_updatable_count_{}_{}.rs",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn exact(values: [u64; 4]) -> [Measurement<u64>; 4] {
        values.map(Measurement::Exact)
    }

    fn upper_bound(values: [u64; 4]) -> [Measurement<u64>; 4] {
        values.map(Measurement::UpperBound)
    }

    /// Returns a count at the given position. The measurements are irrelevant to `locate`.
    fn count_at(line: u32, column: u32) -> UpdatableCount {
        UpdatableCount {
            constant: Measurement::Exact(0),
            public: Measurement::Exact(0),
            private: Measurement::Exact(0),
            constraints: Measurement::Exact(0),
            file: "",
            line,
            column,
        }
    }

    #[test]
    fn check_position() {
        // A literal line number here goes stale whenever anything above it in this file moves.
        let count = count_is!(0, 0, 0, 0);
        assert_eq!(count.line, line!() - 1);
        assert_eq!(count.file, "circuit/environment/src/helpers/updatable_count.rs");
        assert_eq!(count.column, 21);
    }

    #[test]
    fn check_locate_finds_the_arguments() {
        let text = "// a\n        let count = count_is!(1, 2, 3, 4);\n";
        assert_eq!(&text[count_at(2, 21).locate(text)], "(1, 2, 3, 4)");
    }

    #[test]
    fn check_locate_finds_upper_bound_arguments() {
        let text = "let counts = count_is!(<=36085, 8, 24131, 24156);\n";
        assert_eq!(&text[count_at(1, 14).locate(text)], "(<=36085, 8, 24131, 24156)");
    }

    #[test]
    fn check_arguments_parse() {
        for (text, values) in [
            ("(1, 2, 3, 4)", [1, 2, 3, 4]),
            ("(<=36085, 8, 24131, 24156)", [36085, 8, 24131, 24156]),
            ("(1_000, 2, 3, 4)", [1000, 2, 3, 4]),
            ("(0,0,0,0)", [0, 0, 0, 0]),
        ] {
            assert_eq!(Arguments::parse(text, "test").values, values, "parsing {text}");
        }
    }

    #[test]
    fn check_arguments_rewrite_touches_only_the_literals() {
        // Everything but the digits -- the `<=`, the spacing -- has to come back out unchanged, and an
        // argument whose value did not change has to come back out exactly as it was written.
        for (text, values, expected) in [
            ("(1, 2, 3, 4)", [5, 6, 7, 8], "(5, 6, 7, 8)"),
            ("(<=36085, 8, 24131, 24156)", [5, 6, 7, 8], "(<=5, 6, 7, 8)"),
            ("(0,0,0,0)", [5, 6, 7, 8], "(5,6,7,8)"),
            ("( 1 , 2 , 3 , 4 )", [5, 6, 7, 8], "( 5 , 6 , 7 , 8 )"),
            ("(1_000, 2, 3, 4)", [1000, 5, 3, 4], "(1_000, 5, 3, 4)"),
        ] {
            let mut source = format!("prefix{text}suffix");
            Arguments::parse(text, "test").rewrite(&mut source, "prefix".len(), values);
            assert_eq!(source, format!("prefix{expected}suffix"), "rewriting {text}");
        }
    }

    #[test]
    fn check_count_passes() {
        let count = count_is!(1, 2, 3, 4);
        count.assert_matches(1, 2, 3, 4);
    }

    #[test]
    #[should_panic]
    fn check_count_fails() {
        let count = count_is!(1, 2, 3, 4);
        count.assert_matches_with_query(None, 5, 6, 7, 8);
    }

    #[test]
    #[should_panic]
    fn check_count_does_not_update_if_query_does_not_match() {
        let count = count_is!(1, 2, 3, 4);
        count.assert_matches_with_query(Some("a_file_that_is_not_this_one"), 5, 6, 7, 8);
    }

    #[test]
    fn check_count_updates_correctly() {
        let fixture = Fixture::new("count_is", &["(1, 2, 3, 4)"]);
        let count = fixture.count(1, exact([1, 2, 3, 4]));
        count.assert_matches_with_query(Some(fixture.path), 11, 12, 13, 14);
        assert_eq!(fixture.arguments(1), "(11, 12, 13, 14)");
    }

    #[test]
    fn check_count_updates_correctly_multiple_times() {
        let fixture = Fixture::new("count_is", &["(1, 2, 3, 4)"]);
        let count = fixture.count(1, exact([1, 2, 3, 4]));
        for values in [[5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16], [17, 18, 19, 20]] {
            count.assert_matches_with_query(Some(fixture.path), values[0], values[1], values[2], values[3]);
        }
        assert_eq!(fixture.arguments(1), "(17, 18, 19, 20)");
    }

    #[test]
    fn check_count_update_is_idempotent() {
        let fixture = Fixture::new("count_is", &["(1, 2, 3, 4)"]);
        let count = fixture.count(1, exact([1, 2, 3, 4]));
        count.assert_matches_with_query(Some(fixture.path), 11, 12, 13, 14);
        let after_first = fs::read_to_string(fixture.path).unwrap();
        count.assert_matches_with_query(Some(fixture.path), 11, 12, 13, 14);
        assert_eq!(fs::read_to_string(fixture.path).unwrap(), after_first);
    }

    #[test]
    fn check_count_less_than_selects_maximum() {
        let fixture = Fixture::new("count_less_than", &["(1, 2, 3, 4)"]);
        let count = fixture.count(1, upper_bound([1, 2, 3, 4]));
        for values in [[5, 18, 7, 8], [17, 10, 11, 12], [13, 6, 19, 16], [9, 18, 15, 20]] {
            count.assert_matches_with_query(Some(fixture.path), values[0], values[1], values[2], values[3]);
        }
        assert_eq!(fixture.arguments(1), "(17, 18, 19, 20)");
    }

    #[test]
    fn check_count_is_upper_bound_keeps_its_prefix() {
        // Dropping the `<=` here would rewrite the upper-bound arm of `count_is!` into the exact arm,
        // silently turning a deliberate bound into a count that fails on the next real change.
        let fixture = Fixture::new("count_is", &["(<=100, 2, 3, 4)"]);
        let count = fixture.count(1, [
            Measurement::UpperBound(100),
            Measurement::Exact(2),
            Measurement::Exact(3),
            Measurement::Exact(4),
        ]);

        // A measurement under the bound leaves the bound alone and updates the exact arguments.
        count.assert_matches_with_query(Some(fixture.path), 7, 8, 9, 10);
        assert_eq!(fixture.arguments(1), "(<=100, 8, 9, 10)");

        // A measurement over the bound raises it, still as a bound.
        count.assert_matches_with_query(Some(fixture.path), 150, 8, 9, 10);
        assert_eq!(fixture.arguments(1), "(<=150, 8, 9, 10)");
    }

    #[test]
    #[should_panic(expected = "is not delimited by parentheses")]
    fn check_bracket_delimited_invocation_is_refused() {
        // `macro_rules!` accepts `count_is![..]`, which `locate` runs past to the next `)` anywhere later in the
        // file. The update has to refuse rather than rewrite whatever span that lands on.
        let fixture = Fixture::new("count_is", &["[1, 2, 3, 4]", "(5, 6, 7, 8)"]);
        let count = fixture.count(1, exact([1, 2, 3, 4]));
        count.assert_matches_with_query(Some(fixture.path), 9, 10, 11, 12);
    }

    #[test]
    fn check_update_leaves_no_scratch_file_behind() {
        let fixture = Fixture::new("count_is", &["(1, 2, 3, 4)"]);
        let count = fixture.count(1, exact([1, 2, 3, 4]));
        count.assert_matches_with_query(Some(fixture.path), 11, 12, 13, 14);
        assert_eq!(fixture.arguments(1), "(11, 12, 13, 14)");
        let scratch = Path::new(fixture.path).with_extension(format!("{}.tmp", std::process::id()));
        assert!(!scratch.exists(), "the file written before the rename is still there: {}", scratch.display());
    }

    #[test]
    fn check_updates_to_one_file_do_not_disturb_each_other() {
        // The first update lengthens its line, which shifts the byte offset of the second invocation.
        let fixture = Fixture::new("count_is", &["(1, 2, 3, 4)", "(5, 6, 7, 8)"]);
        let first = fixture.count(1, exact([1, 2, 3, 4]));
        let second = fixture.count(2, exact([5, 6, 7, 8]));
        first.assert_matches_with_query(Some(fixture.path), 100000, 2, 3, 4);
        second.assert_matches_with_query(Some(fixture.path), 9, 10, 11, 12);
        assert_eq!(fixture.arguments(1), "(100000, 2, 3, 4)");
        assert_eq!(fixture.arguments(2), "(9, 10, 11, 12)");
    }

    #[test]
    fn check_concurrent_updates_to_one_file_all_survive() {
        const INVOCATIONS: u32 = 16;
        let fixture = Fixture::new("count_is", &vec!["(0, 0, 0, 0)"; INVOCATIONS as usize]);
        let fixture = &fixture;
        std::thread::scope(|scope| {
            for line in 1..=INVOCATIONS {
                scope.spawn(move || {
                    let count = fixture.count(line, exact([0, 0, 0, 0]));
                    count.assert_matches_with_query(Some(fixture.path), line as u64 * 100000, 1, 2, 3);
                });
            }
        });
        for line in 1..=INVOCATIONS {
            assert_eq!(fixture.arguments(line), format!("({}, 1, 2, 3)", line * 100000));
        }
    }
}
