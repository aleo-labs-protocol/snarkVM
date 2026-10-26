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

pub struct ExecutionPool<'a, T> {
    jobs: Vec<Box<dyn 'a + FnOnce() -> T + Send>>,
}

impl<'a, T> ExecutionPool<'a, T> {
    pub fn new() -> Self {
        Self { jobs: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self { jobs: Vec::with_capacity(cap) }
    }

    pub fn add_job<F: 'a + FnOnce() -> T + Send>(&mut self, f: F) {
        self.jobs.push(Box::new(f));
    }

    pub fn execute_all(self) -> Vec<T>
    where
        T: Send + Sync,
    {
        #[cfg(not(feature = "serial"))]
        {
            use rayon::prelude::*;
            execute_with_max_available_threads(|| self.jobs.into_par_iter().map(|f| f()).collect())
        }
        #[cfg(feature = "serial")]
        {
            self.jobs.into_iter().map(|f| f()).collect()
        }
    }
}

impl<T> Default for ExecutionPool<'_, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "serial"))]
pub fn max_available_threads() -> usize {
    use aleo_std::Cpu;
    use std::sync::OnceLock;

    // On Linux, `num_cpus::get_physical` reads and parses `/proc/cpuinfo` on every call, which
    // takes milliseconds on a many-core machine. Hot paths such as SNARK verification call this
    // function several times per proof.
    static INTEL_PHYSICAL_CORES: OnceLock<Option<usize>> = OnceLock::new();
    let intel_physical_cores = *INTEL_PHYSICAL_CORES.get_or_init(|| match aleo_std::get_cpu() {
        Cpu::Intel => Some(num_cpus::get_physical()),
        Cpu::AMD | Cpu::Unknown => None,
    });

    // Read on every call, not cached: this is the size of the caller's pool, which may be
    // smaller than the global one, such as a pool `execute_with_threads` installs.
    let rayon_threads = rayon::current_num_threads();
    intel_physical_cores.map_or(rayon_threads, |cores| cores.min(rayon_threads))
}

#[inline(always)]
#[cfg(not(any(feature = "serial", feature = "wasm")))]
pub fn execute_with_max_available_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send) -> T {
    execute_with_threads(f, max_available_threads())
}

#[inline(always)]
#[cfg(any(feature = "serial", feature = "wasm"))]
pub fn execute_with_max_available_threads<T>(f: impl FnOnce() -> T + Send) -> T {
    f()
}

#[cfg(not(any(feature = "serial", feature = "wasm")))]
#[inline(always)]
fn execute_with_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    if rayon::current_thread_index().is_none() {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(num_threads).build().unwrap();
        pool.install(f)
    } else {
        f()
    }
}

/// Creates parallel iterator over refs if `parallel` feature is enabled.
#[macro_export]
macro_rules! cfg_iter {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_iter();

        #[cfg(feature = "serial")]
        let result = $e.iter();

        result
    }};

    ($e: expr, $min: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_iter().with_min_len($min);

        #[cfg(feature = "serial")]
        let result = $e.iter();

        result
    }};
}

/// Creates parallel iterator over mut refs if `parallel` feature is enabled.
#[macro_export]
macro_rules! cfg_iter_mut {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_iter_mut();

        #[cfg(feature = "serial")]
        let result = $e.iter_mut();

        result
    }};

    ($e: expr, $min: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_iter_mut().with_min_len($min);

        #[cfg(feature = "serial")]
        let result = $e.iter_mut();

        result
    }};
}

/// Creates parallel iterator if `parallel` feature is enabled.
#[macro_export]
macro_rules! cfg_into_iter {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.into_par_iter();

        #[cfg(feature = "serial")]
        let result = $e.into_iter();

        result
    }};
}

/// Returns an iterator over `chunk_size` elements of the slice at a
/// time.
#[macro_export]
macro_rules! cfg_chunks {
    ($e: expr, $size: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_chunks($size);

        #[cfg(feature = "serial")]
        let result = $e.chunks($size);

        result
    }};
}

/// Returns an iterator over `chunk_size` elements of the slice at a time.
#[macro_export]
macro_rules! cfg_chunks_mut {
    ($e: expr, $size: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_chunks_mut($size);

        #[cfg(feature = "serial")]
        let result = $e.chunks_mut($size);

        result
    }};
}

/// Creates parallel iterator from iterator if `parallel` feature is enabled.
#[macro_export]
macro_rules! cfg_par_bridge {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_bridge();

        #[cfg(feature = "serial")]
        let result = $e;

        result
    }};
}

/// Applies the reduce operation over an iterator.
#[macro_export]
macro_rules! cfg_reduce {
    ($e: expr, $default: expr, $op: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.reduce($default, $op);

        #[cfg(feature = "serial")]
        let result = $e.fold($default(), $op);

        result
    }};
}

/// Applies `reduce_with` or `reduce` depending on the `serial` feature.
#[macro_export]
macro_rules! cfg_reduce_with {
    ($e: expr, $op: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.reduce_with($op);

        #[cfg(feature = "serial")]
        let result = $e.reduce($op);

        result
    }};
}

/// Turns a collection into an iterator.
#[macro_export]
macro_rules! cfg_keys {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_keys();

        #[cfg(feature = "serial")]
        let result = $e.keys();

        result
    }};
}

/// Turns a collection into an iterator.
#[macro_export]
macro_rules! cfg_values {
    ($e: expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $e.par_values();

        #[cfg(feature = "serial")]
        let result = $e.values();

        result
    }};
}

/// Find an element `e` where `lambda(e)` evalutes to true (if any).
///
/// # Notes
/// - This returns at most one entry that satisfies the given condition, not necessarily the first one.
/// - `closure` must be a lambda function returning a boolean, e.g., `|e| e > 0`.
#[macro_export]
macro_rules! cfg_find {
    ($object:expr, $closure:expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $object.par_values().find_any($closure);

        #[cfg(feature = "serial")]
        let result = $object.values().find($closure);

        result
    }};
}

/// Applies a function and returns an entry where `lambda(e)` is not None.
///
/// # Notes
/// - This returns at most one entry that satisfies the given condition, not necessarily the first one.
/// - `closure` must be a lambda function returning Option, e.g., `|e| Some(e)`.
#[macro_export]
macro_rules! cfg_find_map {
    ($object:expr, $closure:expr) => {{
        #[cfg(not(feature = "serial"))]
        let result = $object.par_values().filter_map($closure).find_any(|_| true);

        #[cfg(feature = "serial")]
        let result = $object.values().find_map($closure);

        result
    }};
}

/// Applies fold to the iterator
#[macro_export]
macro_rules! cfg_zip_fold {
    ($self: expr, $other: expr, $init: expr, $op: expr, $type: ty) => {{
        let default = $init;

        #[cfg(feature = "serial")]
        let default = $init();
        let result = $self.zip_eq($other).fold(default, $op);

        #[cfg(not(feature = "serial"))]
        let result = result.sum::<$type>();

        result
    }};
}

/// Performs an unstable sort
#[macro_export]
macro_rules! cfg_sort_unstable_by {
    ($self: expr, $closure: expr) => {{
        #[cfg(feature = "serial")]
        $self.sort_unstable_by($closure);

        #[cfg(not(feature = "serial"))]
        $self.par_sort_unstable_by($closure);
    }};
}

/// Performs a sort that caches the extracted keys
#[macro_export]
macro_rules! cfg_sort_by_cached_key {
    ($self: expr, $closure: expr) => {{
        #[cfg(feature = "serial")]
        $self.sort_by_cached_key($closure);

        #[cfg(not(feature = "serial"))]
        $self.par_sort_by_cached_key($closure);
    }};
}

/// Returns a sorted, by-value iterator for the given IndexMap/IndexSet
#[macro_export]
macro_rules! cfg_sorted_by {
    ($self: expr, $closure: expr) => {{
        #[cfg(feature = "serial")]
        {
            $self.sorted_by($closure)
        }

        #[cfg(not(feature = "serial"))]
        {
            $self.par_sorted_by($closure)
        }
    }};
}

#[cfg(all(test, not(feature = "serial")))]
mod tests {
    use super::*;
    use aleo_std::Cpu;

    #[test]
    fn max_available_threads_matches_uncached_count() {
        let rayon_threads = rayon::current_num_threads();
        let expected = match aleo_std::get_cpu() {
            Cpu::Intel => num_cpus::get_physical().min(rayon_threads),
            Cpu::AMD | Cpu::Unknown => rayon_threads,
        };
        assert_eq!(max_available_threads(), expected);
        assert_eq!(max_available_threads(), expected);
    }
}
