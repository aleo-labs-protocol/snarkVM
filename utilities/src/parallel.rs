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
        use rayon::prelude::*;
        execute_with_max_available_threads(|| self.jobs.into_par_iter().map(|f| f()).collect())
    }
}

impl<T> Default for ExecutionPool<'_, T> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn max_available_threads() -> usize {
    // Read on every call, not cached: this is the size of the caller's pool, which may be
    // smaller than the global one, such as a pool `execute_with_threads` installs.
    rayon::current_num_threads()
}

/// Runs `f` in the caller's rayon pool, or in a new pool of `max_available_threads()` threads
/// when the caller is not in one.
///
/// To run single-threaded, call snarkVM inside a 1-thread pool:
/// `ThreadPoolBuilder::new().num_threads(1).use_current_thread().build()?.install(..)`.
/// With `use_current_thread()`, the work runs on the calling thread and its stack. Without it, the
/// work runs on a new thread with the default stack size (2 MiB unless `RUST_MIN_STACK` is set),
/// so a caller with deep recursion, such as circuit synthesis, should also set `stack_size`.
#[inline(always)]
#[cfg(not(target_family = "wasm"))]
pub fn execute_with_max_available_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send) -> T {
    execute_with_threads(f, max_available_threads())
}

/// Runs `f` on the calling thread. On wasm, `ThreadPoolBuilder::build` fails because no thread can be
/// spawned; only rayon's global pool falls back to the calling thread.
#[inline(always)]
#[cfg(target_family = "wasm")]
pub fn execute_with_max_available_threads<T>(f: impl FnOnce() -> T + Send) -> T {
    f()
}

#[cfg(not(target_family = "wasm"))]
#[inline(always)]
fn execute_with_threads<T: Sync + Send>(f: impl FnOnce() -> T + Send, num_threads: usize) -> T {
    if rayon::current_thread_index().is_none() {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(num_threads).build().unwrap();
        pool.install(f)
    } else {
        f()
    }
}

/// Creates a parallel iterator over refs.
#[macro_export]
macro_rules! cfg_iter {
    ($e: expr) => {{ $e.par_iter() }};

    ($e: expr, $min: expr) => {{ $e.par_iter().with_min_len($min) }};
}

/// Creates a parallel iterator over mut refs.
#[macro_export]
macro_rules! cfg_iter_mut {
    ($e: expr) => {{ $e.par_iter_mut() }};

    ($e: expr, $min: expr) => {{ $e.par_iter_mut().with_min_len($min) }};
}

/// Creates a parallel iterator.
#[macro_export]
macro_rules! cfg_into_iter {
    ($e: expr) => {{ $e.into_par_iter() }};
}

/// Returns an iterator over `chunk_size` elements of the slice at a
/// time.
#[macro_export]
macro_rules! cfg_chunks {
    ($e: expr, $size: expr) => {{
        $e.par_chunks($size)
    }};
}

/// Returns an iterator over `chunk_size` elements of the slice at a time.
#[macro_export]
macro_rules! cfg_chunks_mut {
    ($e: expr, $size: expr) => {{
        $e.par_chunks_mut($size)
    }};
}

/// Creates a parallel iterator from an iterator.
#[macro_export]
macro_rules! cfg_par_bridge {
    ($e: expr) => {{ $e.par_bridge() }};
}

/// Applies the reduce operation over an iterator.
#[macro_export]
macro_rules! cfg_reduce {
    ($e: expr, $default: expr, $op: expr) => {{ $e.reduce($default, $op) }};
}

/// Applies `reduce_with` over a parallel iterator.
#[macro_export]
macro_rules! cfg_reduce_with {
    ($e: expr, $op: expr) => {{ $e.reduce_with($op) }};
}

/// Turns a collection into an iterator.
#[macro_export]
macro_rules! cfg_keys {
    ($e: expr) => {{ $e.par_keys() }};
}

/// Turns a collection into an iterator.
#[macro_export]
macro_rules! cfg_values {
    ($e: expr) => {{ $e.par_values() }};
}

/// Find an element `e` where `lambda(e)` evalutes to true (if any).
///
/// # Notes
/// - This returns at most one entry that satisfies the given condition, not necessarily the first one.
/// - `closure` must be a lambda function returning a boolean, e.g., `|e| e > 0`.
#[macro_export]
macro_rules! cfg_find {
    ($object:expr, $closure:expr) => {{ $object.par_values().find_any($closure) }};
}

/// Applies a function and returns an entry where `lambda(e)` is not None.
///
/// # Notes
/// - This returns at most one entry that satisfies the given condition, not necessarily the first one.
/// - `closure` must be a lambda function returning Option, e.g., `|e| Some(e)`.
#[macro_export]
macro_rules! cfg_find_map {
    ($object:expr, $closure:expr) => {{ $object.par_values().filter_map($closure).find_any(|_| true) }};
}

/// Applies fold to the iterator
#[macro_export]
macro_rules! cfg_zip_fold {
    ($self: expr, $other: expr, $init: expr, $op: expr, $type: ty) => {{ $self.zip_eq($other).fold($init, $op).sum::<$type>() }};
}

/// Performs an unstable sort
#[macro_export]
macro_rules! cfg_sort_unstable_by {
    ($self: expr, $closure: expr) => {{
        $self.par_sort_unstable_by($closure);
    }};
}

/// Performs a sort that caches the extracted keys
#[macro_export]
macro_rules! cfg_sort_by_cached_key {
    ($self: expr, $closure: expr) => {{
        $self.par_sort_by_cached_key($closure);
    }};
}

/// Returns a sorted, by-value iterator for the given IndexMap/IndexSet
#[macro_export]
macro_rules! cfg_sorted_by {
    ($self: expr, $closure: expr) => {{ $self.par_sorted_by($closure) }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_available_threads_matches_global_pool() {
        assert_eq!(max_available_threads(), rayon::current_num_threads());
    }

    #[test]
    fn max_available_threads_matches_installed_pool() {
        // On SMT hosts, this exceeds the physical core count.
        let logical = std::thread::available_parallelism().map_or(1, |n| n.get());
        for num_threads in [1, 2, logical] {
            // Pool construction fails only if the OS cannot spawn threads.
            let pool = rayon::ThreadPoolBuilder::new().num_threads(num_threads).build().unwrap();
            assert_eq!(pool.install(max_available_threads), num_threads);
        }
    }
}
