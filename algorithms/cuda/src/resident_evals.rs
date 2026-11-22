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

//! Each proving key's round-four evaluations on the device, held while the key
//! lives.
//!
//! The registry holds keys by `Weak`, and a proof holds its key's `Arc`, so a
//! copy is freed at the first sweep after the key's last strong reference goes
//! and never while a call reads it. A lookup matches against the arrays of the
//! live key it upgraded, so the freed host memory of a dead key is never
//! matched, and `Arc::get_mut` fails while a `Weak` exists, so a live key's
//! arrays cannot change. A miss, a failed upload or more than one GPU uploads
//! the arrays for that call.

use core::ffi::c_void;
use std::sync::{
    Arc,
    LazyLock,
    Mutex,
    MutexGuard,
    Weak,
    atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
};

/// Where a key's round-four evaluations live on the host.
pub trait Evals: Send + Sync + 'static {
    /// `row`, `col` and `row_col_val` on K for each of A, B and C, as
    /// (address, bytes).
    fn evals(&self) -> [[(*const u8, usize); 3]; 3];
}

/// Asked on the first upload, so an offer never initialises the device.
// SAFETY: no arguments.
static SUPPORTED: LazyLock<bool> = LazyLock::new(|| unsafe { super::snarkvm_bases_status() }.code == 0);
static REGISTRY: Mutex<Vec<Arc<Entry>>> = Mutex::new(Vec::new());

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static UPLOADS: AtomicU64 = AtomicU64::new(0);
static UPLOAD_FAILURES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_BYTES: AtomicUsize = AtomicUsize::new(0);

/// One matrix's three arrays, end to end on device 0.
struct DeviceEvals {
    ptr: usize,
    bytes: usize,
}

impl Drop for DeviceEvals {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `snarkvm_resident_upload` and is freed
        // once. Every call that read it has returned: a call holds its
        // entry until then.
        unsafe { super::snarkvm_bases_release(self.ptr as *mut c_void) };
        RESIDENT_BYTES.fetch_sub(self.bytes, Relaxed);
    }
}

struct Entry {
    key: Weak<dyn Evals>,
    /// `None` until an upload succeeds, so a failed one is retried.
    matrices: [Mutex<Option<DeviceEvals>>; 3],
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Unlinks the dead entries, to be dropped once the lock is released:
/// dropping one frees its device copies.
fn take_dead(reg: &mut Vec<Arc<Entry>>) -> Vec<Arc<Entry>> {
    reg.extract_if(.., |e| e.key.strong_count() == 0).collect()
}

/// Registers `key`, uploading nothing. A key already registered is a no-op.
pub fn offer<K: Evals>(key: &Arc<K>) {
    let weak: Weak<dyn Evals> = Arc::downgrade(key) as Weak<K>;
    let dead = {
        let mut reg = lock(&REGISTRY);
        let dead = take_dead(&mut reg);
        if !reg.iter().any(|e| Weak::ptr_eq(&e.key, &weak)) {
            reg.push(Arc::new(Entry { key: weak, matrices: Default::default() }));
        }
        dead
    };
    drop(dead);
}

/// Frees the device copies of keys that are gone.
pub fn sweep() {
    let dead = take_dead(&mut lock(&REGISTRY));
    drop(dead);
}

/// Keeps the key and its entry alive, so it must outlive the call that
/// reads `ptr()`.
pub(crate) struct Hit {
    _key: Option<Arc<dyn Evals>>,
    _entry: Option<Arc<Entry>>,
    ptr: *const c_void,
}

impl Hit {
    /// The device copy, or null for the upload path.
    pub(crate) fn ptr(&self) -> *const c_void {
        self.ptr
    }
}

/// The device copy of `arrays` if they are exactly one registered matrix.
pub(crate) fn lookup<T>(arrays: [&[T]; 3]) -> Hit {
    let want = arrays.map(|a| (a.as_ptr() as *const u8, std::mem::size_of_val(a)));
    let (found, dead) = {
        let mut reg = lock(&REGISTRY);
        let dead = take_dead(&mut reg);
        let found = reg.iter().find_map(|entry| {
            let key = entry.key.upgrade()?;
            let m = key.evals().into_iter().position(|matrix| matrix == want)?;
            Some((entry.clone(), key, m))
        });
        (found, dead)
    };
    drop(dead);
    let miss = || {
        MISSES.fetch_add(1, Relaxed);
        Hit { _key: None, _entry: None, ptr: std::ptr::null() }
    };
    let Some((entry, key, m)) = found else { return miss() };
    let mut slot = lock(&entry.matrices[m]);
    if slot.is_none() {
        *slot = upload(want);
    }
    let Some(dev) = slot.as_ref() else { return miss() };
    let ptr = dev.ptr as *const c_void;
    drop(slot);
    HITS.fetch_add(1, Relaxed);
    Hit { _key: Some(key), _entry: Some(entry), ptr }
}

fn upload(arrays: [(*const u8, usize); 3]) -> Option<DeviceEvals> {
    if !*SUPPORTED {
        return None;
    }
    let bytes = arrays[0].1;
    let srcs = arrays.map(|(ptr, _)| ptr as *const c_void);
    let mut d: *mut c_void = std::ptr::null_mut();
    // SAFETY: each source is `bytes` of a live key's array, and the caller
    // holds the key's `Arc` across this call.
    let err = unsafe { super::snarkvm_resident_upload(&mut d, srcs.as_ptr(), srcs.len(), bytes) };
    if err.code != 0 {
        if UPLOAD_FAILURES.fetch_add(1, Relaxed) == 0 {
            eprintln!(
                "resident evaluations: an upload of 3 x {bytes} bytes failed ({err}); calls upload them until one succeeds"
            );
        }
        return None;
    }
    RESIDENT_BYTES.fetch_add(3 * bytes, Relaxed);
    UPLOADS.fetch_add(1, Relaxed);
    Some(DeviceEvals { ptr: d as usize, bytes: 3 * bytes })
}

/// Counters since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Calls that read a device copy.
    pub hits: u64,
    /// Calls that uploaded their arrays.
    pub misses: u64,
    /// Matrices uploaded.
    pub uploads: u64,
    /// Uploads that failed, each retried on a later call.
    pub upload_failures: u64,
    /// Device bytes held.
    pub resident_bytes: usize,
}

pub fn stats() -> Stats {
    Stats {
        hits: HITS.load(Relaxed),
        misses: MISSES.load(Relaxed),
        uploads: UPLOADS.load(Relaxed),
        upload_failures: UPLOAD_FAILURES.load(Relaxed),
        resident_bytes: RESIDENT_BYTES.load(Relaxed),
    }
}

/// Whether `key` has an entry, without keeping it alive.
#[doc(hidden)]
pub fn is_registered<K: Evals>(key: &Weak<K>) -> bool {
    let key: Weak<dyn Evals> = key.clone();
    lock(&REGISTRY).iter().any(|e| Weak::ptr_eq(&e.key, &key))
}

/// Device bytes held for `key`.
#[doc(hidden)]
pub fn resident_bytes_of<K: Evals>(key: &Arc<K>) -> usize {
    let weak: Weak<dyn Evals> = Arc::downgrade(key) as Weak<K>;
    lock(&REGISTRY)
        .iter()
        .filter(|e| Weak::ptr_eq(&e.key, &weak))
        .flat_map(|e| e.matrices.iter())
        .filter_map(|m| lock(m).as_ref().map(|d| d.bytes))
        .sum()
}
