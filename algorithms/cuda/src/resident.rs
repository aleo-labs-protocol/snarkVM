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

//! Device-resident bases.
//!
//! Every proving key's bases are a prefix and a suffix of one universal SRS of
//! `N` powers: `SRS[0, P)` and `SRS[N - S, N)`. The device holds two windows of
//! it, `SRS[0, W)` and `SRS[N - W, N)`, uploaded once by
//! [`load_windows`] and never freed. `W` is the pool's NTT bound
//! ([`window_points`]), so every key this build can derive fits.
//!
//! An MSM reads a window when its bases lie inside the SRS snapshot that window
//! was uploaded from. Keys trimmed from the SRS share its snapshots, the
//! windows hold an `Arc` to each, and growing the SRS copies a snapshot rather
//! than changing it, so a slice inside one is the SRS at that offset. Anything
//! else takes the host path, which uploads the points per call: a key read from
//! bytes, an array a key owns, copied points, any MSM before the windows load,
//! and a host with more than one GPU.
//!
//! Keys must be trimmed from the SRS instance the windows were loaded from,
//! after the windows were fetched; other keys hold other snapshots and miss.
//! Loading windows from a second instance is refused
//! ([`LoadError::OtherSrs`]). Once the windows are fetched, only a
//! key longer than `W` at an end grows the SRS, and a circuit that large
//! overflows the pool first.

use core::ffi::c_void;
use std::{
    any::{Any, TypeId},
    fmt,
    ops::Range,
    sync::{
        Arc,
        Mutex,
        OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
};

/// An SRS snapshot, and a range of powers within it.
pub type Snapshot<P> = (Arc<Vec<P>>, Range<usize>);

/// The universal SRS the windows are cut from.
pub trait Srs: Send + Sync + 'static {
    type Point: Send + Sync + 'static;

    fn max_degree(&self) -> usize;

    /// Fetches the first `prefix` and the last `suffix` powers that the SRS
    /// does not hold. Fails if either is more than `max_degree() + 1`.
    fn fetch(&self, prefix: usize, suffix: usize) -> anyhow::Result<()>;

    /// The snapshots holding the powers in each of `ranges`, and each
    /// range within its snapshot. Call it after [`Srs::fetch`]: it downloads
    /// nothing, and fails for a range the SRS does not hold.
    fn shared_powers(&self, ranges: [Range<usize>; 2]) -> anyhow::Result<[Snapshot<Self::Point>; 2]>;

    /// This instance of the SRS: shared by its clones, distinct for each
    /// load.
    fn instance(&self) -> Arc<dyn Any + Send + Sync>;
}

/// `cudaErrorNotSupported`, which `snarkvm_bases_status` returns for more
/// than one GPU.
const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;

/// Points uploaded per call. `upload_points` stages each call's points
/// whole on the device before widening them, so this bounds that.
const CHUNK_POINTS: usize = 1 << 20;

static WINDOWS: OnceLock<Windows> = OnceLock::new();
/// Held while loading, so two loads cannot both upload.
static LOADING: Mutex<()> = Mutex::new(());

static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static RESIDENT_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Each window's length in points: the pool's NTT bound for this build,
/// `2^(MAX_LG_DOMAIN + 2)`. Builds nothing, so it may be asked before the
/// device is ready.
pub fn window_points() -> usize {
    // SAFETY: returns a constant computed from the build.
    unsafe { super::snarkvm_cuda_window_points() }
}

/// One window: its device slots, freed only if its load fails, and where
/// the host points it was uploaded from start, kept alive by `_snapshot`.
struct Window {
    ptr: usize,
    host: usize,
    _snapshot: Arc<dyn Any + Send + Sync>,
}

impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `snarkvm_bases_alloc` and is freed once,
        // here. A window that reached `WINDOWS` is never dropped, and one
        // that did not was never read.
        unsafe { super::snarkvm_bases_release(self.ptr as *mut c_void) };
    }
}

struct Windows {
    points: usize,
    point: TypeId,
    /// Held, so no later instance can reuse its address.
    srs: Arc<dyn Any + Send + Sync>,
    ends: [Window; 2],
}

/// Why [`load_windows`] did not load.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoadError<E> {
    /// The device path does not support resident bases: more than one GPU,
    /// whose MSMs would split across devices the windows are not on.
    Unsupported,
    /// The device did not build, or refused an allocation or an upload.
    Device(i32),
    /// The windows are already loaded at another length.
    Mismatch { loaded: usize, asked: usize },
    /// The windows are already loaded from another instance of the SRS,
    /// whose keys would not read them.
    OtherSrs,
    /// Reading the SRS failed.
    Fill(E),
}

impl<E: fmt::Display> fmt::Display for LoadError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "resident bases need exactly one GPU"),
            Self::Device(code) => write!(f, "the device refused a resident window (CUDA error {code})"),
            Self::Mismatch { loaded, asked } => {
                write!(f, "resident windows of {loaded} points are loaded; {asked} were asked for")
            }
            Self::OtherSrs => write!(
                f,
                "the resident windows were loaded from another instance of the SRS, whose keys alone read them"
            ),
            Self::Fill(e) => write!(f, "reading the SRS for a resident window failed: {e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for LoadError<E> {}

/// Whether windows of `points` are already loaded from SRS instance `srs`
/// (`Ok(true)`) or may be (`Ok(false)`); an error if they are loaded at
/// another length or from another instance.
fn preflight<E>(points: usize, srs: &Arc<dyn Any + Send + Sync>) -> Result<bool, LoadError<E>> {
    match WINDOWS.get() {
        Some(loaded) if loaded.points != points => Err(LoadError::Mismatch { loaded: loaded.points, asked: points }),
        Some(loaded) if !Arc::ptr_eq(&loaded.srs, srs) => Err(LoadError::OtherSrs),
        Some(_) => Ok(true),
        None => Ok(false),
    }
}

/// Each loaded window's length in points, or `None` before they load.
pub fn loaded_points() -> Option<usize> {
    WINDOWS.get().map(|w| w.points)
}

/// Downloads the powers both windows need into `pp`, touching no device.
/// Powers `pp` already holds are not fetched again.
pub fn fetch_windows<S: Srs>(pp: &S) -> anyhow::Result<()> {
    fetch_windows_of(pp, window_points())
}

fn fetch_windows_of<S: Srs>(pp: &S, w: usize) -> anyhow::Result<()> {
    // Windows are whole degree files, which is what the SRS downloads.
    anyhow::ensure!(w.is_power_of_two(), "a resident window of {w} points is not a power of two");
    let n = pp.max_degree() + 1;
    // Below the midpoint: a suffix from it would download the whole SRS.
    anyhow::ensure!(w < n / 2, "a resident window of {w} points does not fit twice in an SRS of {n}");
    pp.fetch(w, w)
}

/// Fetches the windows if `pp` lacks them, then uploads both from the
/// snapshots holding them. Idempotent once it has succeeded.
///
/// Fails before fetching anything when windows are already loaded at
/// another length or from another instance of the SRS
/// ([`LoadError::OtherSrs`]). A failed allocation or upload frees what it
/// allocated and leaves nothing loaded, so a later call starts again. A
/// [`LoadError::Device`] from a device that did not build is final for the
/// process, as it is for every entry point: the caller should end the
/// process.
pub fn load_windows<S: Srs>(pp: &S) -> Result<(), LoadError<anyhow::Error>> {
    load_windows_of(pp, window_points())
}

/// [`load_windows`] with windows of `w` points instead of the build's, so
/// a test can load windows the bundled SRS already holds.
#[doc(hidden)]
pub fn load_windows_of<S: Srs>(pp: &S, w: usize) -> Result<(), LoadError<anyhow::Error>> {
    super::assert_type::<S::Point, super::G1Affine>();
    let srs = pp.instance();
    if preflight(w, &srs)? {
        return Ok(());
    }
    fetch_windows_of(pp, w).map_err(LoadError::Fill)?;
    let n = pp.max_degree() + 1;
    let snapshots = pp.shared_powers([0..w, n - w..n]).map_err(LoadError::Fill)?;
    let _loading = LOADING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if preflight(w, &srs)? {
        return Ok(());
    }
    // SAFETY: no arguments; builds the device singleton if it is not built.
    match unsafe { super::snarkvm_bases_status() }.code {
        0 => {}
        CUDA_ERROR_NOT_SUPPORTED => return Err(LoadError::Unsupported),
        code => return Err(LoadError::Device(code)),
    }
    let point_size = std::mem::size_of::<S::Point>();
    let mut ends = Vec::with_capacity(2);
    let mut device_bytes = 0;
    for (snapshot, range) in snapshots {
        let host = &snapshot[range];
        assert_eq!(host.len(), w, "a window's snapshot range is not the window");
        let host_ptr = host.as_ptr();
        let (mut d, mut bytes): (*mut c_void, usize) = (std::ptr::null_mut(), 0);
        // SAFETY: writes one device pointer into `d` and its size into `bytes`.
        let err = unsafe { super::snarkvm_bases_alloc(&mut d, &mut bytes, w) };
        if err.code != 0 {
            return Err(LoadError::Device(err.code));
        }
        device_bytes += bytes;
        for (i, chunk) in host.chunks(CHUNK_POINTS).enumerate() {
            // SAFETY: the window holds `w` slots and the chunk lies inside
            // them; `chunk` is live host points.
            let err = unsafe {
                super::snarkvm_bases_upload_at(
                    d,
                    i * CHUNK_POINTS,
                    chunk.as_ptr() as *const c_void,
                    chunk.len(),
                    point_size,
                )
            };
            if err.code != 0 {
                // SAFETY: `d` came from `snarkvm_bases_alloc` and nothing read it.
                unsafe { super::snarkvm_bases_release(d) };
                return Err(LoadError::Device(err.code));
            }
        }
        ends.push(Window { ptr: d as usize, host: host_ptr as usize, _snapshot: snapshot });
    }
    let ends: [Window; 2] = ends.try_into().unwrap_or_else(|_| unreachable!("one window per end"));
    RESIDENT_BYTES.store(device_bytes, Relaxed);
    // `LOADING` is held and `WINDOWS` was empty under it, so this is the
    // only set.
    let _ = WINDOWS.set(Windows { points: w, point: TypeId::of::<S::Point>(), srs, ends });
    Ok(())
}

/// What a lookup found: a window, which is never freed, and an offset.
pub(crate) struct Hit {
    ptr: *const c_void,
    offset: usize,
}

impl Hit {
    fn none() -> Self {
        Self { ptr: std::ptr::null(), offset: 0 }
    }

    /// The window holding the looked-up points, or null for the host path.
    pub(crate) fn ptr(&self) -> *const c_void {
        self.ptr
    }

    /// Where the looked-up points start in it, in points.
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }
}

/// Which window holds `points`, and where in it: the window whose host
/// points contain them wholly, on a point boundary.
fn find<Affine: 'static>(points: &[Affine]) -> Option<(&'static Window, usize)> {
    let windows = WINDOWS.get().filter(|w| w.point == TypeId::of::<Affine>())?;
    let size = std::mem::size_of::<Affine>();
    let start = points.as_ptr() as usize;
    let end = start + std::mem::size_of_val(points);
    windows.ends.iter().find_map(|window| {
        let inside = start >= window.host
            && end <= window.host + windows.points * size
            && (start - window.host).is_multiple_of(size);
        inside.then(|| (window, (start - window.host) / size))
    })
}

/// The resident copy of `points`, if there is one.
pub(crate) fn lookup<Affine: 'static>(points: &[Affine]) -> Hit {
    if points.is_empty() {
        return Hit::none();
    }
    match find(points) {
        Some((window, offset)) => {
            HITS.fetch_add(1, Relaxed);
            Hit { ptr: window.ptr as *const c_void, offset }
        }
        None => {
            MISSES.fetch_add(1, Relaxed);
            Hit::none()
        }
    }
}

/// Whether `points` would be read from a window, by the same test `lookup`
/// applies, without counting.
#[doc(hidden)]
pub fn is_resident<Affine: 'static>(points: &[Affine]) -> bool {
    !points.is_empty() && find(points).is_some()
}

/// Counters since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// MSMs that read a window.
    pub hits: u64,
    /// MSMs that looked and read none, including every one before the
    /// windows loaded.
    pub misses: u64,
    /// Device bytes the windows hold: zero until loaded, then fixed.
    pub resident_bytes: usize,
}

pub fn stats() -> Stats {
    Stats { hits: HITS.load(Relaxed), misses: MISSES.load(Relaxed), resident_bytes: RESIDENT_BYTES.load(Relaxed) }
}
