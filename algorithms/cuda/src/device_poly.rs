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

//! Polynomial coefficients kept on the device after the call that computed
//! them, for later calls to read in place of uploading a host copy.
//!
//! A [`DevicePoly`] owns its memory through an `Arc`, from the resident pool on
//! device 0, and the last clone to drop frees it. A [`DeviceCopy`] either pairs
//! one with the host coefficients it mirrors, and a consumer reads the device
//! copy only for those same host coefficients, or holds a polynomial that has
//! no host coefficients, which a host reader downloads. Device copies exist
//! only on one GPU.

use core::ffi::c_void;
use std::{
    any::Any,
    cell::RefCell,
    fmt,
    io::{Read, Write},
    marker::PhantomData,
    sync::{
        Arc,
        LazyLock,
        Mutex,
        OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed},
    },
};

use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate};

use super::{FR_BYTES, Fr, assert_type};

// SAFETY: no arguments.
static SUPPORTED: LazyLock<bool> = LazyLock::new(|| unsafe { super::snarkvm_bases_status() }.code == 0);

static RETAINED: AtomicU64 = AtomicU64::new(0);
static RETAIN_FAILURES: AtomicU64 = AtomicU64::new(0);
static DEVICE_READS: AtomicU64 = AtomicU64::new(0);
static HOST_FALLBACKS: AtomicU64 = AtomicU64::new(0);
static DEVICE_EVALS: AtomicU64 = AtomicU64::new(0);
static DOWNLOADED_BYTES: AtomicUsize = AtomicUsize::new(0);
static HELD_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Retention requests to let through, then to refuse.
static FAIL_RETAINS: Mutex<(u64, u64)> = Mutex::new((0, 0));

/// Lets the next `skip` retention requests through and refuses the `n` after
/// them, as if the device could not hold them, until the guard drops. For
/// tests of the host path.
#[doc(hidden)]
pub fn fail_retains(skip: u64, n: u64) -> FailRetains {
    *FAIL_RETAINS.lock().unwrap_or_else(|e| e.into_inner()) = (skip, n);
    FailRetains(())
}

/// Lets every retention request through again when dropped.
#[doc(hidden)]
#[must_use]
pub struct FailRetains(());

impl Drop for FailRetains {
    fn drop(&mut self) {
        *FAIL_RETAINS.lock().unwrap_or_else(|e| e.into_inner()) = (0, 0);
    }
}

/// Whether a call should ask the device to keep its outputs.
pub(crate) fn retain() -> bool {
    if !*SUPPORTED {
        return false;
    }
    let mut fail = FAIL_RETAINS.lock().unwrap_or_else(|e| e.into_inner());
    let (skip, n) = &mut *fail;
    if *skip > 0 {
        *skip -= 1;
    } else if *n > 0 {
        *n -= 1;
        RETAIN_FAILURES.fetch_add(1, Relaxed);
        return false;
    }
    true
}

pub(crate) fn count_download(bytes: usize) {
    DOWNLOADED_BYTES.fetch_add(bytes, Relaxed);
}

pub(crate) struct Buffer {
    pub(crate) ptr: usize,
    bytes: usize,
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from the resident pool and is freed once. Every
        // call that read it has returned with its device work complete.
        unsafe { super::snarkvm_bases_release(self.ptr as *mut c_void) };
        HELD_BYTES.fetch_sub(self.bytes, Relaxed);
    }
}

impl Buffer {
    fn adopt(ptr: *mut c_void, bytes: usize) -> Arc<Self> {
        HELD_BYTES.fetch_add(bytes, Relaxed);
        Arc::new(Self { ptr: ptr as usize, bytes })
    }
}

/// `len` field elements on device 0, from `offset` elements into a buffer.
#[derive(Clone)]
pub struct DevicePoly {
    buf: Arc<Buffer>,
    offset: usize,
    len: usize,
}

impl fmt::Debug for DevicePoly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DevicePoly({})", self.len)
    }
}

impl DevicePoly {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The device ordinal the coefficients are on.
    pub fn device(&self) -> usize {
        0
    }

    fn ptr(&self) -> *const c_void {
        (self.buf.ptr + self.offset * FR_BYTES) as *const c_void
    }

    /// The device pointer, counting the read.
    pub(crate) fn read(&self) -> *const c_void {
        DEVICE_READS.fetch_add(1, Relaxed);
        self.ptr()
    }

    pub fn download<T: 'static>(&self, out: &mut [T]) -> Result<(), super::cuda::Error> {
        assert_type::<T, Fr>();
        assert_eq!(out.len(), self.len, "the output is the device copy's length");
        if self.len == 0 {
            return Ok(());
        }
        // SAFETY: `out` holds `len` elements and the buffer holds `len` from `ptr()`.
        let err = unsafe {
            super::snarkvm_resident_download(out.as_mut_ptr() as *mut c_void, self.ptr(), self.len * FR_BYTES)
        };
        if err.code != 0 {
            return Err(err);
        }
        count_download(self.len * FR_BYTES);
        Ok(())
    }
}

/// `p(z)`, computed on the device.
pub fn evaluate<T: 'static>(p: &DevicePoly, z: &T) -> Result<T, super::cuda::Error> {
    assert_type::<T, Fr>();
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `out` has room for one element, and the buffer holds `len` from
    // `ptr()`.
    let err = unsafe {
        super::snarkvm_device_evaluate(out.as_mut_ptr() as *mut c_void, p.ptr(), p.len, z as *const T as *const c_void)
    };
    if err.code != 0 {
        return Err(err);
    }
    DEVICE_EVALS.fetch_add(1, Relaxed);
    // SAFETY: the C++ writes `*out` on success.
    Ok(unsafe { out.assume_init() })
}

/// `Σ c · p` over `terms`, kept on the device at its trimmed length. `None` if
/// the device cannot hold it.
pub fn combine<T: Copy + 'static>(terms: &[(T, &DevicePoly)]) -> Result<Option<DevicePoly>, super::cuda::Error> {
    assert_type::<T, Fr>();
    let out_len = terms.iter().map(|(_, p)| p.len).max().unwrap_or(0);
    if out_len == 0 || !retain() {
        return Ok(None);
    }
    let coeffs: Vec<T> = terms.iter().map(|(c, _)| *c).collect();
    let lens: Vec<usize> = terms.iter().map(|(_, p)| p.len).collect();
    let d_polys: Vec<*const c_void> = terms.iter().map(|(_, p)| p.read()).collect();
    let (mut keep, mut trimmed) = (std::ptr::null_mut(), 0usize);
    // SAFETY: each array holds `terms.len()` entries, and each device pointer
    // holds its length.
    let err = unsafe {
        super::snarkvm_device_combine(
            &mut keep,
            &mut trimmed,
            terms.len(),
            d_polys.as_ptr(),
            lens.as_ptr(),
            coeffs.as_ptr() as *const c_void,
            out_len,
        )
    };
    if err.code != 0 {
        return Err(err);
    }
    if keep.is_null() {
        RETAIN_FAILURES.fetch_add(1, Relaxed);
        return Ok(None);
    }
    RETAINED.fetch_add(1, Relaxed);
    Ok(Some(DevicePoly { buf: Buffer::adopt(keep, out_len * FR_BYTES), offset: 0, len: trimmed }))
}

/// Four buffers of `domain` elements from the resident pool for
/// `FourthRoundChain` to keep its outputs in. `None` if the device cannot hold
/// them.
pub(crate) fn reserve(domain: usize) -> Option<[Arc<Buffer>; 4]> {
    if !retain() {
        return None;
    }
    let bytes = domain * FR_BYTES;
    let mut out = [std::ptr::null_mut(); 4];
    // SAFETY: `out` holds four pointers.
    let err = unsafe { super::snarkvm_resident_reserve(out.as_mut_ptr(), 4, bytes) };
    if err.code != 0 || out[0].is_null() {
        RETAIN_FAILURES.fetch_add(1, Relaxed);
        return None;
    }
    Some(out.map(|p| Buffer::adopt(p, bytes)))
}

/// `FourthRoundChain`'s kept `a`, `b`, `g = f[1..]` and `lhs`, at the trimmed
/// lengths `lens`.
pub(crate) fn adopt(kept: [Arc<Buffer>; 4], lens: [usize; 4]) -> [DevicePoly; 4] {
    RETAINED.fetch_add(1, Relaxed);
    let mut i = 0;
    kept.map(|buf| {
        let (offset, len) = ([0, 0, 1, 0][i], lens[i]);
        i += 1;
        DevicePoly { buf, offset, len }
    })
}

/// The host side of a [`DeviceCopy`].
#[derive(Clone)]
enum Host {
    /// The address and length of the host coefficients the device mirrors.
    Mirror(usize, usize),
    /// No host coefficients, and the download a host reader made, if any.
    Only(Arc<OnceLock<Box<dyn Any + Send + Sync>>>),
}

/// A [`DevicePoly`] and the host coefficients it mirrors, a [`DevicePoly`]
/// with no host coefficients, or nothing.
///
/// Serializes as nothing and compares equal to any other, so a polynomial's
/// bytes and equality do not depend on it.
#[derive(Clone, Default)]
pub struct DeviceCopy(Option<(DevicePoly, Host)>);

impl DeviceCopy {
    /// `device` as the copy of `host`, which must be a prefix of it.
    pub fn new<T: 'static>(device: DevicePoly, host: &[T]) -> Self {
        assert_type::<T, Fr>();
        assert!(host.len() <= device.len, "{} host coefficients for a device copy of {}", host.len(), device.len);
        Self(Some((device, Host::Mirror(host.as_ptr() as usize, host.len()))))
    }

    /// `device` as the only copy of the coefficients.
    pub fn only(device: DevicePoly) -> Self {
        Self(Some((device, Host::Only(Default::default()))))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    /// The coefficients, if they are only on the device.
    pub fn device_only(&self) -> Option<&DevicePoly> {
        match &self.0 {
            Some((device, Host::Only(_))) => Some(device),
            _ => None,
        }
    }

    /// For a device-only copy, the host form `download` makes of it, made once
    /// and shared by every clone.
    ///
    /// # Panics
    ///
    /// If an earlier call made a different type.
    pub fn host<P: Any + Send + Sync>(&self, download: impl FnOnce(&DevicePoly) -> P) -> Option<&P> {
        let Some((device, Host::Only(host))) = &self.0 else { return None };
        let host = host.get_or_init(|| Box::new(download(device)));
        Some(host.downcast_ref().expect("every caller makes the same host form"))
    }

    /// The device copy if this mirrors `host`, counting the read or, for a copy
    /// of other coefficients, the fallback.
    fn get<T>(&self, host: &[T]) -> Option<&DevicePoly> {
        let (device, Host::Mirror(ptr, len)) = self.0.as_ref()? else { return None };
        if host.as_ptr() as usize == *ptr && host.len() == *len {
            Some(device)
        } else {
            HOST_FALLBACKS.fetch_add(1, Relaxed);
            None
        }
    }

    /// The number of coefficients of a term whose host coefficients are
    /// `host`: the device copy's for a device-only copy, otherwise `host`'s.
    pub fn coeffs_len<T>(&self, host: &[T]) -> usize {
        self.device_only().map_or(host.len(), DevicePoly::len)
    }

    /// An opening term's host pointer, length and device pointer. A
    /// device-only copy has no host pointer; otherwise a null device pointer
    /// means the host path.
    pub(crate) fn term<T>(&self, host: &[T]) -> (*const c_void, usize, *const c_void) {
        if let Some(device) = self.device_only() {
            assert!(host.is_empty(), "a device-only term has no host coefficients");
            return (std::ptr::null(), device.len, if device.is_empty() { std::ptr::null() } else { device.read() });
        }
        let d = match self.get(host) {
            Some(device) if !host.is_empty() => device.read(),
            _ => std::ptr::null(),
        };
        (host.as_ptr() as *const c_void, host.len(), d)
    }
}

impl fmt::Debug for DeviceCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some((device, Host::Mirror(..))) => device.fmt(f),
            Some((device, Host::Only(_))) => write!(f, "DeviceOnly({})", device.len),
            None => f.write_str("None"),
        }
    }
}

impl PartialEq for DeviceCopy {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for DeviceCopy {}

impl CanonicalSerialize for DeviceCopy {
    fn serialize_with_mode<W: Write>(&self, _: W, _: Compress) -> Result<(), SerializationError> {
        Ok(())
    }

    fn serialized_size(&self, _: Compress) -> usize {
        0
    }
}

impl Valid for DeviceCopy {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalDeserialize for DeviceCopy {
    fn deserialize_with_mode<R: Read>(_: R, _: Compress, _: Validate) -> Result<Self, SerializationError> {
        Ok(Self::default())
    }
}

thread_local! {
    static LENT: RefCell<Vec<(DevicePoly, usize, usize)>> = const { RefCell::new(Vec::new()) };
}

/// Lends a device copy to the MSMs on this thread until dropped.
pub struct Lend<'a>(bool, PhantomData<&'a ()>);

impl Drop for Lend<'_> {
    fn drop(&mut self) {
        if self.0 {
            LENT.with_borrow_mut(|lent| lent.pop());
        }
    }
}

/// Until the guard drops, an MSM on this thread whose scalars lie in `host`
/// reads them from `copy`'s device copy, if `copy` mirrors `host`.
pub fn lend<'a, T>(copy: &DeviceCopy, host: &'a [T]) -> Lend<'a> {
    let Some(device) = copy.get(host) else { return Lend(false, PhantomData) };
    let entry = (device.clone(), host.as_ptr() as usize, host.len());
    LENT.with_borrow_mut(|lent| lent.push(entry));
    Lend(true, PhantomData)
}

/// The device copy of `scalars` if a [`lend`] on this thread covers them.
pub(crate) fn lent<T>(scalars: &[T]) -> *const c_void {
    let (start, size) = (scalars.as_ptr() as usize, size_of::<T>());
    LENT.with_borrow(|lent| {
        lent.iter().rev().find_map(|(device, host, len)| {
            let inside = size == FR_BYTES
                && start >= *host
                && (start - host).is_multiple_of(size)
                && (start - host) / size + scalars.len() <= *len;
            inside.then(|| {
                DEVICE_READS.fetch_add(1, Relaxed);
                (device.ptr() as usize + (start - host)) as *const c_void
            })
        })
    })
    .unwrap_or(std::ptr::null())
}

/// Counters since the process started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Calls whose outputs the device kept.
    pub retained: u64,
    /// Calls that asked the device to keep their outputs and it could not.
    pub retain_failures: u64,
    /// MSMs, opening terms and combinations that read a device copy.
    pub device_reads: u64,
    /// Reads that had a device copy of other coefficients and uploaded.
    pub host_fallbacks: u64,
    /// Evaluations of a device-only polynomial.
    pub device_evals: u64,
    /// Bytes of round four's outputs and of device copies brought to the host.
    pub downloaded_bytes: usize,
    /// Device bytes held.
    pub held_bytes: usize,
}

pub fn stats() -> Stats {
    Stats {
        retained: RETAINED.load(Relaxed),
        retain_failures: RETAIN_FAILURES.load(Relaxed),
        device_reads: DEVICE_READS.load(Relaxed),
        host_fallbacks: HOST_FALLBACKS.load(Relaxed),
        device_evals: DEVICE_EVALS.load(Relaxed),
        downloaded_bytes: DOWNLOADED_BYTES.load(Relaxed),
        held_bytes: HELD_BYTES.load(Relaxed),
    }
}

/// Each consumer against the host path on the same inputs. Retention needs
/// exactly one GPU, so each test returns early on any other count. The tests
/// hold `SERIAL`, so the counters and `fail_retains` move only with them.
#[cfg(test)]
mod tests {
    use super::{DeviceCopy, DevicePoly, combine, evaluate, fail_retains, lend, stats};
    use crate::{G1Affine, G1Projective, accumulate_open, fourth_round_chain, msm, msm_device};
    use snarkvm_curves::{ProjectiveCurve, bls12_377::Fr};
    use snarkvm_utilities::rand::{TestRng, Uniform};
    use std::sync::{Arc, Mutex};

    static SERIAL: Mutex<()> = Mutex::new(());

    const LG: u32 = 10;

    fn one_gpu() -> bool {
        crate::device_count() == 1
    }

    fn zero() -> Fr {
        Fr::default()
    }

    fn trimmed(mut v: Vec<Fr>) -> Vec<Fr> {
        while v.last() == Some(&zero()) {
            v.pop();
        }
        v
    }

    fn horner(coeffs: &[Fr], z: Fr) -> Fr {
        coeffs.iter().rev().fold(zero(), |acc, c| acc * z + c)
    }

    struct Chain {
        f0: Fr,
        out: Result<[DevicePoly; 4], [Vec<Fr>; 4]>,
    }

    /// The chain over random evaluations of `len`, with arguments the divide
    /// accepts. The same `seed` gives the same inputs. `host` refuses the
    /// retention.
    fn chain(seed: u64, lg: u32, len: usize, host: bool) -> Chain {
        let _refuse = host.then(|| fail_retains(0, 1));
        let rng = &mut TestRng::fixed(seed);
        let mut array = || (0..len).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
        let (row, col, rcv) = (array(), array(), array());
        let [alpha, beta, coeff, b_scale, selector_mult] = [(); 5].map(|_| Fr::rand(rng));
        let n = 1usize << lg;
        let mut f0 = zero();
        let out = fourth_round_chain(
            n - 1,
            &mut f0,
            &row,
            &col,
            &rcv,
            lg,
            lg + 1,
            &alpha,
            &beta,
            &coeff,
            &b_scale,
            &(b_scale * coeff),
            &selector_mult,
        )
        .map_err(|e| e.code)
        .expect("the chain runs");
        Chain { f0, out }
    }

    /// The host outputs, trimmed, and the device's for the same inputs.
    fn both(seed: u64, lg: u32, len: usize) -> ([Vec<Fr>; 4], [DevicePoly; 4]) {
        let host = chain(seed, lg, len, true);
        let device = chain(seed, lg, len, false);
        assert!(device.f0 == host.f0);
        (
            host.out.expect_err("a refused chain keeps nothing").map(trimmed),
            device.out.expect("one GPU keeps the outputs"),
        )
    }
    fn bases(rng: &mut TestRng, n: usize) -> Vec<G1Affine> {
        G1Projective::batch_normalization_into_affine((0..n).map(|_| G1Projective::rand(rng)).collect())
    }

    fn download(d: &DevicePoly) -> Vec<Fr> {
        let mut out = vec![zero(); d.len()];
        d.download(&mut out).map_err(|e| e.code).expect("the download runs");
        out
    }

    fn view(d: &DevicePoly, len: usize) -> DevicePoly {
        assert!(len <= d.buf.bytes / 32 - d.offset);
        DevicePoly { buf: Arc::clone(&d.buf), offset: d.offset, len }
    }

    #[test]
    fn the_kept_outputs_are_the_host_outputs_trimmed() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        for (lg, len) in [(LG, 1usize << LG), (12, (1 << 12) - 1025)] {
            let host = chain(1, lg, len, true);
            let host = host.out.expect_err("a refused chain keeps nothing");
            let lens = host.each_ref().map(|v| v.len());
            assert_eq!(
                lens,
                [1 << lg, 1 << lg, (1 << lg) - 1, (1 << lg) - 1],
                "lg {lg}: the host outputs are untrimmed"
            );
            let before = stats();
            let device = chain(1, lg, len, false);
            let after = stats();
            assert_eq!(after.held_bytes, before.held_bytes + 4 * (32 << lg), "lg {lg}");
            assert_eq!(after.retained, before.retained + 1, "lg {lg}");
            assert_eq!(after.downloaded_bytes, before.downloaded_bytes, "lg {lg}: nothing came down");
            let kept = device.out.expect("one GPU keeps the outputs");
            for (i, (want, got)) in host.into_iter().map(trimmed).zip(&kept).enumerate() {
                assert_eq!(got.len(), want.len(), "lg {lg}: output {i}'s trimmed length");
                assert!(download(got) == want, "lg {lg}: output {i}");
            }
            let [a, b, g, lhs] = kept;
            drop((a, b, lhs));
            assert_eq!(stats().held_bytes, before.held_bytes + (32 << lg), "lg {lg}: a, b and lhs are freed");
            drop(g);
            assert_eq!(stats().held_bytes, before.held_bytes, "lg {lg}: g is freed");
        }
    }

    #[test]
    fn a_refused_retention_downloads_everything() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let n = 1usize << LG;
        let before = stats();
        let got = chain(2, LG, n, true).out.expect_err("a refused chain keeps nothing");
        let after = stats();
        assert_eq!(got.each_ref().map(Vec::len), [n, n, n - 1, n - 1]);
        assert_eq!(after.retain_failures, before.retain_failures + 1);
        assert_eq!(after.downloaded_bytes, before.downloaded_bytes + 32 * (4 * n - 2));
        assert_eq!(after.held_bytes, before.held_bytes);
        assert!(chain(2, LG, n, false).out.is_ok(), "the refusal was for one request");
    }

    /// Short lengths, one block, up to 32 blocks, more than 32 blocks, and
    /// whole buffers up to 2^20.
    #[test]
    fn evaluate_matches_the_host() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let mut cases = vec![(LG, vec![0, 1, 2, 3, 5, 7, 33, 257, 1000])];
        cases.push((20, vec![1025, 20_000, 40_000, 100_001, (1 << 20) - 12_345]));
        for (lg, lens) in cases {
            let (host, kept) = both(3, lg, 1 << lg);
            for (want, d) in host.iter().zip(&kept) {
                for len in lens.iter().copied().chain([d.len()]) {
                    let (coeffs, d) = (&want[..len], view(d, len));
                    for _ in 0..2 {
                        let z = Fr::rand(rng);
                        let evals = stats().device_evals;
                        let got = evaluate(&d, &z).map_err(|e| e.code).expect("the evaluation runs");
                        assert!(got == horner(coeffs, z), "lg {lg} len {len}");
                        assert_eq!(stats().device_evals, evals + 1);
                    }
                }
            }
        }
    }

    /// `p - p + q` trims to `q`'s length, and `p - p` to nothing.
    #[test]
    fn combine_matches_the_host_and_trims() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let ([a, b, g, lhs], [d_a, d_b, d_g, d_lhs]) = both(4, LG, 1 << LG);
        let c = [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
        let run = |terms: &[(Fr, &DevicePoly)]| {
            combine(terms).map_err(|e| e.code).expect("the combination runs").expect("one GPU keeps it")
        };

        let got = run(&[(c[0], &d_a), (c[1], &d_g), (c[2], &d_lhs)]);
        let want: Vec<Fr> = (0..a.len())
            .map(|i| {
                let at = |p: &[Fr], k: Fr| p.get(i).map_or(zero(), |x| k * x);
                at(&a, c[0]) + at(&g, c[1]) + at(&lhs, c[2])
            })
            .collect();
        assert!(download(&got) == trimmed(want), "the combination");

        // Within a warp, at block edges, and across grid strides.
        let ([_, b20, ..], [d_a20, d_b20, ..]) = both(5, 20, 1 << 20);
        for (d_p, q, d_q) in [(&d_a, &b, &d_b), (&d_a20, &b20, &d_b20)] {
            for k in [1, 31, 100, 255, 256, 257, 1000, 120_001, 700_001] {
                if k > d_q.len() {
                    continue;
                }
                assert!(q[k - 1] != zero(), "the test needs q's top coefficient non-zero");
                let short = view(d_q, k);
                let got = run(&[(c[0], d_p), (-c[0], d_p), (c[1], &short)]);
                assert_eq!(got.len(), k, "p - p + q trims to q's length");
                assert!(download(&got) == q[..k].iter().map(|x| c[1] * x).collect::<Vec<_>>(), "k {k}");
            }
            assert_eq!(run(&[(c[0], d_p), (-c[0], d_p)]).len(), 0, "p - p trims to nothing");
        }

        let held = stats().held_bytes;
        let got = run(&[(c[0], &d_a)]);
        assert_eq!(stats().held_bytes, held + 32 * d_a.len());
        drop(got);
        assert_eq!(stats().held_bytes, held);
        let _refuse = fail_retains(0, 1);
        assert!(combine(&[(c[0], &d_a)]).map_err(|e| e.code).expect("a refusal is not an error").is_none());
    }

    #[test]
    fn msm_device_matches_the_host() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let ([.., g, _], [.., d_g, _]) = both(5, LG, 1 << LG);
        let bases = bases(rng, g.len());
        let want = msm::<G1Affine, G1Projective, Fr>(&bases, &g).map_err(|e| e.code).expect("the MSM runs");
        let reads = stats().device_reads;
        let got = msm_device::<G1Affine, G1Projective>(&bases, &d_g).map_err(|e| e.code).expect("the MSM runs");
        assert_eq!(got.to_affine(), want.to_affine());
        assert_eq!(stats().device_reads, reads + 1);
    }

    /// `a` and `g` device-only, `b` uploaded, as the opening at gamma mixes
    /// them with host terms.
    #[test]
    fn accumulate_open_reads_device_only_terms() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let ([a, b, g, _], [d_a, _, d_g, _]) = both(6, LG, 1 << LG);
        let out_len = a.len();
        let bases = bases(rng, out_len - 1);
        let (z, c) = (Fr::rand(rng), [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)]);
        let none = DeviceCopy::default();
        let open = |terms: &[(Fr, &[Fr], &DeviceCopy)]| {
            accumulate_open::<G1Affine, G1Projective, Fr>(out_len, terms, &z, &bases)
                .map_err(|e| e.code)
                .expect("the opening runs")
                .to_affine()
        };
        let want = open(&[(c[0], &a, &none), (c[1], &b, &none), (c[2], &g, &none)]);
        let (only_a, only_g) = (DeviceCopy::only(d_a), DeviceCopy::only(d_g));
        let reads = stats().device_reads;
        assert_eq!(open(&[(c[0], &[], &only_a), (c[1], &b, &none), (c[2], &[], &only_g)]), want);
        assert_eq!(stats().device_reads, reads + 2, "both device-only terms were read");
    }

    /// `g` from a leading offset, as `skip_leading_zeros` slices it.
    #[test]
    fn a_lent_msm_reads_the_device_copy() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let ([.., mut g, _], [.., d_g, _]) = both(7, LG, 1 << LG);
        let bases = bases(rng, g.len());
        let delta = Fr::rand(rng);
        let run = |g: &[Fr], copy: &DeviceCopy, k: usize| {
            let _lend = lend(copy, g);
            msm::<G1Affine, G1Projective, Fr>(&bases[k..], &g[k..])
                .map_err(|e| e.code)
                .expect("the MSM runs")
                .to_affine()
        };
        let none = DeviceCopy::default();
        for k in [0, 5] {
            let want = run(&g, &none, k);
            let copy = DeviceCopy::new(d_g.clone(), &g);
            let reads = stats().device_reads;
            assert_eq!(run(&g, &copy, k), want, "k {k}");
            assert_eq!(stats().device_reads, reads + 1, "k {k}: the MSM read the device copy");
            g[k] += delta;
            assert_ne!(run(&g, &none, k), want, "k {k}: the change moves the host path");
            assert_eq!(run(&g, &copy, k), want, "k {k}: the MSM read the host scalars");
            g[k] -= delta;
        }
        let other = g.clone();
        let copy = DeviceCopy::new(d_g.clone(), &g);
        let fallbacks = stats().host_fallbacks;
        assert_eq!(run(&other, &copy, 0), run(&g, &none, 0), "a copy of other coefficients is not read");
        assert_eq!(stats().host_fallbacks, fallbacks + 1);
        let (only, reads) = (DeviceCopy::only(d_g), stats().device_reads);
        assert_eq!(run(&g, &only, 0), run(&g, &none, 0), "a device-only copy is never lent");
        assert_eq!((stats().device_reads, stats().host_fallbacks), (reads, fallbacks + 1));
    }

    /// `a` and `g` from the device, `b` uploaded, as the opening at gamma mixes
    /// them with host terms.
    #[test]
    fn accumulate_open_reads_device_terms() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let rng = &mut TestRng::default();
        let ([mut a, b, mut g, _], [d_a, _, d_g, _]) = both(8, LG, 1 << LG);
        let out_len = a.len();
        let bases = bases(rng, out_len - 1);
        let (z, coeffs) = (Fr::rand(rng), [Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)]);
        let none = DeviceCopy::default();
        let delta = Fr::rand(rng);
        let open = |a: &[Fr], g: &[Fr], copies: [&DeviceCopy; 2]| {
            let terms = [(coeffs[0], a, copies[0]), (coeffs[1], &b[..], &none), (coeffs[2], g, copies[1])];
            accumulate_open::<G1Affine, G1Projective, Fr>(out_len, &terms, &z, &bases)
                .map_err(|e| e.code)
                .expect("the opening runs")
                .to_affine()
        };
        let want = open(&a, &g, [&none, &none]);
        let (copy_a, copy_g) = (DeviceCopy::new(d_a, &a), DeviceCopy::new(d_g, &g));
        let reads = stats().device_reads;
        assert_eq!(open(&a, &g, [&copy_a, &copy_g]), want);
        assert_eq!(stats().device_reads, reads + 2, "both device terms were read");
        a[3] += delta;
        g[7] += delta;
        assert_ne!(open(&a, &g, [&none, &none]), want, "the change moves the host path");
        assert_eq!(open(&a, &g, [&copy_a, &copy_g]), want, "the opening read the host terms");
    }

    #[test]
    fn a_device_copy_serializes_as_nothing() {
        use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize, Compress};
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let ([.., g, _], [.., d_g, _]) = both(9, LG, 1 << LG);
        for (copy, debug) in [
            (DeviceCopy::new(d_g.clone(), &g), format!("DevicePoly({})", g.len())),
            (DeviceCopy::only(d_g), format!("DeviceOnly({})", g.len())),
        ] {
            let mut bytes = Vec::new();
            copy.serialize_with_mode(&mut bytes, Compress::Yes).unwrap();
            assert!(bytes.is_empty() && copy.serialized_size(Compress::No) == 0);
            assert!(DeviceCopy::deserialize_compressed(&[][..]).unwrap() == copy, "any two compare equal");
            assert_eq!(format!("{copy:?}"), debug);
        }
    }

    /// The host form of a device-only copy is downloaded once, for every clone.
    #[test]
    fn a_device_only_copy_downloads_once() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        if !one_gpu() {
            return;
        }
        let ([.., g, _], [.., d_g, _]) = both(10, LG, 1 << LG);
        assert!(DeviceCopy::new(d_g.clone(), &g).host(download).is_none(), "a mirror has host coefficients");
        let only = DeviceCopy::only(d_g);
        let clone = only.clone();
        let before = stats().downloaded_bytes;
        assert!(only.host(download).expect("device-only") == &g);
        assert!(clone.host::<Vec<Fr>>(|_| unreachable!("downloaded once")).expect("device-only") == &g);
        assert_eq!(stats().downloaded_bytes, before + 32 * g.len());
    }
}
