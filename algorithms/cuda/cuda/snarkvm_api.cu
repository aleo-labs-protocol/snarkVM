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

#include <cuda.h>

#include "snarkvm.cu"

#ifndef __CUDA_ARCH__

// Largest domain the device pool is sized for, as a log2 element count.
//
// `snarkvm_t`'s constructor allocates `(1 << max_lg_domain) * 4` elements:
// `snarkvm_t::NTT` admits a domain up to that, and `snarkvm_t::PolyMul` up to
// 2^MAX_LG_DOMAIN. `snarkvm_algorithms_cuda::max_domain()` gives the circuit
// bound this implies.
//
// sppark also guards `lg_domain_size <= MAX_LG_DOMAIN_SIZE` (28) in
// ntt/ntt.cuh with a plain `assert`, which a release build compiles out, so a
// MAX_LG_DOMAIN above 26 claims an NTT bound sppark does not enforce.
//
// The pool costs `allocated_elements * FLIP_FLOP * sizeof(fr_t)` of device and
// pinned host memory per GPU, which is 3 GiB of each at 23.
//
// 23 covers `MAX_DEPLOYMENT_CONSTRAINTS_V2` (2^22). Rounds three and four
// allocate outside the pool.
#ifndef MAX_LG_DOMAIN
#define MAX_LG_DOMAIN 23
#endif

// Lazy instantiation of snarkvm_t
class snarkvm_singleton_t {
    std::once_flag once;
    snarkvm_t *snarkvm = nullptr;
    // One code for every construction failure, so a caught 801 from an
    // allocation cannot read as a pool capacity refusal.
    cudaError_t fail_code = cudaErrorInitializationError;
    std::string fail_detail;

    // Never throws: `std::call_once` does not mark a call that throws as
    // done, so the next call would build the pool again.
    void init() noexcept {
        try {
            // With no usable GPU, `snarkvm_t` builds an empty slot pool, and
            // the first call waits forever for a slot.
            if (ngpus() == 0) {
                fail_code = cudaErrorNoDevice;
                return;
            }
            snarkvm = new snarkvm_t(MAX_LG_DOMAIN);
        } catch (const std::exception& e) {
            snarkvm = nullptr;
            try { fail_detail = e.what(); } catch (...) {}
        } catch (...) {
            snarkvm = nullptr;
        }
    }

public:
    snarkvm_singleton_t() {}
    ~snarkvm_singleton_t() {
        delete snarkvm;
        snarkvm = nullptr;
    }
    // Builds the pool once, however many threads make the first call.
    bool ok() {
        std::call_once(once, [this] { init(); });
        return snarkvm != nullptr;
    }
    // Why `ok()` failed: `cudaErrorNoDevice` for no usable GPU, or
    // `cudaErrorInitializationError` for a pool that would not build. No
    // per-call path returns either.
    RustError failure() const {
        return RustError{fail_code, fail_detail};
    }
    snarkvm_t* operator->() {
        assert (ok());
        return snarkvm;
    }
};
snarkvm_singleton_t snarkvm_g;

// blst's portable routines choose ADX from `__blst_platform_cap`, which a
// constructor in blst's `server.c` sets from CPUID. Nothing else here calls
// into `server.c`, so without this reference the linker drops it, the flag
// stays 0, and ADX is never used.
extern "C" size_t blst_p1_sizeof(void);
__attribute__((used)) static size_t (*const keep_blst_cpuid)(void) = blst_p1_sizeof;
extern "C" int __blst_platform_cap;

// sppark reports device failures by throwing, and an exception that crosses
// `extern "C"` into Rust is undefined behaviour.
template<class F> static RustError catch_all(F f) noexcept
{
    try {
        return f();
    } catch (const cuda_error& e) {
        return RustError{e.code(), e.what()};
    } catch (...) {
        return RustError{cudaErrorUnknown};
    }
}

#ifndef __CUDA_ARCH__

extern "C" {
    int snarkvm_blst_platform_cap()
    {
        return __blst_platform_cap;
    }

    /// How many CUDA devices the runtime reports. Zero on any error.
    size_t snarkvm_cuda_device_count()
    {
        int count = 0;
        if (cudaGetDeviceCount(&count) != cudaSuccess) {
            return 0;
        }
        return (size_t)count;
    }

    /// Elements the device pool reserves per device per stream slot.
    ///
    /// `NTT` admits a domain up to this, `PolyMul` up to a quarter of it.
    /// `snarkvm_algorithms_cuda::max_domain()` derives the circuit limit.
    ///
    /// Zero if there is no usable pool; the entry points return
    /// `snarkvm_g.failure()` with the reason.
    size_t snarkvm_cuda_pool_elements()
    {
        try {
            return snarkvm_g.ok() ? snarkvm_g->pool_elements() : 0;
        } catch (...) {
            return 0;
        }
    }

    // Device 0's free and total bytes. False if the runtime cannot say.
    bool snarkvm_cuda_device_memory(size_t* free_out, size_t* total_out)
    {
        return cudaSetDevice(0) == cudaSuccess
            && cudaMemGetInfo(free_out, total_out) == cudaSuccess;
    }

    // The resident windows' length: the pool's NTT bound, 2^(MAX_LG_DOMAIN+2),
    // from the build alone. Unlike `snarkvm_cuda_pool_elements` it builds
    // nothing, so it is safe to ask before the device is ready.
    size_t snarkvm_cuda_window_points()
    {
        return size_t(1) << (MAX_LG_DOMAIN + 2);
    }

    RustError snarkvm_ntt(fr_t* inout, uint32_t lg_domain_size,
                          NTT::InputOutputOrder ntt_order, NTT::Direction ntt_direction,
                          NTT::Type ntt_type)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->NTT(inout, inout, lg_domain_size, ntt_order,
                                  ntt_direction, ntt_type);
        });
    }

    RustError snarkvm_lineval_interpolate_mul(fr_t* out, const fr_t* evals,
                                              size_t ncols, const fr_t* assignment,
                                              size_t assignment_len,
                                              uint32_t lg_domain_size,
                                              uint32_t lg_mul_domain)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->LinevalInterpolateMul(out, evals, ncols, assignment,
                                                    assignment_len, lg_domain_size,
                                                    lg_mul_domain);
        });
    }

    RustError snarkvm_fourth_round_chain(fr_t* a_out, fr_t* b_out, fr_t* g_out,
                                         fr_t* lhs_out, fr_t* f0_out,
                                         const fr_t* row, const fr_t* col,
                                         const fr_t* rcv, const fr_t* d_evals,
                                         size_t len, uint32_t lg_domain_size,
                                         uint32_t lg_mul_domain, size_t q_len,
                                         const fr_t* alpha, const fr_t* beta,
                                         const fr_t* coeff, const fr_t* b_scale,
                                         const fr_t* a_scale,
                                         const fr_t* selector_mult,
                                         void* const* keep, size_t* kept_lens)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->FourthRoundChain(a_out, b_out, g_out, lhs_out,
                                               f0_out, row, col, rcv, d_evals, len,
                                               lg_domain_size, lg_mul_domain,
                                               q_len, alpha, beta, coeff,
                                               b_scale, a_scale, selector_mult,
                                               keep, kept_lens);
        });
    }

    RustError snarkvm_fourth_round_polys(fr_t* a_out, fr_t* b_out, fr_t* f_out,
                                         const fr_t* row, const fr_t* col,
                                         const fr_t* rcv, size_t len,
                                         uint32_t lg_domain_size,
                                         const fr_t* alpha, const fr_t* beta,
                                         const fr_t* coeff, const fr_t* b_scale,
                                         const fr_t* a_scale)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->FourthRoundPolys(a_out, b_out, f_out, row, col,
                                               rcv, len, lg_domain_size, alpha,
                                               beta, coeff, b_scale, a_scale);
        });
    }

    RustError snarkvm_polymul(fr_t* out,
                              size_t pcount, fr_t** polynomials, size_t* plens,
                              size_t ecount, fr_t** evaluations, size_t* elens,
                              uint32_t lg_domain_size) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->PolyMul(out,
                                      pcount, polynomials, plens,
                                      ecount, evaluations, elens,
                                      lg_domain_size);
        });
    }

    RustError snarkvm_accumulate_open(point_t* out, size_t out_len,
                                      size_t nterms, const fr_t* const* polys,
                                      const size_t* lens, const fr_t* coeffs,
                                      const fr_t* z,
                                      const affine_t bases[], size_t nbases,
                                      size_t ffi_affine_size,
                                      const void* d_bases, size_t d_offset,
                                      const fr_t* const* d_polys)
    {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->AccumulateOpen(out, out_len, nterms, polys, lens,
                                             coeffs, z, bases, nbases,
                                             ffi_affine_size, d_bases, d_offset,
                                             d_polys);
        });
    }

    /// `mont` says the scalars arrive in Montgomery form, and sppark reduces
    /// them in its digit-extraction kernel.
    RustError snarkvm_msm(point_t* out, const affine_t points[], size_t npoints,
                          const scalar_t scalars[], size_t ffi_affine_size,
                          bool mont, const void* d_bases, size_t d_offset,
                          const scalar_t* d_scalars) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->MSM(out, points, npoints, scalars, ffi_affine_size,
                                  mont, d_bases, d_offset, d_scalars);
        });
    }

    // Whether resident windows can be loaded: the device singleton's own
    // failure if it did not build (latched, like every entry point's), and
    // cudaErrorNotSupported if MSMs split across more than one GPU.
    RustError snarkvm_bases_status() {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return RustError{snarkvm_g->BasesSupported() ? cudaSuccess : cudaErrorNotSupported};
        });
    }

    RustError snarkvm_bases_alloc(void** d_out, size_t* bytes_out, size_t npoints) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->AllocBases(d_out, bytes_out, npoints);
        });
    }

    RustError snarkvm_bases_upload_at(void* d, size_t offset,
                                      const affine_t points[], size_t npoints,
                                      size_t ffi_affine_size) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->UploadBasesAt(d, offset, points, npoints,
                                            ffi_affine_size);
        });
    }

    RustError snarkvm_resident_upload(void** d_out, const void* const* srcs,
                                      size_t count, size_t bytes) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->UploadResident(d_out, srcs, count, bytes);
        });
    }

    RustError snarkvm_resident_download(void* out, const void* d, size_t bytes) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->DownloadResident(out, d, bytes);
        });
    }

    RustError snarkvm_resident_reserve(void** out, size_t n, size_t bytes) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->ReserveResident(out, n, bytes);
        });
    }

    RustError snarkvm_device_evaluate(fr_t* out, const fr_t* d, size_t len,
                                      const fr_t* z) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->DeviceEvaluate(out, d, len, z);
        });
    }

    RustError snarkvm_device_combine(void** keep, size_t* trimmed, size_t nterms,
                                     const fr_t* const* d_polys,
                                     const size_t* lens, const fr_t* coeffs,
                                     size_t out_len) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->DeviceCombine(keep, trimmed, nterms, d_polys, lens,
                                            coeffs, out_len);
        });
    }

    void snarkvm_bases_release(void* d) {
        RustError e = catch_all([&] {
            if (snarkvm_g.ok()) {
                snarkvm_g->ReleaseBases(d);
            }
            return RustError{cudaSuccess};
        });
        free(e.message);
    }
}
#endif // __CUDA_ARCH__

#endif
