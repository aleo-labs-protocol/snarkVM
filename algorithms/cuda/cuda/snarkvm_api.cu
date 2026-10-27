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

    RustError snarkvm_msm(point_t* out, const affine_t points[], size_t npoints,
                          const scalar_t scalars[], size_t ffi_affine_size) {
        return catch_all([&] {
            if (!snarkvm_g.ok()) {
                return snarkvm_g.failure();
            }
            return snarkvm_g->MSM(out, points, npoints, scalars, ffi_affine_size);
        });
    }
}
#endif // __CUDA_ARCH__

#endif
