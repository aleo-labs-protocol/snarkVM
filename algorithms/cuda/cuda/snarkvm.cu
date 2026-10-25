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

#if defined(FEATURE_BLS12_381)
# include <ff/bls12-381.hpp>
#elif defined(FEATURE_BLS12_377)
# include <ff/bls12-377.hpp>
#elif defined(FEATURE_BN254)
# include <ff/alt_bn128.hpp>
#else
# error "no FEATURE"
#endif

#include <ntt/ntt.cuh>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <stdexcept>

// Blank is nothing, or nothing but whitespace. Separate from `getenv` so the
// rule can be asserted at compile time: every knob caches its answer in a
// `static`, so no test run could exercise it.
constexpr bool env_is_blank(const char* s)
{
    if (s == nullptr) return true;
    for (; *s != '\0'; ++s) {
        if (*s != ' ' && *s != '\t' && *s != '\r' && *s != '\n') return false;
    }
    return true;
}

static_assert(env_is_blank(nullptr), "unset is blank");
static_assert(env_is_blank(""), "`docker run -e X` is blank");
static_assert(env_is_blank(" \t\r\n"), "whitespace-only is blank");
static_assert(!env_is_blank("12"), "a value is not blank");
static_assert(!env_is_blank(" 12"), "whitespace around a value leaves a value, "
                                    "which env_int_in_range then refuses");

// `getenv`, with a blank value reading as unset.
//
// An empty or whitespace-only value, as an unset `${VAR}` in a CI expression, a
// bare `docker run -e X` or a stray `--env-file` line produces, means nobody set
// the knob. Every knob reads through this. Whitespace around a value leaves it a
// value, so `" 12"` still reaches `snarkvm_t::env_int_in_range` and is refused
// there.
inline const char* snarkvm_env(const char* name)
{
    const char* s = getenv(name);
    return env_is_blank(s) ? nullptr : s;
}

#include "polynomial.cuh"

#include <ec/jacobian_t.hpp>
#include <ec/xyzz_t.hpp>

typedef jacobian_t<fp_t> point_t;
typedef xyzz_t<fp_t> bucket_t;
typedef bucket_t::affine_inf_t affine_t;
typedef fr_t scalar_t;

#define WBITS 11 // Suitable for ~2^16
#include <msm/pippenger.cuh>
#undef WBITS

// A simple way to allocate a host pointer without having to
// care about freeing it.
template<typename T> class host_ptr_t {
    T* h_ptr;
public:
    host_ptr_t(size_t nelems) : h_ptr(nullptr)
    {
        if (nelems) {
            CUDA_OK(cudaMallocHost(&h_ptr, nelems * sizeof(T)));
        }
    }
    ~host_ptr_t() { if (h_ptr) cudaFreeHost((void*)h_ptr); }

    inline operator const T*() const            { return h_ptr; }
    inline operator T*() const                  { return h_ptr; }
    inline operator void*() const               { return (void*)h_ptr; }
    inline const T& operator[](size_t i) const  { return h_ptr[i]; }
    inline T& operator[](size_t i)              { return h_ptr[i]; }
};

#ifndef __CUDA_ARCH__

#include <vector>
#include <chrono>
#include <atomic>
#include <mutex>
#include <cstring>
#include <string>
#include <exception>

typedef std::chrono::high_resolution_clock Clock;

using namespace std;

static_assert(cudaErrorNotSupported == 801, "snarkvm-algorithms' CUDA_ERROR_NOT_SUPPORTED");

// Defined in batchinv.cu. Kept there so its kernels stay out of this
// translation unit; only this host call crosses.
void fourth_round_evals_device(const stream_t& stream, int sm_count,
                               fr_t* d_a, fr_t* d_b, fr_t* d_f,
                               const fr_t* d_row, const fr_t* d_col,
                               const fr_t* d_rcv,
                               fr_t* d_scan, fr_t* d_scan_rev, fr_t* d_t,
                               fr_t alpha, fr_t beta, fr_t coeff,
                               fr_t b_scale, fr_t a_scale, size_t len);
// Defined in batchinv.cu. Kept there so its kernel stays out of this
// translation unit; only this host call crosses.
void accumulate_axpy_device(const stream_t& stream, int sm_count,
                            fr_t* d_acc, const fr_t* d_src, fr_t coeff, size_t len);
// Defined in batchinv.cu, for the same reason.
void widen_points_device(const stream_t& stream, int sm_count, uint64_t* d_dst,
                         const uint64_t* d_src, size_t npoints,
                         size_t src_words, size_t dst_words);

// Defined in div.cu, for the same reason. In place: the remainder lands in slot
// 0 and the quotient in [1, len).
void divide_by_x_minus_z_device(const stream_t& stream, fr_t* d_inout,
                                size_t len, const fr_t& z);

// Defined in batchinv.cu, for the reason the others there are.
void round4_sub_device(const stream_t& stream, int sm_count, fr_t* d_out,
                       const fr_t* d_a, size_t a_len, const fr_t* d_b, size_t len);
void round4_vanishing_device(const stream_t& stream, int sm_count,
                             fr_t* d_q, unsigned* d_nonzero, const fr_t* d_p,
                             size_t n, size_t q_len, size_t total, fr_t mult);

// Returns `cudaErrorNotSupported` with a message naming the domain and the
// limit it exceeds. Falls back to the bare code if the message cannot be
// built, since nothing may cross `extern "C"`.
static RustError pool_refusal(const char* op, size_t domain_size, size_t limit) noexcept {
    try {
        return RustError{cudaErrorNotSupported,
                         std::string(op) + " domain of " + std::to_string(domain_size)
                         + " exceeds the device pool's limit of " + std::to_string(limit)};
    } catch (...) {
        return RustError{cudaErrorNotSupported};
    }
}

class snarkvm_t {
    thread_pool_t pool;

    struct resource_t {
        int dev;
        int stream;
        resource_t(int _dev, int _stream) {
            dev = _dev;
            stream = _stream;
        }
    };
    channel_t<resource_t*> resources;

    // Returns a pool slot on every path out, including an exception. A lost
    // slot is never replaced, and after `ngpus() * FLIP_FLOP` losses
    // `resources.recv()` blocks forever.
    class slot_t {
        channel_t<resource_t*>& pool;
        resource_t* r;
    public:
        slot_t(channel_t<resource_t*>& p) : pool(p), r(p.recv()) {}
        // `Polynomial::Mul` syncs the device in its own `cuda_error` handler.
        // Only an exception it does not catch can leave zero-stream copies into
        // the staging buffers in flight, so the whole device is synced only then.
        ~slot_t() noexcept {
            try {
                auto& gpu = select_gpu(r->dev);
                if (std::uncaught_exceptions()) gpu.sync(); else gpu[r->stream].sync();
            } catch (...) {}
            try { pool.send(r); } catch (...) {}
        }
        slot_t(const slot_t&) = delete;
        slot_t& operator=(const slot_t&) = delete;
        int dev() const { return r->dev; }
        int stream() const { return r->stream; }
    };

    // Host and device storage
    size_t                         allocated_elements;
    std::vector<dev_ptr_t<fr_t>*>  d_mem;
    std::vector<host_ptr_t<fr_t>*> h_mem;

    void free_memory() {
        allocated_elements = 0;
        for (size_t i = 0; i < ngpus(); i++) {
            if (d_mem[i] != nullptr) {
                delete d_mem[i];
                d_mem[i] = nullptr;
            }
            if (h_mem[i] != nullptr) {
                delete h_mem[i];
                h_mem[i] = nullptr;
            }
        }
    }

    fr_t *d_addr(uint32_t dev, uint32_t stream) {
        if (allocated_elements == 0) {
            assert(false);
            return nullptr;
        }
        fr_t* dmem = *d_mem[dev];
        return &dmem[allocated_elements * stream];
    }
    fr_t *h_addr(uint32_t dev, uint32_t stream) {
        if (allocated_elements == 0) {
            assert(false);
            return nullptr;
        }
        fr_t* hmem = *h_mem[dev];
        return &hmem[allocated_elements * stream];
    }
    
public:
    // Elements the pool reserves per device per stream slot. `NTT` admits a
    // domain up to this, `PolyMul` up to a quarter of it.
    size_t pool_elements() const { return allocated_elements; }

    // A tuning knob that cannot be parsed is refused, not ignored, so a typo
    // cannot run as the default. `snarkvm_env` maps a blank variable to unset
    // before it reaches here; a value with whitespace around it still arrives,
    // and is refused.
    static int env_int_in_range(const char* name, const char* s,
                                int lo, int hi)
    {
        // `strtol` skips leading whitespace but not trailing, which would
        // accept " 12" and refuse "12 ". Requiring the first character to start
        // an integer literal makes both sides the same answer.
        char* end = nullptr;
        errno = 0;
        long v = strtol(s, &end, 10);
        bool starts_clean = (s[0] == '-' || s[0] == '+' || (s[0] >= '0' && s[0] <= '9'));
        bool parsed = starts_clean && (end != s) && (*end == '\0') && (errno == 0);
        if (!parsed || v < lo || v > hi) {
            fprintf(stderr,
                    "%s=\"%s\" is not a value this build understands "
                    "(expected an integer in %d..%d). Refusing rather than "
                    "falling back to the default, which would make the run look "
                    "like a measurement of the setting you asked for.\n",
                    name, s, lo, hi);
            abort();
        }
        return (int)v;
    }

    // Worker threads for MSM. MSM() spawns one task per GPU and blocks on it,
    // so with one thread per GPU every MSM call queues behind every other. Two
    // per GPU, fitted on an L4, overlap one call's upload with another's
    // compute; each concurrent call builds its own bucket arrays, so this
    // trades device memory for the overlap. SNARKVM_MSM_THREADS=<n> overrides
    // it.
    static size_t msm_pool_size() {
        size_t n = ngpus() * 2;
        if (const char* s = snarkvm_env("SNARKVM_MSM_THREADS")) {
            n = (size_t)env_int_in_range("SNARKVM_MSM_THREADS", s, 1, 1024);
        }
        return n;
    }

    snarkvm_t(int max_lg_domain) : pool(msm_pool_size()) {
        // Validates both tuning knobs before anything serves: `msm_pool_size()`
        // ran in the initialiser list, and this forces the other, so a typo
        // refuses to start rather than aborting at the first MSM.
        (void)msm_wbits();

        // Allocate storage for 4 polynomials, required by polynomial multiplication
        // Will be allocated per gpu per stream
        allocated_elements = ((size_t)1 << max_lg_domain) * 4;

        d_mem.resize(ngpus());
        h_mem.resize(ngpus());
        for (size_t i = 0; i < ngpus(); i++) {
            d_mem[i] = nullptr;
            h_mem[i] = nullptr;
        }
        try {
            for (size_t i = 0; i < ngpus(); i++) {
                auto& gpu = select_gpu(i);
                d_mem[i] = new dev_ptr_t<fr_t>(allocated_elements * gpu_t::FLIP_FLOP);
                h_mem[i] = new host_ptr_t<fr_t>(allocated_elements * gpu_t::FLIP_FLOP);
            }
        } catch (const cuda_error& e) {
            // Clean up, then rethrow. Completing with `allocated_elements == 0`
            // would fail every later capacity check as `cudaErrorNotSupported`,
            // reporting a startup failure as a property of each circuit.
            // `snarkvm_singleton_t::init()` reports it as
            // `cudaErrorInitializationError`.
            free_memory();
            throw;
        }

        // GPU resource allocation scheme
        for (size_t j = 0; j < gpu_t::FLIP_FLOP; j++) {
            for (size_t dev = 0; dev < ngpus(); dev++) {
                resources.send(new resource_t(dev, j));
            }
        }
    }
    ~snarkvm_t() {}

    // The fourth round's chain, from row/col/rcv to the selector's output,
    // without the polynomials leaving the device. After FourthRoundPolys's
    // interpolations it runs the shift into g, the b*f multiply, the
    // subtraction and the vanishing divide with its scaling.
    //
    // a, b and g come back, because they are committed and opened, as do the
    // selector's quotient and f's constant term. `g = f.coeffs[1..]` is a
    // download starting at `d_f + 1`.
    //
    // The caller's obligations:
    //
    // - `selector_mult` is `combiner * src_domain.size_as_field_element *
    //   target_domain.size_inv`, not the combiner. A wrong value is not
    //   detected.
    // - `q_len` is an upper bound on the quotient's length; the caller passes
    //   `domain_size - 1`, which always holds. Too small a bound strands
    //   quotient coefficients, which `d_vanishing_scaled` refuses.
    // - `g_out` receives `domain_size - 1` untrimmed coefficients, and
    //   `check_degrees_and_bounds` rejects `g` above its degree bound, so the
    //   caller must build `g` through something that trims, such as
    //   `from_coefficients_vec`.
    RustError FourthRoundChain(fr_t* a_out, fr_t* b_out, fr_t* g_out,
                               fr_t* lhs_out, fr_t* f0_out,
                               const fr_t* row, const fr_t* col, const fr_t* rcv,
                               size_t len, uint32_t lg_domain_size,
                               uint32_t lg_mul_domain, size_t q_len,
                               const fr_t* alpha, const fr_t* beta,
                               const fr_t* coeff, const fr_t* b_scale,
                               const fr_t* a_scale, const fr_t* selector_mult)
    {
        if (len == 0)
            return RustError{cudaSuccess};

        size_t domain_size = (size_t)1 << lg_domain_size;
        size_t mul_domain = (size_t)1 << lg_mul_domain;
        if (len > domain_size || mul_domain < 2 * domain_size)
            return RustError{cudaErrorInvalidValue};
        // Only the single-step branch of `divide_by_vanishing_poly`, which
        // needs `q_len <= n`, is implemented. Any other shape is refused.
        if (q_len > domain_size || q_len + domain_size > mul_domain)
            return RustError{cudaErrorInvalidValue};

        slot_t slot(resources);
        RustError ret = RustError{cudaSuccess};
        try {
            auto& gpu = select_gpu(slot.dev());
            stream_t& stream = gpu[slot.stream()];
            try {
                dev_ptr_t<fr_t> d_a{domain_size, stream}, d_b{domain_size, stream},
                                d_f{domain_size, stream};

                if (domain_size > len) {
                    size_t tail = (domain_size - len) * sizeof(fr_t);
                    CUDA_OK(cudaMemsetAsync(&d_a[len], 0, tail, stream));
                    CUDA_OK(cudaMemsetAsync(&d_b[len], 0, tail, stream));
                    CUDA_OK(cudaMemsetAsync(&d_f[len], 0, tail, stream));
                }

                // Scoped, so these buffers are freed before the multiply's
                // `mul_domain` buffers are allocated.
                {
                    dev_ptr_t<fr_t> d_in{3 * len, stream};
                    dev_ptr_t<fr_t> d_scan{len, stream}, d_scan_rev{len, stream};
                    dev_ptr_t<fr_t> d_t{1, stream};

                    stream.HtoD(&d_in[0], row, len);
                    stream.HtoD(&d_in[len], col, len);
                    stream.HtoD(&d_in[2 * len], rcv, len);

                    fourth_round_evals_device(stream, gpu.sm_count(),
                                              &d_a[0], &d_b[0], &d_f[0],
                                              &d_in[0], &d_in[len], &d_in[2 * len],
                                              &d_scan[0], &d_scan_rev[0], &d_t[0],
                                              *alpha, *beta, *coeff, *b_scale,
                                              *a_scale, len);
                }

                NTT::Base_dev_ptr(stream, &d_a[0], lg_domain_size,
                                  NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                                  NTT::Type::standard);
                NTT::Base_dev_ptr(stream, &d_b[0], lg_domain_size,
                                  NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                                  NTT::Type::standard);
                NTT::Base_dev_ptr(stream, &d_f[0], lg_domain_size,
                                  NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                                  NTT::Type::standard);

                // b and f, zero-padded into the multiply's larger domain. Both
                // are consumed by MulDev, which is why they are copies rather
                // than the buffers above -- a and b are still wanted intact.
                dev_ptr_t<fr_t> d_m0{mul_domain, stream}, d_m1{mul_domain, stream},
                                d_prod{mul_domain, stream};
                size_t pad = (mul_domain - domain_size) * sizeof(fr_t);
                CUDA_OK(cudaMemcpyAsync(&d_m0[0], &d_b[0], domain_size * sizeof(fr_t),
                                        cudaMemcpyDeviceToDevice, stream));
                CUDA_OK(cudaMemsetAsync(&d_m0[domain_size], 0, pad, stream));
                CUDA_OK(cudaMemcpyAsync(&d_m1[0], &d_f[0], domain_size * sizeof(fr_t),
                                        cudaMemcpyDeviceToDevice, stream));
                CUDA_OK(cudaMemsetAsync(&d_m1[domain_size], 0, pad, stream));

                Polynomial::MulDev(stream, &d_prod[0], &d_m0[0], &d_m1[0],
                                   lg_mul_domain);

                // h = a - b*f, in place over the product. a is the shorter, and
                // its tail is zeros rather than absent.
                round4_sub_device(stream, gpu.sm_count(), &d_prod[0],
                                  &d_a[0], domain_size, &d_prod[0], mul_domain);

                // The vanishing divide and the selector's scaling, with the
                // remainder checked rather than built.
                dev_ptr_t<fr_t> d_lhs{q_len, stream};
                dev_ptr_t<unsigned> d_nonzero{1, stream};
                CUDA_OK(cudaMemsetAsync(&d_nonzero[0], 0, sizeof(unsigned), stream));
                round4_vanishing_device(stream, gpu.sm_count(), &d_lhs[0],
                                        &d_nonzero[0], &d_prod[0],
                                        domain_size, q_len, mul_domain,
                                        *selector_mult);

                unsigned nonzero = 0;
                stream.DtoH(a_out, &d_a[0], domain_size);
                stream.DtoH(b_out, &d_b[0], domain_size);
                stream.DtoH(g_out, &d_f[1], domain_size - 1);
                stream.DtoH(f0_out, &d_f[0], 1);
                stream.DtoH(lhs_out, &d_lhs[0], q_len);
                stream.DtoH(&nonzero, &d_nonzero[0], 1);
                stream.sync();

                // A non-zero remainder means a wrong proof. `cudaErrorAssert`,
                // not the shape guards' `cudaErrorInvalidValue`, so the caller
                // can tell the two apart.
                if (nonzero)
                    ret = RustError{cudaErrorAssert};
            } catch (...) {
                // After a fault the drain fails too, and its error must not
                // replace the cause.
                try {
                    stream.sync();
                } catch (...) {
                }
                throw;
            }
        } catch (const cuda_error& e) {
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
            ret = RustError{e.code(), e.what()};
#else
            ret = RustError{e.code()};
#endif
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
        } catch (const std::exception& e) {
            // Ahead of the catch-all, so a `std::bad_alloc` keeps its message.
            ret = RustError{cudaErrorUnknown, e.what()};
#endif
        } catch (...) {
            // Nothing may cross `extern "C"`: the wrappers in `snarkvm_api.cu`
            // have no handler.
            ret = RustError{cudaErrorUnknown};
        }
        return ret;
    }

    // Round 3's interpolate-then-multiply, as in
    // `calculate_lineval_sumcheck_instance_witness`, without the interpolated
    // polynomial leaving the device.
    RustError LinevalInterpolateMul(fr_t* out, const fr_t* evals, size_t ncols,
                                    const fr_t* assignment, size_t assignment_len,
                                    uint32_t lg_domain_size, uint32_t lg_mul_domain)
    {
        size_t domain_size = (size_t)1 << lg_domain_size;
        size_t mul_domain = (size_t)1 << lg_mul_domain;
        // `Evaluations::from_vec_and_domain` requires the evaluations to fill
        // the domain exactly, so this is equality and not a bound.
        if (ncols != domain_size || assignment_len > domain_size)
            return RustError{cudaErrorInvalidValue};
        if (mul_domain < 2 * domain_size)
            return RustError{cudaErrorInvalidValue};

        slot_t slot(resources);
        RustError ret = RustError{cudaSuccess};
        try {
            auto& gpu = select_gpu(slot.dev());
            stream_t& stream = gpu[slot.stream()];
            try {
                dev_ptr_t<fr_t> d_m{mul_domain, stream}, d_a{mul_domain, stream},
                                d_prod{mul_domain, stream};

                stream.HtoD(&d_m[0], evals, ncols);

                // Interpolate in place.
                NTT::Base_dev_ptr(stream, &d_m[0], lg_domain_size,
                                  NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                                  NTT::Type::standard);

                CUDA_OK(cudaMemsetAsync(&d_m[domain_size], 0,
                                        (mul_domain - domain_size) * sizeof(fr_t),
                                        stream));

                stream.HtoD(&d_a[0], assignment, assignment_len);
                CUDA_OK(cudaMemsetAsync(&d_a[assignment_len], 0,
                                        (mul_domain - assignment_len) * sizeof(fr_t),
                                        stream));

                Polynomial::MulDev(stream, &d_prod[0], &d_m[0], &d_a[0],
                                   lg_mul_domain);

                stream.DtoH(out, &d_prod[0], mul_domain);
                stream.sync();
            } catch (...) {
                // After a fault the drain fails too, and its error must not
                // replace the cause.
                try {
                    stream.sync();
                } catch (...) {
                }
                throw;
            }
        } catch (const cuda_error& e) {
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
            ret = RustError{e.code(), e.what()};
#else
            ret = RustError{e.code()};
#endif
        } catch (...) {
            // Nothing may cross `extern "C"`: the wrappers in `snarkvm_api.cu`
            // have no handler.
            ret = RustError{cudaErrorUnknown};
        }
        return ret;
    }

    // The f/b/a evaluations and the three interpolations that consume them,
    // with each array crossing the bus once.
    RustError FourthRoundPolys(fr_t* a_out, fr_t* b_out, fr_t* f_out,
                               const fr_t* row, const fr_t* col, const fr_t* rcv,
                               size_t len, uint32_t lg_domain_size,
                               const fr_t* alpha, const fr_t* beta,
                               const fr_t* coeff, const fr_t* b_scale,
                               const fr_t* a_scale)
    {
        if (len == 0)
            return RustError{cudaSuccess};

        size_t domain_size = (size_t)1 << lg_domain_size;
        if (len > domain_size)
            return RustError{cudaErrorInvalidValue};

        // Takes a slot from the pool NTT and polymul use, so this path is
        // bounded by FLIP_FLOP per device too. `select_gpu` can throw, so it
        // sits inside the `try`; `slot_t` releases the slot on every path.
        slot_t slot(resources);
        RustError ret = RustError{cudaSuccess};
        try {
            auto& gpu = select_gpu(slot.dev());
            stream_t& stream = gpu[slot.stream()];
            try {
            // Domain-sized, not len-sized: the interpolation runs over the
            // whole domain, as `interpolate_with_pc` does after
            // `evals.resize(domain.size(), zero)`. The tail is zeroed to match.
            dev_ptr_t<fr_t> d_row{len, stream}, d_col{len, stream}, d_rcv{len, stream};
            dev_ptr_t<fr_t> d_a{domain_size, stream}, d_b{domain_size, stream},
                            d_f{domain_size, stream};
            dev_ptr_t<fr_t> d_scan{len, stream}, d_scan_rev{len, stream};
            dev_ptr_t<fr_t> d_t{1, stream};

            stream.HtoD(&d_row[0], row, len);
            stream.HtoD(&d_col[0], col, len);
            stream.HtoD(&d_rcv[0], rcv, len);

            if (domain_size > len) {
                size_t tail = (domain_size - len) * sizeof(fr_t);
                CUDA_OK(cudaMemsetAsync(&d_a[len], 0, tail, stream));
                CUDA_OK(cudaMemsetAsync(&d_b[len], 0, tail, stream));
                CUDA_OK(cudaMemsetAsync(&d_f[len], 0, tail, stream));
            }

            fourth_round_evals_device(stream, gpu.sm_count(),
                                      &d_a[0], &d_b[0], &d_f[0],
                                      &d_row[0], &d_col[0], &d_rcv[0],
                                      &d_scan[0], &d_scan_rev[0], &d_t[0],
                                      *alpha, *beta, *coeff, *b_scale, *a_scale,
                                      len);

            // Three interpolations, in place, on data that is already here.
            NTT::Base_dev_ptr(stream, &d_a[0], lg_domain_size,
                              NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                              NTT::Type::standard);
            NTT::Base_dev_ptr(stream, &d_b[0], lg_domain_size,
                              NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                              NTT::Type::standard);
            NTT::Base_dev_ptr(stream, &d_f[0], lg_domain_size,
                              NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                              NTT::Type::standard);

            // The results come back into the caller's pageable buffers through
            // the driver's bounce buffer.
            fr_t* outs[3] = { a_out, b_out, f_out };
            fr_t* srcs[3] = { &d_a[0], &d_b[0], &d_f[0] };
            for (int i = 0; i < 3; i++)
                stream.DtoH(outs[i], srcs[i], domain_size);
            stream.sync();
            } catch (...) {
                // After a fault the drain fails too, and its error must not
                // replace the cause.
                try {
                    stream.sync();
                } catch (...) {
                }
                throw;
            }
        } catch (const cuda_error& e) {
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
            ret = RustError{e.code(), e.what()};
#else
            ret = RustError{e.code()};
#endif
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
        } catch (const std::exception& e) {
            // Ahead of the catch-all, so a `std::bad_alloc` keeps its message.
            ret = RustError{cudaErrorUnknown, e.what()};
#endif
        } catch (...) {
            // Nothing may cross `extern "C"`: the wrappers in `snarkvm_api.cu`
            // have no handler.
            ret = RustError{cudaErrorUnknown};
        }
        return ret;
    }

    RustError NTT(fr_t* out, fr_t* in,
                  uint32_t lg_domain_size,
                  NTT::InputOutputOrder ntt_order,
                  NTT::Direction ntt_direction,
                  NTT::Type ntt_type) {
        size_t domain_size = (size_t)1 << lg_domain_size;

        // Larger than the pool this instance preallocated. This check and
        // PolyMul's are the only source of a positive `cudaErrorNotSupported`,
        // so the Rust side can tell it from an allocation failure.
        if (allocated_elements < domain_size) {
            return pool_refusal("NTT", domain_size, allocated_elements);
        }

        slot_t slot(resources);
        int dev = slot.dev();
        auto& gpu = select_gpu(dev);
        int stream_idx = slot.stream();
        stream_t& stream = gpu[stream_idx];

        fr_t* h_mem = h_addr(dev, stream_idx);
        memcpy(h_mem, in, sizeof(fr_t) * domain_size);

        // Run on the slot's own stream, against the slot's slice of the
        // preallocated device block, as `PolyMul` does. Not sppark's
        // `NTT::Base(const gpu_t&, ...)`: anything reached through `gpu_t`
        // runs on its `zero` stream, with an allocation pair and three
        // syncs of a stream every other NTT thread queues on.
        //
        // `lg_domain_size == 0` is a one-element NTT, which is the
        // identity; `NTT::Base` special-cases it, `Base_dev_ptr` does not.
        if (lg_domain_size != 0) {
            fr_t* d_mem = d_addr(dev, stream_idx);
            stream.HtoD(d_mem, h_mem, domain_size);
            NTT::Base_dev_ptr(stream, d_mem, lg_domain_size,
                              ntt_order, ntt_direction, ntt_type);
            stream.DtoH(h_mem, d_mem, domain_size);
            stream.sync();
        }
        // Out of the pinned buffer into the caller's memory. The device
        // transfer is the `DtoH` above; this one is host-to-host.
        memcpy(out, h_mem, sizeof(fr_t) * domain_size);
        return RustError{cudaSuccess};
    }

    RustError PolyMul(fr_t* out,
                      size_t pcount, fr_t** polynomials, size_t* plens,
                      size_t ecount, fr_t** evaluations, size_t* elens,
                      uint32_t lg_domain_size) {
        // domain_size is the size of the final polynomial
        size_t domain_size = (size_t)1 << lg_domain_size;

        // Corner cases
        if (pcount + ecount == 0) {
            return RustError{cudaSuccess};
        } else if (pcount + ecount == 1) {
            if (pcount == 1) {
                memcpy(out, polynomials[0], sizeof(fr_t) * plens[0]);
            } else {
                // Perform iNTT on the single evaluation
                memset((uint8_t*)out, 0, sizeof(fr_t) * domain_size);
                memcpy(out, evaluations[0], sizeof(fr_t) * elens[0]);
                return NTT(out, out, lg_domain_size,
                           NTT::InputOutputOrder::NN, NTT::Direction::inverse,
                           NTT::Type::standard);
            }
            return RustError{cudaSuccess};
        }
        
        // Too large for the preallocated pool, as in `NTT`. PolyMul works on
        // four polynomials of the domain, so it refuses at a quarter of what
        // `NTT` accepts.
        if (allocated_elements < 4 * domain_size) {
            return pool_refusal("PolyMul", domain_size, allocated_elements / 4);
        }

        slot_t slot(resources);
        int dev = slot.dev();
        auto& gpu = select_gpu(dev);
        int stream_idx = slot.stream();
        stream_t& stream = gpu[stream_idx];

        // // Copy data to pinned staging buffer
        fr_t* h_mem0 = h_addr(dev, stream_idx);
        fr_t* h_mem1 = &h_mem0[domain_size];
        fr_t* h_mem2 = &h_mem0[domain_size * 2];
        fr_t* d_mem0 = d_addr(dev, stream_idx);
        fr_t* d_mem1 = &d_mem0[domain_size];
        fr_t* d_mem2 = &d_mem0[domain_size * 2];
        fr_t* d_mem3 = &d_mem0[domain_size * 3];
        RustError e = Polynomial::Mul(gpu, stream,
                                      h_mem0, h_mem1, h_mem2,
                                      d_mem0, d_mem1, d_mem2, d_mem3,
                                      pcount, polynomials, plens,
                                      ecount, evaluations, elens,
                                      lg_domain_size);
        if (e.code != cudaSuccess) {
            return e;
        }

        // `Polynomial::Mul` ends in `stream.DtoH` then `stream.sync()`, so
        // `h_mem0` is complete here without a device-wide sync.
        memcpy(out, h_mem0, sizeof(fr_t) * domain_size);

        return RustError{cudaSuccess};
    }

    // The MSM window for MSM() and AccumulateOpen(). 14 was fitted on an H100
    // at the proof's sizes, 2^18 and 2^19; sppark's heuristic picks 10 at
    // 2^17-2^18, where most MSM time sits. SNARKVM_MSM_WBITS=<10..18> selects
    // a window, and SNARKVM_MSM_WBITS=auto restores sppark's heuristic, which
    // 0 means to the caller.
    //
    // Read and validated once, and the constructor forces it, so a bad value
    // refuses to start. It must not first run at the MSM call site, inside the
    // worker's `catch (...)`, which `abort()` would bypass.
    static int msm_wbits()
    {
        static const int wbits = [] {
            const char* w = snarkvm_env("SNARKVM_MSM_WBITS");
            if (w == nullptr) return 14;
            if (strcmp(w, "auto") == 0) return 0;
            return env_int_in_range("SNARKVM_MSM_WBITS", w, 10, 18);
        }();
        return wbits;
    }

    // Puts `npoints` host points of `ffi_affine_size` bytes each into `d_dst`,
    // one device slot per point, on `stream`. The caller syncs `stream` before
    // anything on another stream reads the slots, and has checked that
    // `ffi_affine_size` is a whole number of words no larger than a slot.
    //
    // The host point is 104 bytes and the device slot is 112. The copy works
    // because is_inf() reads inf[0]&1, which lands on the Rust `bool` at
    // offset 96; the copy keeps that byte in place and zeroes the slot's tail.
    //
    // The points cross as one contiguous copy and a kernel widens them.
    // sppark's `HtoD` widens with a per-row `cudaMemcpy2DAsync`, which is far
    // slower under confidential computing.
    void upload_points(typename affine_t::mem_t* d_dst, const void* points,
                       size_t npoints, size_t ffi_affine_size,
                       const stream_t& stream)
    {
        constexpr size_t slot = sizeof(typename affine_t::mem_t);
        static_assert(slot == 112,
                      "device affine slot is no longer 112 bytes; the widening "
                      "copy into it, and is_inf() reading inf[0]&1 at offset 96, "
                      "both assume it");

        size_t src_words = ffi_affine_size / sizeof(uint64_t);
        size_t dst_words = slot / sizeof(uint64_t);
        dev_ptr_t<uint64_t> d_packed{npoints * src_words, stream};
        stream.HtoD(&d_packed[0], (const uint64_t*)points, npoints * src_words);
        widen_points_device(stream, stream.sm_count(), (uint64_t*)d_dst,
                            &d_packed[0], npoints, src_words, dst_words);
    }

    // The device-pointer form `invoke` takes for points `upload_points` placed.
    //
    // Typed as `dev_ptr_t<affine_t::mem_t>`, the view would re-enter the
    // templated `invoke` for ever. And `affine_t` is the 104-byte host point
    // while the storage is 112-byte slots, so the view must never be indexed:
    // sppark reads only element 0, for its address.
    static dev_ptr_t<affine_t> device_points(typename affine_t::mem_t* d_slots)
    {   return dev_ptr_t<affine_t>{reinterpret_cast<affine_t*>(d_slots)};   }

    // The opening's chain: accumulate the linear combination, divide by X - z,
    // and commit to the quotient, with the polynomial never leaving the device.
    // Only a curve point comes back.
    //
    // The scalars reach sppark as a device pointer: `msm_t::invoke` is
    // templated on the scalar pointer type and adopts a `dev_ptr_t` without
    // uploading. `dev_ptr_t(T*, n)` is a non-owning view, so sppark does not
    // free it.
    //
    // `mont` is true because the quotient is in Montgomery form.
    RustError AccumulateOpen(point_t* out, size_t out_len,
                             size_t nterms, const fr_t* const* polys,
                             const size_t* lens, const fr_t* coeffs,
                             const fr_t* z,
                             const affine_t bases[], size_t nbases,
                             size_t ffi_affine_size)
    {
        // A quotient needs at least two coefficients, and the caller must have
        // supplied a base per quotient coefficient.
        if (out_len < 2 || nbases < out_len - 1)
            return RustError{cudaErrorInvalidValue};
        if (ffi_affine_size > sizeof(typename affine_t::mem_t)
            || ffi_affine_size % sizeof(uint64_t) != 0)
            return RustError{cudaErrorInvalidValue};
        for (size_t j = 0; j < nterms; j++)
            if (lens[j] > out_len)
                return RustError{cudaErrorInvalidValue};

        // The slot is held across the accumulation, the division and the MSM:
        // `d_acc` is allocated stream-ordered on this slot's stream, so
        // releasing the slot before the MSM would issue its free onto a stream
        // another request may have taken.
        slot_t slot(resources);
        RustError ret = RustError{cudaSuccess};
        try {
            auto& gpu = select_gpu(slot.dev());
            stream_t& stream = gpu[slot.stream()];
            dev_ptr_t<fr_t> d_acc{out_len, stream};
            // The quotient is `[1, out_len)`; slot 0 holds the remainder.
            size_t n = out_len - 1;
            dev_ptr_t<typename affine_t::mem_t> d_slots{n, stream};
            try {
                CUDA_OK(cudaMemsetAsync(&d_acc[0], 0, out_len * sizeof(fr_t), stream));

                dev_ptr_t<fr_t> d_buf{out_len, stream};
                for (size_t j = 0; j < nterms; j++) {
                    if (lens[j] == 0)
                        continue;
                    stream.HtoD(&d_buf[0], polys[j], lens[j]);
                    accumulate_axpy_device(stream, gpu.sm_count(),
                                           &d_acc[0], &d_buf[0], coeffs[j], lens[j]);
                }

                divide_by_x_minus_z_device(stream, &d_acc[0], out_len, *z);
                upload_points(&d_slots[0], bases, n, ffi_affine_size, stream);

                // The MSM runs in its own context and streams, so the
                // accumulation, the division and the bases have to be complete
                // before it reads them.
                stream.sync();
            } catch (...) {
                // After a fault the drain fails too, and its error must not
                // replace the cause.
                try {
                    stream.sync();
                } catch (...) {
                }
                throw;
            }

            dev_ptr_t<scalar_t> d_quotient{&d_acc[1], n};

            int wbits = msm_wbits();
            size_t hint = wbits ? (size_t)((1ULL << (wbits + 8)) * 2 / 3) + 32 : n;
            msm_t<bucket_t, point_t, affine_t, scalar_t> msm(nullptr, hint,
                                                             ffi_affine_size,
                                                             slot.dev());
            ret = msm.invoke(*out, device_points(&d_slots[0]), n, d_quotient,
                             /*mont=*/true);
        } catch (const cuda_error& e) {
            out->inf();
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
            ret = RustError{e.code(), e.what()};
#else
            ret = RustError{e.code()};
#endif
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
        } catch (const std::exception& e) {
            // Ahead of the catch-all, so a `std::bad_alloc` keeps its message.
            out->inf();
            ret = RustError{cudaErrorUnknown, e.what()};
#endif
        } catch (...) {
            // Nothing may cross `extern "C"`: the wrappers in `snarkvm_api.cu`
            // have no handler.
            //
            // `out` is written here for the same reason as above: the caller
            // reads it regardless of the code returned.
            out->inf();
            ret = RustError{cudaErrorUnknown};
        }
        return ret;
    }

    RustError MSM(point_t* out, const affine_t points[], size_t npoints,
                  const scalar_t scalars[], size_t ffi_affine_size, bool mont) {
        // The host point's layout cannot be checked from here, so the caller
        // asserts it and passes its size; this checks it fits the device slot
        // as `upload_points` copies it (see there for the layout).
        if (ffi_affine_size > sizeof(typename affine_t::mem_t)
            || ffi_affine_size % sizeof(uint64_t) != 0) {
            return RustError{cudaErrorInvalidValue};
        }

        // With no points, `gpu_count` is 0, and `ch.recv()` below would wait
        // forever. Rust reads all three coordinates, and `inf()` sets only Z,
        // so this writes Rust's zero in full.
        if (npoints == 0) {
            fp_t zero;
            zero.zero();
            *out = point_t{zero, fp_t::one(), zero};
            return RustError{cudaSuccess};
        }

        size_t bases_per_gpu = (npoints + ngpus() - 1) / ngpus();
        // One worker per share, so no worker starts past the last point.
        size_t gpu_count = (npoints + bases_per_gpu - 1) / bases_per_gpu;
        // A failed worker leaves its sum unwritten, and the reduction below
        // reads every one.
        point_t partial_sums[gpu_count];
        for (size_t i = 0; i < gpu_count; i++) {
            partial_sums[i].inf();
        }
        channel_t<size_t> ch;
        RustError error = RustError{cudaSuccess};
        std::mutex error_mtx;

        // Divide the MSM among the GPUs. If a spawn throws, the workers
        // already running still write this frame, so wait for them first.
        for (size_t i = 0; i < gpu_count; i++) {
            auto work = [&, i]() {
                int dev = i;
                size_t start = i * bases_per_gpu;
                size_t sz = std::min(bases_per_gpu, npoints - start);

                const uint8_t* pts = (const uint8_t*)points + start * ffi_affine_size;

                RustError ret;
                try {
                    select_gpu(dev);
                    // A stream of its own: two MSM calls can run on this device
                    // at once, and syncing one of the device's shared streams
                    // would also wait for the other call's queued work.
                    stream_t stream(dev);
                    dev_ptr_t<typename affine_t::mem_t> d_slots{sz, stream};
                    upload_points(&d_slots[0], pts, sz, ffi_affine_size, stream);
                    stream.sync();

                    // invoke() takes the window from the count passed to the
                    // constructor and sizes buckets from it, so a synthetic
                    // count selects the window while invoke() processes the
                    // real sz. `points` stays nullptr: the bases reach invoke
                    // as a device pointer.
                    int wbits = msm_wbits();
                    // Smallest count for which floor(log2(1.5n)) - 8 == wbits.
                    size_t hint = wbits
                        ? (size_t)((1ULL << (wbits + 8)) * 2 / 3) + 32
                        : sz;
                    msm_t<bucket_t, point_t, affine_t, scalar_t> msm(nullptr, hint,
                                                                     ffi_affine_size, dev);
                    ret = msm.invoke(partial_sums[i], device_points(&d_slots[0]),
                                     sz, &scalars[start], mont);
                } catch (const cuda_error& e) {
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
                    ret = RustError{e.code(), e.what()};
#else
                    ret = RustError{e.code()};
#endif
                } catch (...) {
                    // An exception that leaves the worker would skip the
                    // `send` below, and the caller would wait forever.
                    ret = RustError{cudaErrorUnknown};
                }
                if (ret.code != cudaSuccess) {
                    std::lock_guard<std::mutex> lock(error_mtx);
                    if (error.code == cudaSuccess) {
                        error = ret;
                    } else {
                        free(ret.message);
                    }
                }
                ch.send(i);
            };
            try {
                pool.spawn(work);
            } catch (...) {
                for (size_t j = 0; j < i; j++)
                    ch.recv();
                free(error.message);
                throw;
            }
        }
        size_t dev = ch.recv();
        *out = partial_sums[dev];
        for (size_t i = 0; i < gpu_count - 1; i++) {
            dev = ch.recv();
            point_t::dadd(*out, *out, partial_sums[dev]);
        }

        return error;
    }
};

#endif
