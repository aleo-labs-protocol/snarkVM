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
        // Mul and NTT::Base sync the device in their own cuda_error handlers.
        // Only an exception they do not catch can leave zero-stream copies into
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

    snarkvm_t(int max_lg_domain) : pool(ngpus()) {
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

        // Perform NTT
        RustError e = Polynomial::Base(gpu, h_mem, lg_domain_size,
                                       ntt_order, ntt_direction, ntt_type);
        if (e.code != cudaSuccess) {
            return e;
        }
        // Successful. Copy the result back
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

        // Slice this stream's share of the pinned and device pools.
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

    RustError MSM(point_t* out, const affine_t points[], size_t npoints,
                  const scalar_t scalars[], size_t ffi_affine_size) {
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

                // This is ugly, but we only know the size of the affine points in bytes
                const affine_t* pts = (affine_t*)(&((uint8_t*)points)[start * ffi_affine_size]);

                RustError ret;
                try {
                    select_gpu(dev);
                    msm_t<bucket_t, point_t, affine_t, scalar_t> msm(dev);
                    ret = msm.invoke(partial_sums[i], slice_t<affine_t>{pts, sz},
                                     &scalars[start], false, ffi_affine_size);
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
