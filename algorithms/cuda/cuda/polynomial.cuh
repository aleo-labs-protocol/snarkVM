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

#ifndef __POLYNOMIAL_CUH__
#define __POLYNOMIAL_CUH__

#ifndef __CUDA_ARCH__

#include <util/exception.cuh>
#include <util/rusterror.h>
#include <util/gpu_t.cuh>

#endif

#ifndef __CUDA_ARCH__
void host_print_fr(fr_t f) {
    uint64_t val[4];
    f.from();
    f.store((limb_t*)val);
    printf("0x%016lx%016lx%016lx%016lx\n", val[3], val[2], val[1], val[0]);
}
#endif

__global__
void polynomial_inner_multiply(size_t domain_size, fr_t* out, fr_t* in0, fr_t* in1) {
    index_t idx = threadIdx.x + blockDim.x * (index_t)blockIdx.x;
    if (idx >= domain_size)
        return;
    
    fr_t x = in0[idx];
    fr_t y = in1[idx];
    out[idx] = x * y;
}

#ifndef __CUDA_ARCH__

class Polynomial : public NTT {
protected:
    static void mul_copy_poly(fr_t* hmem, fr_t* dmem, fr_t* poly, size_t len,
                              stream_t& stream, uint32_t lg_domain_size) {
        size_t domain_size = (size_t)1 << lg_domain_size;
        // Stage into the pinned buffer, then transfer. The first copy is
        // host-to-host and charges the caller; only the second crosses the bus.
        cudaMemcpyAsync(hmem, poly, sizeof(fr_t) * len, cudaMemcpyHostToHost, stream);
        stream.HtoD(dmem, hmem, len);
        cudaMemsetAsync(&dmem[len], 0, sizeof(fr_t) * (domain_size - len), stream);
    }
    static void mul_copy_eval(fr_t* hmem, fr_t* dmem,
                              fr_t* eval, size_t len,
                              stream_t& stream, uint32_t lg_domain_size) {
        size_t domain_size = (size_t)1 << lg_domain_size;
        // Evaluations fill the domain exactly, so unlike `mul_copy_poly` there
        // is no tail to zero.
        assert (len == domain_size);
        cudaMemcpyAsync(hmem, eval, sizeof(fr_t) * len, cudaMemcpyHostToHost, stream);
        stream.HtoD(dmem, hmem, len);
    }
    
public:
    // A polymul on data that is already on the device.
    //
    // The same transform `Mul` runs, minus the staging, the transfers and the
    // sync, so a caller already holding the inputs drives it directly.
    //
    // `d_in0` and `d_in1` are consumed: both are left transformed rather than as
    // the caller passed them. `d_out` may alias neither.
    static void MulDev(stream_t& stream,
                       fr_t* d_out, fr_t* d_in0, fr_t* d_in1,
                       uint32_t lg_domain_size)
    {
        size_t domain_size = (size_t)1 << lg_domain_size;

        NTT::Base_dev_ptr(stream, d_in0, lg_domain_size, NTT::InputOutputOrder::NR,
                          NTT::Direction::forward, NTT::Type::standard);
        NTT::Base_dev_ptr(stream, d_in1, lg_domain_size, NTT::InputOutputOrder::NR,
                          NTT::Direction::forward, NTT::Type::standard);

        // Full coverage, not the `sm_count * 8` cap the launchers in
        // batchinv.cu use: `polynomial_inner_multiply` is **not** grid-stride --
        // it returns when `idx >= domain_size` and never loops. Capping the grid
        // here would silently drop every coefficient past the cap.
        int block = 1024;
        int grid = (int)((domain_size + block - 1) / block);
        polynomial_inner_multiply<<<grid, block, 0, stream>>>
            (domain_size, d_out, d_in0, d_in1);
        CUDA_OK(cudaGetLastError());

        NTT::Base_dev_ptr(stream, d_out, lg_domain_size, NTT::InputOutputOrder::RN,
                          NTT::Direction::inverse, NTT::Type::standard);
    }

    // `hmem0` receives `1 << lg_domain_size` coefficients.
    static RustError Mul(const gpu_t& gpu, stream_t& stream,
                         fr_t* hmem0, fr_t* hmem1, fr_t* hmem2,
                         fr_t* dmem0, fr_t* dmem1, fr_t* dmem2, fr_t* dmem3,
                         size_t pcount, fr_t** polynomials, size_t* plens,
                         size_t ecount, fr_t** evaluations, size_t* elens,
                         uint32_t lg_domain_size) {
        try {
            gpu.select();

            size_t domain_size = (size_t)1 << lg_domain_size;

            size_t pcur = 0;
            size_t ecur = 0;

            // Set up the first polynomial / evaluation in dmem0
            if (pcount > 0) {
                mul_copy_poly(hmem0, dmem0, polynomials[0], plens[0], stream, lg_domain_size);
                // Perform NTT on the input data
                NTT_internal(dmem0, lg_domain_size, NTT::InputOutputOrder::NR,
                             NTT::Direction::forward, NTT::Type::standard, stream);
                pcur++;
            } else {
                mul_copy_eval(hmem0, dmem3, evaluations[0], elens[0], stream, lg_domain_size);
                // Bit reversal
                bit_rev(dmem0, dmem3, lg_domain_size, stream);
                ecur++;
            }

            // Compute counters
            size_t pcomp = pcur;
            size_t ecomp = ecur;
            // Alternate stream
            stream_t& alt = gpu;

            // Start copying the next data into dmem on the alternate stream
            if (pcur < pcount) {
                mul_copy_poly(hmem2, dmem2, polynomials[pcur], plens[pcur], alt, lg_domain_size);
                pcur++;
            } else {
                assert (ecur < ecount);
                mul_copy_eval(hmem2, dmem2, evaluations[ecur], elens[ecur], alt, lg_domain_size);
                ecur++;
            }

            // From here we overlap compute and copy using a double buffer
            fr_t* hmem_comp = hmem2;
            fr_t* dmem_comp = dmem2;
            fr_t* hmem_copy = hmem1;
            fr_t* dmem_copy = dmem1;
            bool comp_on_mem2 = true;
            
            while (pcomp < pcount || ecomp < ecount) {
                // Sync the alternate stream to ensure data is on the GPU
                alt.sync();
                // And the compute stream to ensure the compute buffers can be overwritten
                stream.sync();

                // Start the computation
                fr_t* mul_src = nullptr;
                if (pcomp < pcount) {
                    // Perform NTT on the input data
                    NTT_internal(dmem_comp, lg_domain_size, NTT::InputOutputOrder::NR,
                                 NTT::Direction::forward, NTT::Type::standard, stream);
                    mul_src = dmem_comp;
                    pcomp++;
                } else {
                    // Bit reversal into an aux buffer
                    bit_rev(dmem3, dmem_comp, lg_domain_size, stream);
                    mul_src = dmem3;
                    ecomp++;
                }

                // Inner multiply
                polynomial_inner_multiply<<<(domain_size + 1023) / 1024, 1024, 0, stream>>>
                    (domain_size, dmem0, dmem0, mul_src);
                CUDA_OK(cudaGetLastError());

                // Start the next copy on `alt`, so it overlaps the compute just
                // queued on `stream`.
                if (pcur < pcount) {
                    mul_copy_poly(hmem_copy, dmem_copy, polynomials[pcur], plens[pcur],
                                  alt, lg_domain_size);
                    pcur++;
                } else if (ecur < ecount) {
                    mul_copy_eval(hmem_copy, dmem_copy, evaluations[ecur], elens[ecur],
                                  alt, lg_domain_size);
                    ecur++;
                }

                // Swap buffers
                std::swap(hmem_comp, hmem_copy);
                std::swap(dmem_comp, dmem_copy);
                comp_on_mem2 = !comp_on_mem2;
            }

            // Perform iNTT on the result
            NTT_internal(dmem0, lg_domain_size,
                         NTT::InputOutputOrder::RN, NTT::Direction::inverse,
                         NTT::Type::standard, stream);
            
            // Copy the output data
            stream.DtoH(hmem0, dmem0, domain_size);
            stream.sync();
        } catch (const cuda_error& e) {
            // A throwing drain must not replace the error it is draining for.
            // This one is wider than the others: `gpu_t::sync()` covers every
            // flip-flop stream, so it can fail on a fault raised by a different
            // slot running concurrently.
            try {
                gpu.sync();
            } catch (...) {
            }
#ifdef TAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE
            return RustError{e.code(), e.what()};
#else
            return RustError{e.code()};
#endif
        }

        return RustError{cudaSuccess};
    }
};
#endif //  __CUDA_ARCH__

#endif
