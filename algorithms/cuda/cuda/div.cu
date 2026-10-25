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

// Division by X - z, in its own translation unit: ptxas allocates registers per
// module, so this cooperative, shfl-heavy kernel is kept apart from the NTT and
// MSM kernels and from batchinv.cu's elementwise passes.

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

#include <util/exception.cuh>
#include <util/gpu_t.cuh>
#include <util/rusterror.h>
#include <polynomial/div_by_x_minus_z.cuh>

#include <algorithm>

// The kernel's parameters, shared by the instantiation and the launch below:
// the two must name the same kernel.
constexpr int div_n = 2, div_bsz = 0;
constexpr bool div_rotate = false;

// nvcc compiles this file twice and the launcher below is host-only, so the
// device pass needs this explicit instantiation. Without it,
// `cudaFuncGetAttributes` fails at run time with "invalid resource handle".
template __global__ void
d_div_by_x_minus_z<fr_t, div_n, div_rotate, div_bsz>(fr_t[], size_t, fr_t);

#ifndef __CUDA_ARCH__

// In place. sppark leaves the remainder in slot 0 and the quotient in
// `[1, len)`, so a caller reads the quotient from `d + 1`.
//
// The exchange buffer holds max(WARP_SZ, gridDim) elements: every thread reads
// it at its lane index, and at indices below `gridDim`. sppark's
// `div_by_x_minus_z` wrapper sizes it max(blockDim/WARP_SZ, gridDim), which is
// short when the block is under 32 warps and the grid under 32 blocks, so the
// wrapper is not used. The launch parameters are otherwise the wrapper's.
void divide_by_x_minus_z_device(const stream_t& stream, fr_t* d_inout,
                                size_t len, const fr_t& z)
{
    auto* kernel = d_div_by_x_minus_z<fr_t, div_n, div_rotate, div_bsz>;

    static const int blockDim = [] {
        cudaFuncAttributes attr;
        CUDA_OK(cudaFuncGetAttributes(&attr,
                    d_div_by_x_minus_z<fr_t, div_n, div_rotate, div_bsz>));
        return attr.maxThreadsPerBlock;
    }();

    int gridDim = std::min(stream.sm_count(), blockDim);
    size_t blocks = (len + blockDim - 1) / blockDim;
    if ((size_t)gridDim > blocks)
        gridDim = (int)blocks;
    if (gridDim < 3)
        gridDim = 1;

    int slots = std::max(WARP_SZ, gridDim);
    stream.launch_coop(kernel, {gridDim, blockDim, sizeof(fr_t) * slots},
                       d_inout, len, z);
}

#endif
