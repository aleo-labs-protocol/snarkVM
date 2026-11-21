// Elementwise kernels for `snarkvm.cu`, and the fourth round's batch inversion.
//
// A separate translation unit: ptxas optimises per module, so a kernel added to
// `snarkvm_api.cu`, even one never called, perturbs register allocation for the
// NTT and MSM kernels there.

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
#include <polynomial/prefix_op.cuh>

// One field inversion for the whole array, with the coefficient folded in.
//
// Launch with a full warp, never one thread. `mont_t::reciprocal` is
// warp-cooperative: it pairs lanes with `shfl_xor`, inverts the product of the
// pair, and multiplies back. With a single active thread the shuffle is
// undefined, so every non-zero output is garbage. All 32 lanes invert the same
// value, which the pairing handles: b = a = x, so a*b = x^2, 1/(x^2) * b = 1/x.
template<typename T>
__global__ void d_total(T* t, const T* prefix, size_t len, T coeff)
{
    // A short block gives a wrong proof rather than an error.
    assert(blockDim.x == WARP_SZ && gridDim.x == 1);
    T inv = prefix[len - 1].reciprocal();
    if (blockIdx.x == 0 && threadIdx.x == 0)
        *t = inv * coeff;
}

// out[i] = coeff / a[i] * mul[i], from the two scans:
//   left  = prod_{j<i} b[j]  = P[i-1]        (one at i = 0)
//   right = prod_{j>i} b[j]  = Q[len-2-i]    (one at i = len-1)
// left * right = P[len-1] / b[i], so left * right * t = coeff / a[i].
//
// A zero in `a` stays zero, as in the host's `batch_inversion_and_mul`, and
// stays zero through `mul` too.
template<typename T>
__global__ void d_combine(T* out, const T* a, const T* P, const T* Q,
                          const T* t, const T* mul, size_t len)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < len; i += stride) {
        if (a[i].is_zero()) { out[i] = a[i]; continue; }
        T left  = i == 0       ? T::one() : P[i - 1];
        T right = i == len - 1 ? T::one() : Q[len - 2 - i];
        T v = left * right * (*t);
        out[i] = v * mul[i];
    }
}

// The fourth round's cross products, `b` evaluations and scan inputs, in one
// pass over K.
//
// The host's batch inversion leaves zeros alone, so a zero cross product must
// come back as zero. Mapping it to one keeps it out of the products, and
// `d_combine` puts it back. A zero is unlikely, but `reciprocal()` returns a
// value on zero rather than faulting, so without this the proof would be
// silently wrong.
template<typename T>
__global__ void d_cross(T* cross, T* b_evals, T* scan, T* scan_rev,
                        const T* row, const T* col,
                        T alpha, T beta, T b_scale, size_t len)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < len; i += stride) {
        T cp = (alpha - row[i]) * (beta - col[i]);
        cross[i] = cp;
        b_evals[i] = cp * b_scale;
        T v = cp.is_zero() ? T::one() : cp;
        scan[i] = v;
        scan_rev[len - 1 - i] = v;
    }
}

// acc[i] += coeff * src[i]: one term of a linear combination of polynomials,
// with the accumulator kept on the device across terms.
template<typename T>
__global__ void d_axpy(T* acc, const T* src, T coeff, size_t len)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < len; i += stride)
        acc[i] += coeff * src[i];
}

// Copies `npoints` packed records of `src_words` words into slots of
// `dst_words`, zeroing each slot's tail. One thread per destination word, so
// both sides are read and written in order.
__global__ void d_widen(uint64_t* dst, const uint64_t* src, size_t npoints,
                        size_t src_words, size_t dst_words)
{
    size_t total = npoints * dst_words;
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < total; i += stride) {
        size_t point = i / dst_words;
        size_t word = i - point * dst_words;
        dst[i] = word < src_words ? src[point * src_words + word] : 0;
    }
}


// `h = a_poly - b*f`, where `a` is the shorter of the two.
//
// `DensePolynomial`'s `Sub` zero-extends the shorter operand, so coefficients
// past `a_len` are `-b[i]`. Reading `a` past its end would be an overrun that
// produces a plausible polynomial.
//
// Safe with `out == b`: each thread reads `b[i]` before writing `out[i]`.
template<typename T>
__global__ void d_sub_ext(T* out, const T* a, size_t a_len, const T* b, size_t len)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < len; i += stride) {
        T bi = b[i];
        if (i < a_len) {
            out[i] = a[i] - bi;
        } else {
            T zero;
            zero.zero();
            out[i] = zero - bi;
        }
    }
}

// `divide_by_vanishing_poly` followed by the selector's scaling, in one pass,
// for the single-step case, `q_len <= n`.
//
// The quotient is `q = p[n..]`, scaled. The remainder, `r = p[..n]` with `q`
// added into its first `min(q_len, n)` coefficients, must be zero, so a thread
// sets `nonzero` if its own `r[i]` would be non-zero, without building `r`.
template<typename T>
__global__ void d_vanishing_scaled(T* q, unsigned* nonzero, const T* p,
                                   size_t n, size_t q_len, size_t total, T mult)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < total; i += stride) {
        if (i < n) {
            // The remainder, checked rather than built.
            T r = p[i];
            if (i < q_len) {
                T hi = p[n + i];
                r = r + hi;
                q[i] = hi * mult;
            }
            if (!r.is_zero())
                *nonzero = 1;
        } else if (i >= n + q_len) {
            // Above the quotient. A non-zero coefficient here means the true
            // quotient has terms above `q_len`, which a short `lhs` would drop.
            // Neither branch implies the other: an input can have a zero
            // remainder and its only witness here, as
            // `a_truncated_quotient_is_refused` shows.
            if (!p[i].is_zero())
                *nonzero = 1;
        }
    }
}

// a_evals for the fourth round: row_col_val scaled, here because `rcv` is
// already on the device.
template<class T>
__global__ void d_scale(T* out, const T* in, T s, size_t len)
{
    size_t stride = (size_t)gridDim.x * blockDim.x;
    for (size_t i = (size_t)blockIdx.x * blockDim.x + threadIdx.x; i < len; i += stride)
        out[i] = in[i] * s;
}

// nvcc compiles this file twice and everything below is host-only, so the
// device pass needs these explicit instantiations. Without them,
// `cudaFuncGetAttributes` on a cooperative kernel fails with "invalid resource
// handle".
template __global__ void d_scale<fr_t>(fr_t*, const fr_t*, fr_t, size_t);
template __global__ void d_axpy<fr_t>(fr_t*, const fr_t*, fr_t, size_t);
template __global__ void d_sub_ext<fr_t>(fr_t*, const fr_t*, size_t, const fr_t*, size_t);
template __global__ void d_vanishing_scaled<fr_t>(fr_t*, unsigned*, const fr_t*, size_t, size_t, size_t, fr_t);
template __global__ void d_total<fr_t>(fr_t*, const fr_t*, size_t, fr_t);
template __global__ void d_combine<fr_t>(fr_t*, const fr_t*, const fr_t*, const fr_t*, const fr_t*, const fr_t*, size_t);
template __global__ void d_cross<fr_t>(fr_t*, fr_t*, fr_t*, fr_t*, const fr_t*, const fr_t*, fr_t, fr_t, fr_t, size_t);
// `prefix_op` picks its chunk at run time, so every arm it can take needs an
// instantiation. The list is complete only for CHUNK == 4; a missing arm fails
// at run time with "invalid resource handle", so the assert makes it a compile
// error.
static_assert(Multiply<fr_t>::CHUNK == 4,
              "d_prefix_op is instantiated for CHUNK/4, CHUNK/2, CHUNK*3/4 and "
              "CHUNK assuming CHUNK == 4; a different field width needs a "
              "different set");
template __global__ void d_prefix_op<Multiply<fr_t>, 1, fr_t, fr_t*, const fr_t*>(fr_t*, const fr_t*, size_t);
template __global__ void d_prefix_op<Multiply<fr_t>, 2, fr_t, fr_t*, const fr_t*>(fr_t*, const fr_t*, size_t);
template __global__ void d_prefix_op<Multiply<fr_t>, 3, fr_t, fr_t*, const fr_t*>(fr_t*, const fr_t*, size_t);
template __global__ void d_prefix_op<Multiply<fr_t>, 4, fr_t, fr_t*, const fr_t*>(fr_t*, const fr_t*, size_t);

#ifndef __CUDA_ARCH__

// Runs the fourth round's K-sized chain on device buffers the caller owns, with
// no transfers or allocation. Defined here so the kernels stay in this
// translation unit; only this host function crosses, so no device linking is
// involved.
void fourth_round_evals_device(const stream_t& stream, int sm_count,
                               fr_t* d_a, fr_t* d_b, fr_t* d_f,
                               const fr_t* d_row, const fr_t* d_col,
                               const fr_t* d_rcv,
                               fr_t* d_scan, fr_t* d_scan_rev, fr_t* d_t,
                               fr_t alpha, fr_t beta, fr_t coeff,
                               fr_t b_scale, fr_t a_scale, size_t len)
{
    int block = 256;
    int grid = (int)std::min((len + block - 1) / block, (size_t)sm_count * 8);

    d_cross<<<grid, block, 0, stream>>>(d_f, d_b, d_scan, d_scan_rev,
                                        d_row, d_col, alpha, beta, b_scale, len);
    CUDA_OK(cudaGetLastError());

    // a_evals is independent of the inversion chain, so it is issued here and
    // overlaps the two scans below rather than waiting for them.
    d_scale<<<grid, block, 0, stream>>>(d_a, d_rcv, a_scale, len);
    CUDA_OK(cudaGetLastError());

    prefix_op<Multiply<fr_t>>(d_scan, len, stream);
    prefix_op<Multiply<fr_t>>(d_scan_rev, len, stream);

    // A full warp: reciprocal() pairs lanes with shfl_xor.
    d_total<<<1, WARP_SZ, 0, stream>>>(d_t, d_scan, len, coeff);
    CUDA_OK(cudaGetLastError());

    d_combine<<<grid, block, 0, stream>>>(d_f, d_f, d_scan, d_scan_rev, d_t, d_rcv, len);
    CUDA_OK(cudaGetLastError());
}

// Launcher for d_axpy, kept in this translation unit for the reason at the top
// of this file.
void accumulate_axpy_device(const stream_t& stream, int sm_count,
                            fr_t* d_acc, const fr_t* d_src, fr_t coeff, size_t len)
{
    int block = 256;
    int grid = (int)std::min((len + block - 1) / block, (size_t)sm_count * 8);
    d_axpy<<<grid, block, 0, stream>>>(d_acc, d_src, coeff, len);
    CUDA_OK(cudaGetLastError());
}

// Launcher for d_widen, kept here for the reason accumulate_axpy_device is.
void widen_points_device(const stream_t& stream, int sm_count, uint64_t* d_dst,
                         const uint64_t* d_src, size_t npoints,
                         size_t src_words, size_t dst_words)
{
    size_t total = npoints * dst_words;
    int block = 256;
    int grid = (int)std::min((total + block - 1) / block, (size_t)sm_count * 8);
    d_widen<<<grid, block, 0, stream>>>(d_dst, d_src, npoints, src_words, dst_words);
    CUDA_OK(cudaGetLastError());
}


// Launchers for the round-4 chain's tail, kept in this translation unit so the
// kernels stay out of the one holding the NTT and MSM kernels.
void round4_sub_device(const stream_t& stream, int sm_count, fr_t* d_out,
                       const fr_t* d_a, size_t a_len, const fr_t* d_b, size_t len)
{
    int block = 256;
    int grid = (int)std::min((len + block - 1) / block, (size_t)sm_count * 8);
    d_sub_ext<<<grid, block, 0, stream>>>(d_out, d_a, a_len, d_b, len);
    CUDA_OK(cudaGetLastError());
}

void round4_vanishing_device(const stream_t& stream, int sm_count,
                             fr_t* d_q, unsigned* d_nonzero, const fr_t* d_p,
                             size_t n, size_t q_len, size_t total, fr_t mult)
{
    int block = 256;
    int grid = (int)std::min((total + block - 1) / block, (size_t)sm_count * 8);
    d_vanishing_scaled<<<grid, block, 0, stream>>>(d_q, d_nonzero, d_p, n, q_len,
                                                   total, mult);
    CUDA_OK(cudaGetLastError());
}

#endif
