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

//! The Montgomery product, the square, and the sums of two and of three products, over 6 limbs.
//!
//! In the macros the accumulator `t` lives in `r8`–`r13` and its seventh limb in `r15`; `rax` and
//! `r14` are scratch. `rsi`, `rdi` and `rcx` point to `a`, `b` and the modulus table.

use core::arch::asm;

use crate::{Fp384, Fp384Parameters};

/// Returns the limbs of `N` field elements, in place.
#[inline(always)]
pub(crate) fn limbs<P: Fp384Parameters, const N: usize>(elements: &[Fp384<P>; N]) -> &[[u64; 6]; N] {
    const {
        assert!(size_of::<Fp384<P>>() == size_of::<[u64; 6]>());
        assert!(align_of::<Fp384<P>>() == align_of::<[u64; 6]>());
    };
    // SAFETY: `Fp384` and its `BigInteger384` are `repr(transparent)` over `[u64; 6]`, so the two
    // array types have the same layout.
    unsafe { &*(elements as *const [Fp384<P>; N]).cast() }
}

/// Sets the accumulator to `a b_0`, with `b_0` at `[rdi]`. CF carries the column sums.
macro_rules! first_round {
    () => {
        concat!(
            "mov rdx, qword ptr [rdi]\n",
            "xor eax, eax\n",
            "mulx r9, r8, qword ptr [rsi]\n",
            "mulx r10, rax, qword ptr [rsi + 8]\n",
            "adcx r9, rax\n",
            "mulx r11, rax, qword ptr [rsi + 16]\n",
            "adcx r10, rax\n",
            "mulx r12, rax, qword ptr [rsi + 24]\n",
            "adcx r11, rax\n",
            "mulx r13, rax, qword ptr [rsi + 32]\n",
            "adcx r12, rax\n",
            "mulx r15, rax, qword ptr [rsi + 40]\n",
            "adcx r13, rax\n",
            "mov eax, 0\n",
            "adcx r15, rax\n",
        )
    };
}

/// Adds `a b_i` into the accumulator, with `b_i` at byte offset `$offset` of `b`. OF carries the
/// low halves into their column, and CF the high halves into the next one.
macro_rules! round {
    ($offset:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $offset,
            "]\n",
            "xor eax, eax\n",
            "mulx r14, rax, qword ptr [rsi]\n",
            "adox r8, rax\n",
            "adcx r9, r14\n",
            "mulx r14, rax, qword ptr [rsi + 8]\n",
            "adox r9, rax\n",
            "adcx r10, r14\n",
            "mulx r14, rax, qword ptr [rsi + 16]\n",
            "adox r10, rax\n",
            "adcx r11, r14\n",
            "mulx r14, rax, qword ptr [rsi + 24]\n",
            "adox r11, rax\n",
            "adcx r12, r14\n",
            "mulx r14, rax, qword ptr [rsi + 32]\n",
            "adox r12, rax\n",
            "adcx r13, r14\n",
            "mulx r15, rax, qword ptr [rsi + 40]\n",
            "adox r13, rax\n",
            "mov eax, 0\n",
            "adcx r15, rax\n",
            "adox r15, rax\n",
        )
    };
}

/// Adds `a_k b_i` into the accumulator, with `a_k` at byte offset `$a` of `rsi` and `b_i` at byte
/// offset `$b` of `rdi`. As `round!`, except that it adds into the seventh limb in `r15`.
macro_rules! accumulate {
    ($a:literal, $b:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $b,
            "]\n",
            "xor eax, eax\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            "]\n",
            "adox r8, rax\n",
            "adcx r9, r14\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            " + 8]\n",
            "adox r9, rax\n",
            "adcx r10, r14\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            " + 16]\n",
            "adox r10, rax\n",
            "adcx r11, r14\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            " + 24]\n",
            "adox r11, rax\n",
            "adcx r12, r14\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            " + 32]\n",
            "adox r12, rax\n",
            "adcx r13, r14\n",
            "mulx r14, rax, qword ptr [rsi + ",
            $a,
            " + 40]\n",
            "adox r13, rax\n",
            "adcx r15, r14\n",
            "mov eax, 0\n",
            "adox r15, rax\n",
        )
    };
}

/// Sets the accumulator to `(t + m p) / 2^64` with `m = t_0 (-p^-1) mod 2^64`, where the register
/// `$top` holds the seventh limb of `t`: `r15`, or `rax` for a seventh limb of zero. CF carries the
/// accumulator and the high halves of `m p`, and OF its low halves. `imul` clobbers both flags, so
/// the `or` clears them after it. Its `-1` plus `t_0` carries exactly when `t_0 + (m p)_0` does.
macro_rules! reduce {
    ($top:literal) => {
        concat!(
            "mov rdx, r8\n",
            "imul rdx, qword ptr [rcx + 48]\n",
            "or rax, -1\n",
            "adcx rax, r8\n",
            "mulx r8, rax, qword ptr [rcx]\n",
            "adcx r8, r9\n",
            "mulx r9, rax, qword ptr [rcx + 8]\n",
            "adox r8, rax\n",
            "adcx r9, r10\n",
            "mulx r10, rax, qword ptr [rcx + 16]\n",
            "adox r9, rax\n",
            "adcx r10, r11\n",
            "mulx r11, rax, qword ptr [rcx + 24]\n",
            "adox r10, rax\n",
            "adcx r11, r12\n",
            "mulx r12, rax, qword ptr [rcx + 32]\n",
            "adox r11, rax\n",
            "adcx r12, r13\n",
            "mulx r13, rax, qword ptr [rcx + 40]\n",
            "adox r12, rax\n",
            "mov eax, 0\n",
            "adcx r13, rax\n",
            "adox r13, ",
            $top,
            "\n",
        )
    };
}

/// Returns `a b 2^-384 mod p` in `[0, 2p)`, for `a` and `b` below `p`.
///
/// `modulus` holds the 6 limbs of `p`, then `-p^-1 mod 2^64`.
#[inline(always)]
pub(crate) fn mul(a: &[u64; 6], b: &[u64; 6], modulus: &[u64; 7]) -> [u64; 6] {
    let (t0, t1, t2, t3, t4, t5): (u64, u64, u64, u64, u64, u64);
    // SAFETY: the crate compiles this module only when the target enables `adx` and `bmi2`, which
    // `adcx`, `adox` and `mulx` need. The asm reads 6 limbs through `a` and `b` and 7 through
    // `modulus`, as their types guarantee, and writes no memory.
    unsafe {
        asm!(
            first_round!(),
            reduce!("r15"),
            round!("8"),
            reduce!("r15"),
            round!("16"),
            reduce!("r15"),
            round!("24"),
            reduce!("r15"),
            round!("32"),
            reduce!("r15"),
            round!("40"),
            reduce!("r15"),
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            in("rcx") modulus.as_ptr(),
            out("r8") t0,
            out("r9") t1,
            out("r10") t2,
            out("r11") t3,
            out("r12") t4,
            out("r13") t5,
            out("rax") _,
            out("rdx") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3, t4, t5]
}

/// Returns `a^2 2^-384 mod p` in `[0, 2p)`, for `a` below `p`.
///
/// The square `r = a^2` takes 12 limbs: `r_0` to `r_5` end in `r8` to `r13` and `r_6` to `r_11`
/// in `buf`. The reduction runs on `r_0` to `r_5` alone, which leaves at most `p`, and then adds
/// `r_6` to `r_11`, which are below `p`. `modulus` is as in [`mul`].
#[inline(always)]
pub(crate) fn square(a: &[u64; 6], modulus: &[u64; 7]) -> [u64; 6] {
    let (t0, t1, t2, t3, t4, t5): (u64, u64, u64, u64, u64, u64);
    let mut buf = core::mem::MaybeUninit::<[u64; 12]>::uninit();
    // SAFETY: the crate compiles this module only when the target enables `adx` and `bmi2`, which
    // `adcx`, `adox` and `mulx` need. The asm reads 6 limbs through `a` and 7 through `modulus`, as
    // their types guarantee, and reads and writes only limbs 1 to 11 of `buf`, which it writes
    // before it reads them.
    unsafe {
        asm!(
            // The products off the diagonal, `t = sum a_i a_j 2^(64 (i + j))` for `i < j`, row by
            // row. Each row leaves its two lowest limbs complete and stores them in `buf`.
            "mov rdx, qword ptr [rsi]",
            "mulx r9, r8, qword ptr [rsi + 8]",
            "mulx r10, rax, qword ptr [rsi + 16]",
            "add r9, rax",
            "mulx r11, rax, qword ptr [rsi + 24]",
            "adc r10, rax",
            "mulx r12, rax, qword ptr [rsi + 32]",
            "adc r11, rax",
            "mulx r13, rax, qword ptr [rsi + 40]",
            "adc r12, rax",
            "adc r13, 0",
            "mov qword ptr [rdi + 8], r8",
            "mov qword ptr [rdi + 16], r9",
            "mov rdx, qword ptr [rsi + 8]",
            "xor eax, eax",
            "mulx r9, rax, qword ptr [rsi + 16]",
            "adox r10, rax",
            "adcx r11, r9",
            "mulx r9, rax, qword ptr [rsi + 24]",
            "adox r11, rax",
            "adcx r12, r9",
            "mulx r9, rax, qword ptr [rsi + 32]",
            "adox r12, rax",
            "adcx r13, r9",
            "mulx r14, rax, qword ptr [rsi + 40]",
            "adox r13, rax",
            "mov eax, 0",
            "adcx r14, rax",
            "adox r14, rax",
            "mov qword ptr [rdi + 24], r10",
            "mov qword ptr [rdi + 32], r11",
            "mov rdx, qword ptr [rsi + 16]",
            "xor eax, eax",
            "mulx r9, rax, qword ptr [rsi + 24]",
            "adox r12, rax",
            "adcx r13, r9",
            "mulx r9, rax, qword ptr [rsi + 32]",
            "adox r13, rax",
            "adcx r14, r9",
            "mulx r15, rax, qword ptr [rsi + 40]",
            "adox r14, rax",
            "mov eax, 0",
            "adcx r15, rax",
            "adox r15, rax",
            "mov qword ptr [rdi + 40], r12",
            "mov qword ptr [rdi + 48], r13",
            "mov rdx, qword ptr [rsi + 24]",
            "xor eax, eax",
            "mulx r9, rax, qword ptr [rsi + 32]",
            "adox r14, rax",
            "adcx r15, r9",
            "mulx r8, rax, qword ptr [rsi + 40]",
            "adox r15, rax",
            "mov eax, 0",
            "adcx r8, rax",
            "adox r8, rax",
            "mov qword ptr [rdi + 56], r14",
            "mov qword ptr [rdi + 64], r15",
            "mov rdx, qword ptr [rsi + 32]",
            "mulx r9, rax, qword ptr [rsi + 40]",
            "add r8, rax",
            "adc r9, 0",
            "mov qword ptr [rdi + 72], r8",
            "mov qword ptr [rdi + 80], r9",
            // `r = 2 t + sum a_i^2 2^(128 i)`. CF carries the doubling and OF the squares.
            "mov rdx, qword ptr [rsi]",
            "xor eax, eax",
            "mulx r15, r8, rdx",
            "mov r9, qword ptr [rdi + 8]",
            "adcx r9, r9",
            "adox r9, r15",
            "mov rdx, qword ptr [rsi + 8]",
            "mulx r15, rax, rdx",
            "mov r10, qword ptr [rdi + 16]",
            "adcx r10, r10",
            "adox r10, rax",
            "mov r11, qword ptr [rdi + 24]",
            "adcx r11, r11",
            "adox r11, r15",
            "mov rdx, qword ptr [rsi + 16]",
            "mulx r15, rax, rdx",
            "mov r12, qword ptr [rdi + 32]",
            "adcx r12, r12",
            "adox r12, rax",
            "mov r13, qword ptr [rdi + 40]",
            "adcx r13, r13",
            "adox r13, r15",
            "mov rdx, qword ptr [rsi + 24]",
            "mulx r15, rax, rdx",
            "mov r14, qword ptr [rdi + 48]",
            "adcx r14, r14",
            "adox r14, rax",
            "mov qword ptr [rdi + 48], r14",
            "mov r14, qword ptr [rdi + 56]",
            "adcx r14, r14",
            "adox r14, r15",
            "mov qword ptr [rdi + 56], r14",
            "mov rdx, qword ptr [rsi + 32]",
            "mulx r15, rax, rdx",
            "mov r14, qword ptr [rdi + 64]",
            "adcx r14, r14",
            "adox r14, rax",
            "mov qword ptr [rdi + 64], r14",
            "mov r14, qword ptr [rdi + 72]",
            "adcx r14, r14",
            "adox r14, r15",
            "mov qword ptr [rdi + 72], r14",
            "mov rdx, qword ptr [rsi + 40]",
            "mulx r15, rax, rdx",
            "mov r14, qword ptr [rdi + 80]",
            "adcx r14, r14",
            "adox r14, rax",
            "mov qword ptr [rdi + 80], r14",
            "mov eax, 0",
            "adcx r15, rax",
            "adox r15, rax",
            "mov qword ptr [rdi + 88], r15",
            // `(r_0 + ... + r_5 2^320 + m p) / 2^384`, then `+ r_6 + ... + r_11 2^320`.
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            "add r8, qword ptr [rdi + 48]",
            "adc r9, qword ptr [rdi + 56]",
            "adc r10, qword ptr [rdi + 64]",
            "adc r11, qword ptr [rdi + 72]",
            "adc r12, qword ptr [rdi + 80]",
            "adc r13, qword ptr [rdi + 88]",
            in("rsi") a.as_ptr(),
            in("rdi") buf.as_mut_ptr(),
            in("rcx") modulus.as_ptr(),
            out("r8") t0,
            out("r9") t1,
            out("r10") t2,
            out("r11") t3,
            out("r12") t4,
            out("r13") t5,
            out("rax") _,
            out("rdx") _,
            out("r14") _,
            out("r15") _,
            options(nostack),
        );
    }
    [t0, t1, t2, t3, t4, t5]
}

/// Returns `(a_0 b_0 + a_1 b_1) 2^-384 mod p` in `[0, 2p)`, for `a_0`, `a_1`, `b_0` and `b_1` below
/// `p`, where `p < 2^384 / 3`.
///
/// Step `j` adds `a_0 b_{0,j} + a_1 b_{1,j} + m p` to the accumulator `u`, with `m < 2^64`, and
/// divides by `2^64`. If `u < 3p`, the sum is below `3p + 3 (2^64 - 1) p = 2^64 3p`, so 7 limbs
/// hold it, and `u < 3p` again after the division, so 6 limbs hold `u`. The result is
/// `(a_0 b_0 + a_1 b_1 + M p) / 2^384` for some `M < 2^384`, which is below `2p` as `2p < 2^384`.
/// `modulus` is as in [`mul`].
#[inline(always)]
pub(crate) fn sum_of_products_2(a: &[[u64; 6]; 2], b: &[[u64; 6]; 2], modulus: &[u64; 7]) -> [u64; 6] {
    let (t0, t1, t2, t3, t4, t5): (u64, u64, u64, u64, u64, u64);
    // SAFETY: the crate compiles this module only when the target enables `adx` and `bmi2`, which
    // `adcx`, `adox` and `mulx` need. The asm reads 12 limbs through `a` and `b` and 7 through
    // `modulus`, as their types guarantee, and writes no memory.
    unsafe {
        asm!(
            first_round!(),
            accumulate!("48", "48"),
            reduce!("r15"),
            round!("8"),
            accumulate!("48", "56"),
            reduce!("r15"),
            round!("16"),
            accumulate!("48", "64"),
            reduce!("r15"),
            round!("24"),
            accumulate!("48", "72"),
            reduce!("r15"),
            round!("32"),
            accumulate!("48", "80"),
            reduce!("r15"),
            round!("40"),
            accumulate!("48", "88"),
            reduce!("r15"),
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            in("rcx") modulus.as_ptr(),
            out("r8") t0,
            out("r9") t1,
            out("r10") t2,
            out("r11") t3,
            out("r12") t4,
            out("r13") t5,
            out("rax") _,
            out("rdx") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3, t4, t5]
}

/// Returns `(a_0 b_0 + a_1 b_1 + a_2 b_2) 2^-384 mod p` in `[0, 2p)`, for `a_i` and `b_i` below `p`,
/// where `p < 2^384 / 4`.
///
/// The accumulator stays below `4p`, as it stays below `3p` in [`sum_of_products_2`]. The result is
/// `(a_0 b_0 + a_1 b_1 + a_2 b_2 + M p) / 2^384` for some `M < 2^384`, which is below `2p` as
/// `3p < 2^384`. `modulus` is as in [`mul`].
#[inline(always)]
pub(crate) fn sum_of_products_3(a: &[[u64; 6]; 3], b: &[[u64; 6]; 3], modulus: &[u64; 7]) -> [u64; 6] {
    let (t0, t1, t2, t3, t4, t5): (u64, u64, u64, u64, u64, u64);
    // SAFETY: the crate compiles this module only when the target enables `adx` and `bmi2`, which
    // `adcx`, `adox` and `mulx` need. The asm reads 18 limbs through `a` and `b` and 7 through
    // `modulus`, as their types guarantee, and writes no memory.
    unsafe {
        asm!(
            first_round!(),
            accumulate!("48", "48"),
            accumulate!("96", "96"),
            reduce!("r15"),
            round!("8"),
            accumulate!("48", "56"),
            accumulate!("96", "104"),
            reduce!("r15"),
            round!("16"),
            accumulate!("48", "64"),
            accumulate!("96", "112"),
            reduce!("r15"),
            round!("24"),
            accumulate!("48", "72"),
            accumulate!("96", "120"),
            reduce!("r15"),
            round!("32"),
            accumulate!("48", "80"),
            accumulate!("96", "128"),
            reduce!("r15"),
            round!("40"),
            accumulate!("48", "88"),
            accumulate!("96", "136"),
            reduce!("r15"),
            in("rsi") a.as_ptr(),
            in("rdi") b.as_ptr(),
            in("rcx") modulus.as_ptr(),
            out("r8") t0,
            out("r9") t1,
            out("r10") t2,
            out("r11") t3,
            out("r12") t4,
            out("r13") t5,
            out("rax") _,
            out("rdx") _,
            out("r14") _,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3, t4, t5]
}
