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

//! Montgomery products over four limbs.
//!
//! `q` holds the limbs of the modulus `p`, least significant first, and then `-p^-1 mod 2^64`.
//! The operands are below `p`, and the top limb of `p` is below `2^63 - 1`.
//!
//! Each round of a reduction sets the carry of `t0 + lo(m q0)` without computing `lo(m q0)`: the
//! sum is `0 mod 2^64`, so it carries exactly when `t0` is nonzero, and `adcx` of `t0` into
//! `2^64 - 1` sets the same carry.

use core::arch::asm;

/// Adds `rdx b` to `t` in `r11` to `r14`, with `lo` on the `adox` chain and `hi` on the `adcx`
/// chain, and leaves the top limb in `rcx`.
macro_rules! row {
    () => {
        concat!(
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [rsi]\n",
            "adox r11, rax\n",
            "adcx r12, rcx\n",
            "mulx rcx, rax, qword ptr [rsi + 8]\n",
            "adox r12, rax\n",
            "adcx r13, rcx\n",
            "mulx rcx, rax, qword ptr [rsi + 16]\n",
            "adox r13, rax\n",
            "adcx r14, rcx\n",
            "mulx rcx, rax, qword ptr [rsi + 24]\n",
            "adox r14, rax\n",
            "mov eax, 0\n",
            "adcx rcx, rax\n",
            "adox rcx, rax\n",
        )
    };
}

/// Sets `t` in `r11` to `r14`, with the top limb in the register `$top`, to `(t + m q) / 2^64`
/// for `m = t0 q[4] mod 2^64`. `$top` is `rcx`, or `rax` for a top limb of zero.
macro_rules! reduce {
    ($top:literal) => {
        concat!(
            "mov rdx, r11\n",
            "imul rdx, qword ptr [rdi + 32]\n",
            "or rax, -1\n",
            "adcx rax, r11\n",
            "mulx r11, rax, qword ptr [rdi]\n",
            "adcx r11, r12\n",
            "mulx r12, rax, qword ptr [rdi + 8]\n",
            "adox r11, rax\n",
            "adcx r12, r13\n",
            "mulx r13, rax, qword ptr [rdi + 16]\n",
            "adox r12, rax\n",
            "adcx r13, r14\n",
            "mulx r14, rax, qword ptr [rdi + 24]\n",
            "adox r13, rax\n",
            "mov eax, 0\n",
            "adcx r14, rax\n",
            "adox r14, ",
            $top,
            "\n",
        )
    };
}

/// Returns an integer in `[0, 2p)` congruent to `a b 2^-256 mod p`.
///
/// The limbs of `a` stay in registers and enter `mulx` through `rdx`; `b` and `q` are memory
/// operands.
#[inline(always)]
pub(crate) fn mul(a: &[u64; 4], b: &[u64; 4], q: &[u64; 5]) -> [u64; 4] {
    let (t0, t1, t2, t3): (u64, u64, u64, u64);
    // SAFETY: The module compiles only with `target_feature = "adx"` and `"bmi2"`, so `mulx`,
    // `adcx` and `adox` exist. `b` and `q` are references to 4 and 5 limbs, and the assembly reads
    // only `[rsi]` to `[rsi + 24]` and `[rdi]` to `[rdi + 32]`. It writes no memory and no stack.
    unsafe {
        asm!(
            // t = a0 b, with the top limb in rcx.
            "mulx r12, r11, qword ptr [rsi]",
            "mulx r13, rax, qword ptr [rsi + 8]",
            "add r12, rax",
            "mulx r14, rax, qword ptr [rsi + 16]",
            "adc r13, rax",
            "mulx rcx, rax, qword ptr [rsi + 24]",
            "adc r14, rax",
            "adc rcx, 0",
            reduce!("rcx"),
            // t += a1 b, then reduce.
            "mov rdx, r8",
            row!(),
            reduce!("rcx"),
            // t += a2 b, then reduce.
            "mov rdx, r9",
            row!(),
            reduce!("rcx"),
            // t += a3 b, then reduce.
            "mov rdx, r10",
            row!(),
            reduce!("rcx"),
            inout("rdx") a[0] => _,
            in("r8") a[1],
            in("r9") a[2],
            in("r10") a[3],
            in("rsi") b.as_ptr(),
            in("rdi") q.as_ptr(),
            out("rax") _,
            out("rcx") _,
            out("r11") t0,
            out("r12") t1,
            out("r13") t2,
            out("r14") t3,
            options(pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3]
}

/// Returns an integer in `[0, 2p)` congruent to `a^2 2^-256 mod p`.
///
/// The product `r` takes 6 `mulx` off the diagonal and 4 on it: `adcx` doubles the off-diagonal
/// sum while `adox` adds the squares. The reduction runs on `r0` to `r3` alone, and its result,
/// at most `p`, takes `r4` to `r7` at the end. The limbs of `a` stay in registers; `q` is a memory
/// operand.
#[inline(always)]
pub(crate) fn square(a: &[u64; 4], q: &[u64; 5]) -> [u64; 4] {
    let (t0, t1, t2, t3): (u64, u64, u64, u64);
    // SAFETY: The module compiles only with `target_feature = "adx"` and `"bmi2"`, so `mulx`,
    // `adcx` and `adox` exist. `q` is a reference to 5 limbs, and the assembly reads only `[rdi]`
    // to `[rdi + 32]`. It writes no memory and no stack.
    unsafe {
        asm!(
            // r1 to r6 in r12 to r15, rsi and rcx: the products off the diagonal.
            "mov rdx, r8",
            "mulx r13, r12, r9",
            "mulx r14, rax, r10",
            "add r13, rax",
            "mulx r15, rax, r11",
            "adc r14, rax",
            "adc r15, 0",
            "mov rdx, r9",
            "mulx rsi, rax, r10",
            "add r14, rax",
            "adc r15, rsi",
            "mulx rsi, rax, r11",
            "adc rsi, 0",
            "add r15, rax",
            "adc rsi, 0",
            "mov rdx, r10",
            "mulx rcx, rax, r11",
            "add rsi, rax",
            "adc rcx, 0",
            // r = 2 r + the squares, with r0 in rax, then r11, and r7 in r10.
            "mov rdx, r8",
            "xor r8d, r8d",
            "mulx r8, rax, rdx",
            "adcx r12, r12",
            "adox r12, r8",
            "mov rdx, r9",
            "mulx r9, r8, rdx",
            "adcx r13, r13",
            "adox r13, r8",
            "adcx r14, r14",
            "adox r14, r9",
            "mov rdx, r10",
            "mulx r10, r8, rdx",
            "adcx r15, r15",
            "adox r15, r8",
            "adcx rsi, rsi",
            "adox rsi, r10",
            "mov rdx, r11",
            "mov r11, rax",
            "mulx r10, r8, rdx",
            "adcx rcx, rcx",
            "adox rcx, r8",
            "mov r8d, 0",
            "adcx r10, r8",
            "adox r10, r8",
            // (r0 + r1 2^64 + r2 2^128 + r3 2^192 + m q) / 2^256, at most p.
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            reduce!("rax"),
            // + r4 to r7.
            "add r11, r15",
            "adc r12, rsi",
            "adc r13, rcx",
            "adc r14, r10",
            inout("r8") a[0] => _,
            inout("r9") a[1] => _,
            inout("r10") a[2] => _,
            inout("r11") a[3] => t0,
            in("rdi") q.as_ptr(),
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("r12") t1,
            out("r13") t2,
            out("r14") t3,
            out("r15") _,
            options(pure, readonly, nostack),
        );
    }
    [t0, t1, t2, t3]
}
