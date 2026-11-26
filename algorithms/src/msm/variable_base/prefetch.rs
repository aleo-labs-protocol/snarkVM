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

#[macro_export]
macro_rules! prefetch_slice {
    ($curve: ident, $slice_1: ident, $slice_2: ident, $prefetch_iter: ident) => {
        if let Some((idp_1, idp_2)) = $prefetch_iter.next() {
            $crate::msm::variable_base::prefetch::prefetch::<$curve>(&$slice_1[*idp_1 as usize]);
            $crate::msm::variable_base::prefetch::prefetch::<$curve>(&$slice_2[*idp_2 as usize]);
        }
    };

    ($curve: ident, $slice_1: ident, $prefetch_iter: ident) => {
        if let Some((idp_1, _)) = $prefetch_iter.next() {
            $crate::msm::variable_base::prefetch::prefetch::<$curve>(&$slice_1[*idp_1 as usize]);
        }
    };
}

/// Prefetches up to two `bases` entries for `batched::batch_add_write`,
/// masking out bit 31 (`SIGN_BIT`) and skipping `NOOP` (`u32::MAX`) on the
/// second slot.
#[macro_export]
macro_rules! prefetch_slice_write {
    ($curve: ident, $slice_1: ident, $slice_2: ident, $prefetch_iter: ident) => {
        if let Some((idp_1, idp_2)) = $prefetch_iter.next() {
            const SIGN_INDEX_MASK: u32 = !(1u32 << 31);
            $crate::msm::variable_base::prefetch::prefetch::<$curve>(&$slice_1[(*idp_1 & SIGN_INDEX_MASK) as usize]);
            if *idp_2 != u32::MAX {
                $crate::msm::variable_base::prefetch::prefetch::<$curve>(
                    &$slice_2[(*idp_2 & SIGN_INDEX_MASK) as usize],
                );
            }
        }
    };
}

const fn n_lines<T>() -> isize {
    ((std::mem::size_of::<T>() - 1) / 64 + 1) as isize
}

#[macro_export]
macro_rules! unroll {
    (0, |$i:ident| $s:stmt) => {};
    (1, |$i:ident| $s:stmt) => {{
        let $i: isize = 0;
        $s
    }};
    (2, |$i:ident| $s:stmt) => {{
        unroll!(1, |$i| $s);
        let $i: isize = 1;
        $s
    }};
    (3, |$i:ident| $s:stmt) => {{
        unroll!(2, |$i| $s);
        let $i: isize = 2;
        $s
    }};
    (4, |$i:ident| $s:stmt) => {{
        unroll!(3, |$i| $s);
        let $i: isize = 3;
        $s
    }};
    (5, |$i:ident| $s:stmt) => {{
        unroll!(4, |$i| $s);
        let $i: isize = 4;
        $s
    }};
    (6, |$i:ident| $s:stmt) => {{
        unroll!(5, |$i| $s);
        let $i: isize = 5;
        $s
    }};
    (7, |$i:ident| $s:stmt) => {{
        unroll!(6, |$i| $s);
        let $i: isize = 6;
        $s
    }};
    (8, |$i:ident| $s:stmt) => {{
        unroll!(7, |$i| $s);
        let $i: isize = 7;
        $s
    }};
    (9, |$i:ident| $s:stmt) => {{
        unroll!(8, |$i| $s);
        let $i: isize = 8;
        $s
    }};
    (10, |$i:ident| $s:stmt) => {{
        unroll!(9, |$i| $s);
        let $i: isize = 9;
        $s
    }};
    (11, |$i:ident| $s:stmt) => {{
        unroll!(10, |$i| $s);
        let $i: isize = 10;
        $s
    }};
    (12, |$i:ident| $s:stmt) => {{
        unroll!(11, |$i| $s);
        let $i: isize = 11;
        $s
    }};
    (13, |$i:ident| $s:stmt) => {{
        unroll!(12, |$i| $s);
        let $i: isize = 12;
        $s
    }};
    (14, |$i:ident| $s:stmt) => {{
        unroll!(13, |$i| $s);
        let $i: isize = 13;
        $s
    }};
    (15, |$i:ident| $s:stmt) => {{
        unroll!(14, |$i| $s);
        let $i: isize = 14;
        $s
    }};
    (16, |$i:ident| $s:stmt) => {{
        unroll!(15, |$i| $s);
        let $i: isize = 15;
        $s
    }};
}

/// Prefetches as many cache lines as is occupied by the type T.
/// We assume 64B cache lines.
#[allow(unsafe_code)]
#[inline(always)]
pub fn prefetch<T>(p: *const T) {
    unsafe {
        match n_lines::<T>() {
            1 => unroll!(1, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            2 => unroll!(2, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            3 => unroll!(3, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            4 => unroll!(4, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            5 => unroll!(5, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            6 => unroll!(6, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            7 => unroll!(7, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            8 => unroll!(8, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            9 => unroll!(9, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            10 => unroll!(10, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            11 => unroll!(11, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            12 => unroll!(12, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            13 => unroll!(13, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            14 => unroll!(14, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            15 => unroll!(15, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
            _ => unroll!(16, |i| core::arch::x86_64::_mm_prefetch(
                (p as *const i8).offset(i * 64),
                core::arch::x86_64::_MM_HINT_T0
            )),
        }
    }
}
