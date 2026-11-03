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

#![warn(unsafe_code)]
#![allow(clippy::module_inception)]
#![allow(clippy::type_complexity)]
#![cfg_attr(test, allow(clippy::assertions_on_result_states))]

#[allow(unused_imports)]
#[macro_use]
extern crate aleo_std;
#[macro_use]
extern crate thiserror;

pub use snarkvm_utilities::{cfg_chunks, cfg_chunks_mut, cfg_into_iter, cfg_iter, cfg_iter_mut, cfg_reduce};

pub mod crypto_hash;
pub mod fft;
pub mod msm;
pub mod polycommit;
pub mod r1cs;
pub mod snark;

pub mod srs;

pub mod errors;
pub use errors::*;

/// Whether this crate's `cuda` feature is enabled.
///
/// A consumer's own `cfg!(feature = "cuda")` does not answer this, because
/// features are selected per crate. This is a build fact, not a reachability
/// fact: every GPU dispatch site also requires `target_arch = "x86_64"`, so on
/// any other target this reads `true` while nothing dispatches to the GPU.
pub const CUDA_ENABLED: bool = cfg!(feature = "cuda");

// Without nvcc, a `cuda` build would otherwise fail at link time, on undefined
// kernel symbols. Clippy does not link, so it runs without nvcc.
#[cfg(all(feature = "cuda", not(clippy)))]
const _: () = assert!(
    snarkvm_algorithms_cuda::HAVE_NVCC,
    "the `cuda` feature needs nvcc, which the build did not find. Put nvcc on PATH or set NVCC to its path, \
     or build without `cuda`."
);

/// Opens the token that carries the CUDA error code in a [`cuda_must_succeed`]
/// panic message: this prefix, the code in decimal, then
/// [`CUDA_ERROR_CODE_SUFFIX`].
///
/// The token is the stable interface; the text around it is not. Parse the code
/// as a signed integer, or call [`cuda_error_code`]. The panic payload is a
/// `String`.
///
/// The codes a caller classifies on are disjoint. `cudaErrorNotSupported`
/// (801) comes only from the pool capacity checks in `snarkvm_t::NTT` and
/// `snarkvm_t::PolyMul`, and means the input is larger than the preallocated
/// pool. `cudaErrorNoDevice` (100) and `cudaErrorInitializationError` (3) come
/// only from startup, and mean the process has no working pool. Any other code
/// describes the call that failed.
pub const CUDA_ERROR_CODE_PREFIX: &str = "[snarkvm-cuda: code=";

/// `cudaErrorNotSupported` in the CUDA runtime's `cudaError` enum.
/// `snarkvm.cu` asserts this value against the CUDA header.
pub const CUDA_ERROR_NOT_SUPPORTED: i32 = 801;

/// Closes the token opened by [`CUDA_ERROR_CODE_PREFIX`].
pub const CUDA_ERROR_CODE_SUFFIX: &str = "]";

/// Reads the CUDA error code out of a [`cuda_must_succeed`] panic message.
///
/// Returns `None` if the message carries no well-formed token.
///
/// # The code is signed
///
/// sppark's `CUDA_OK` throws `cuda_error{-code}`, so a code raised by a driver
/// call arrives negated: `cudaErrorMemoryAllocation` is `-2`. A code returned
/// by a check in the CUDA layer arrives positive, including the pool capacity
/// checks, the startup codes, and argument and internal-fault errors. So
/// `abs()` gives the `cudaError_t`, and the sign separates "this input is too
/// big" (+801) from "this device could not allocate" (-801). A positive sign
/// alone does not mean one of the codes a caller classifies on.
pub fn cuda_error_code(message: &str) -> Option<i32> {
    let start = message.find(CUDA_ERROR_CODE_PREFIX)? + CUDA_ERROR_CODE_PREFIX.len();
    let rest = &message[start..];
    let end = rest.find(CUDA_ERROR_CODE_SUFFIX)?;
    rest[..end].parse().ok()
}

/// Returns the value of a successful CUDA call, and panics on any error.
///
/// A build with the `cuda` feature must not fall back to the CPU, because
/// nothing downstream reports which one ran. This includes
/// `cudaErrorNotSupported`: an input larger than the device pool is fixed by
/// rebuilding with a larger `MAX_LG_DOMAIN`.
///
/// Every arm carries the error code in a [`CUDA_ERROR_CODE_PREFIX`] token. The
/// payload must stay a `String`: std's default hook prints `Box<dyn Any>` for
/// any other payload type.
///
/// This is a macro because it reads `code` off the error, and sppark's error
/// type cannot be named here. The definition is not behind
/// `#[cfg(feature = "cuda")]`, so its tests run without a device.
#[macro_export]
macro_rules! cuda_must_succeed {
    ($result:expr, $op:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) if e.code == $crate::CUDA_ERROR_NOT_SUPPORTED => panic!(
                "CUDA {} failed {}{}{}: {}\nThe input exceeds the device pool; rebuild with a larger \
                 `MAX_LG_DOMAIN`.",
                $op,
                $crate::CUDA_ERROR_CODE_PREFIX,
                e.code,
                $crate::CUDA_ERROR_CODE_SUFFIX,
                String::from(&e)
            ),
            Err(e) => panic!(
                "CUDA {} failed {}{}{}: {}\nA cuda build does not fall back to the CPU; build without \
                 cuda to use it.",
                $op,
                $crate::CUDA_ERROR_CODE_PREFIX,
                e.code,
                $crate::CUDA_ERROR_CODE_SUFFIX,
                String::from(&e)
            ),
        }
    };
}

#[cfg(test)]
mod cuda_must_succeed_tests {
    // The macro reads only `.code` and `String::from(&e)`, so a stand-in tests
    // it without a device. `sppark::Error` cannot be constructed here.
    struct MockError {
        code: i32,
    }

    // `sppark::Error` implements `Drop`, which restricts moves out of it, so the
    // stand-in must too.
    impl Drop for MockError {
        fn drop(&mut self) {}
    }

    impl From<&MockError> for String {
        fn from(e: &MockError) -> Self {
            format!("mock failure #{}", e.code)
        }
    }

    /// Runs the macro's failing arm and returns the panic payload, which must
    /// be a `String`.
    fn panic_message(code: i32) -> String {
        // No `set_hook`: the hook is process-global, so replacing it would
        // swallow the panics of tests running in parallel.
        let payload = std::panic::catch_unwind(|| {
            let result: Result<(), MockError> = Err(MockError { code });
            crate::cuda_must_succeed!(result, "test op")
        })
        .expect_err("the macro must panic on Err");
        payload.downcast_ref::<String>().expect("the panic payload must be a String").clone()
    }

    #[test]
    fn ok_passes_the_value_through() {
        let result: Result<u32, MockError> = Ok(7);
        assert_eq!(crate::cuda_must_succeed!(result, "test op"), 7);
    }

    // The token is spelled out rather than built from the constants, so a
    // change to a constant fails these tests.
    #[test]
    fn the_pool_arm_carries_its_code() {
        let message = panic_message(801);
        assert!(message.contains("[snarkvm-cuda: code=801]"), "code token missing or reshaped: {message}");
        assert!(message.contains("mock failure #801"), "underlying message lost: {message}");
    }

    #[test]
    fn every_other_code_travels_too() {
        // cudaErrorMemoryAllocation.
        let message = panic_message(2);
        assert!(message.contains("[snarkvm-cuda: code=2]"), "code token missing or reshaped: {message}");
        assert!(message.contains("mock failure #2"), "underlying message lost: {message}");
    }

    /// 801 takes the pool arm, 100 and 3 are the startup codes, and 2 takes
    /// the generic arm.
    #[test]
    fn the_exported_parser_reads_every_arm() {
        for code in [801, 2, 100, 3] {
            assert_eq!(crate::cuda_error_code(&panic_message(code)), Some(code), "parse failed for code {code}");
        }
    }

    /// sppark negates every code it raises by throwing, so a driver fault
    /// carries a negative code.
    #[test]
    fn the_exported_parser_reads_negative_codes() {
        for code in [-2, -801] {
            assert_eq!(crate::cuda_error_code(&panic_message(code)), Some(code), "parse failed for code {code}");
        }
    }

    /// A panic from somewhere else must not parse as a CUDA failure.
    #[test]
    fn the_exported_parser_declines_a_message_without_a_token() {
        assert_eq!(crate::cuda_error_code("index out of bounds: the len is 3"), None);
        assert_eq!(crate::cuda_error_code("[snarkvm-cuda: code=not-a-number]"), None);
        assert_eq!(crate::cuda_error_code("[snarkvm-cuda: code=801"), None);
    }
}

pub mod traits;
pub use traits::*;

pub mod prelude {
    pub use crate::{errors::*, traits::*};

    pub use crate::{polycommit::error::*, r1cs::errors::*};
}
