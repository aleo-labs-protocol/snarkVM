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

//! Montgomery products in x86-64 assembly with BMI2 `mulx` and ADX `adcx` and `adox`.
//!
//! The products use the no-carry CIOS method of El Housni and Botrel, "EdMSM: Multi-Scalar-
//! Multiplication for SNARKs and Faster Montgomery multiplication", TCHES 2023 (3),
//! <https://doi.org/10.46586/tches.v2023.i3.504-521>. `adcx` carries one chain on CF and `adox`
//! another on OF, so two column sums run interleaved, and `mulx` leaves both flags alone.
//!
//! The method needs the top limb of the modulus to be below `2^63 - 1`, as the Rust bodies do.
//! Every routine returns its result in `[0, 2p)`; the caller reduces it.
//!
//! The crate compiles this module only when the target enables `adx` and `bmi2`, for example
//! with `-C target-cpu=broadwell` or newer. Otherwise the field types run their Rust bodies.

#![allow(unsafe_code)]

pub(crate) mod fp256;
pub(crate) mod fp384;
