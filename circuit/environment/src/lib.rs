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

#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

extern crate snarkvm_console_network as console;

pub use snarkvm_circuit_environment_witness::rename_selfs;

pub mod canary_circuit;
pub use canary_circuit::*;

pub mod circuit;
pub use circuit::*;

pub mod environment;
pub use environment::*;

pub mod error;
pub use error::*;

pub mod helpers;
pub use helpers::*;

pub mod macros;
#[allow(unused_imports)]
pub use macros::*;

pub mod testnet_circuit;
pub use testnet_circuit::*;

pub mod traits;
pub use traits::*;

/// Seals [`Environment`]. `snarkvm-circuit-network` implements it for its networks, so it is
/// public, but it is not part of the API.
#[doc(hidden)]
pub mod sealed_circuit_environment {
    pub trait Sealed {}
}

pub mod prelude {
    pub use crate::{
        CircuitType,
        ConstraintUnsatisfied,
        Count,
        Environment,
        LinearCombination,
        Mode,
        OutputMode,
        Variable,
        count,
        count_is,
        count_less_than,
        output_mode,
        rename_selfs,
        traits::*,
        witness,
        witness_mode,
    };
    pub use console::{
        Parser,
        ParserResult,
        TypeName,
        prelude::{
            Debug,
            Display,
            Error,
            Formatter,
            FromStr,
            One as _,
            Result,
            Zero as _,
            bail,
            ensure,
            fmt,
            has_duplicates,
        },
        traits::{
            Double as _,
            FromBits as _,
            Inverse as _,
            Square as _,
            SquareRoot as _,
            ToBits as _,
            ToBitsRaw as _,
            string_parser,
            types::{
                integer_magnitude::Magnitude,
                integer_type::{CheckedPow, IntegerProperties, IntegerType, WrappingDiv, WrappingPow, WrappingRem},
            },
        },
    };
    pub use snarkvm_fields::{self, Field as _, PrimeField, Zero as _};

    #[cfg(debug_assertions)]
    pub use snarkvm_curves::AffineCurve as _;

    pub use core::ops::{
        Add,
        AddAssign,
        BitAnd,
        BitAndAssign,
        BitOr,
        BitOrAssign,
        BitXor,
        BitXorAssign,
        Deref,
        Div,
        DivAssign,
        Mul,
        MulAssign,
        Neg,
        Not,
        Rem,
        RemAssign,
        Shl,
        ShlAssign,
        Shr,
        ShrAssign,
        Sub,
        SubAssign,
    };
    pub use indexmap::IndexMap;
    pub use itertools::Itertools;
    pub use nom::{
        branch::alt,
        bytes::complete::tag,
        character::complete::{alpha1, alphanumeric1, char, one_of},
        combinator::{map, map_res, opt, recognize},
        multi::{many0, many1},
        sequence::{pair, terminated},
    };
    pub use num_traits::{self, Inv, One as NumOne, Pow, Unsigned};
}
