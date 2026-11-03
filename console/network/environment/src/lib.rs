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
#![allow(clippy::too_many_arguments)]

mod environment;
pub use environment::*;

mod helpers;
pub use helpers::*;

pub mod traits;
pub use traits::*;

pub mod prelude {
    pub use crate::{
        environment::*,
        helpers::*,
        traits::{
            ToBits,
            ToBitsRaw,
            algorithms::*,
            arithmetic::*,
            bitwise::*,
            from_bits::*,
            from_field::*,
            parse::*,
            parse_string::*,
            to_bits_le,
            to_field::*,
            type_name::*,
            types::{
                integer_magnitude::Magnitude,
                integer_type::{
                    CheckedPow,
                    CheckedShl,
                    IntegerProperties,
                    IntegerType,
                    WrappingDiv,
                    WrappingPow,
                    WrappingRem,
                },
                *,
            },
            visibility::*,
        },
    };

    pub use snarkvm_curves::{AffineCurve, MontgomeryParameters, ProjectiveCurve, TwistedEdwardsParameters};
    pub use snarkvm_fields::{Field as _, PrimeField as _, SquareRootField as _, Zero as _};
    pub use snarkvm_utilities::{
        DeserializeExt,
        FromBits as _,
        FromBytes,
        FromBytesDeserializer,
        FromBytesUncheckedDeserializer,
        LimitedWriter,
        TestRng,
        ToBits as _,
        ToBitsRaw as _,
        ToBytes,
        ToBytesSerializer,
        Uniform,
        UniformExt,
        cfg_chunks,
        cfg_chunks_mut,
        cfg_find,
        cfg_find_map,
        cfg_into_iter,
        cfg_iter,
        cfg_iter_mut,
        cfg_keys,
        cfg_par_bridge,
        cfg_reduce,
        cfg_reduce_with,
        cfg_sort_by_cached_key,
        cfg_sort_unstable_by,
        cfg_sorted_by,
        cfg_values,
        cfg_zip_fold,
        error,
        has_duplicates,
        into_io_error,
        io_error,
    };

    pub use std::io::{Read, Result as IoResult, Write};

    pub use core::{
        cmp::Ordering,
        fmt::{self, Debug, Display, Formatter},
        hash::Hash as _,
        iter::{Product, Sum},
        ops::{
            Add,
            AddAssign,
            BitAnd,
            BitAndAssign,
            BitOr,
            BitOrAssign,
            BitXor,
            BitXorAssign,
            Deref,
            DerefMut,
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
        },
        str::{self, FromStr},
    };

    pub use anyhow::{Error, Result, anyhow, bail, ensure};
    pub use bech32;
    pub use itertools::Itertools;
    pub use nom::{
        Err,
        branch::alt,
        bytes::{complete::tag, streaming::take},
        character::complete::{alpha1, alphanumeric1, char, one_of},
        combinator::{complete, fail, map, map_res, opt, recognize},
        error::{ErrorKind, make_error},
        multi::{count, many_m_n, many0, many0_count, many1, separated_list0, separated_list1},
        sequence::{delimited, pair, terminated},
    };
    pub use num_traits::{AsPrimitive, One, Pow, Zero};
    pub use rand::{
        CryptoRng,
        RngExt as Rng,
        distr::{Alphanumeric, Distribution, StandardUniform},
    };
    pub use serde::{
        Deserialize,
        Deserializer,
        Serialize,
        Serializer,
        de,
        de::{DeserializeOwned, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor},
        ser::{self, SerializeSeq, SerializeStruct},
    };
}
