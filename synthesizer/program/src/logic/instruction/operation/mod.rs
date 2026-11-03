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

mod assert;
pub use assert::*;

mod async_;
pub use async_::*;

mod call;
pub use call::*;

mod cast;
pub use cast::*;

mod commit;
pub use commit::*;

mod deserialize;
pub use deserialize::*;

mod ecdsa_verify;
pub use ecdsa_verify::*;

mod get_record_dynamic;
pub use get_record_dynamic::*;

mod hash;
pub use hash::*;

mod is;
pub use is::*;

mod literals;
pub use literals::*;

mod macros;

mod serialize;
pub use serialize::*;

mod sign_verify;
pub use sign_verify::*;

mod snark_verify;
pub use snark_verify::*;

use crate::Opcode;
use console::network::prelude::*;

#[allow(unused)]
use console::account::Signature;

pub trait Operation<N: Network, Value: Parser + ToBits, ValueType: Parser, const NUM_OPERANDS: usize> {
    /// The opcode of the operation.
    const OPCODE: Opcode;

    /// Returns the result of evaluating the operation on the given inputs.
    fn evaluate(inputs: &[Value; NUM_OPERANDS]) -> Result<Value>;

    /// Returns the result of executing the operation on the given circuit inputs.
    fn execute<A: circuit::Aleo<Network = N>>(
        inputs: &[circuit::Literal<A>; NUM_OPERANDS],
    ) -> Result<circuit::Literal<A>>;

    /// Returns the output type from the given input types.
    fn output_type(inputs: &[ValueType; NUM_OPERANDS]) -> Result<ValueType>;
}

/// Compute the absolute value of `first`, checking for overflow/underflow, and storing the outcome in `destination`.
pub type Abs<N> = UnaryLiteral<N, AbsOperation<N>>;

crate::operation!(
    pub struct AbsOperation<console::prelude::AbsChecked, circuit::traits::AbsChecked, abs_checked, "abs"> {
        I8 => I8 ("ensure overflows halt"),
        I16 => I16 ("ensure overflows halt"),
        I32 => I32 ("ensure overflows halt"),
        I64 => I64 ("ensure overflows halt"),
        I128 => I128 ("ensure overflows halt"),
    }
);

/// Compute the absolute value of `first`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
pub type AbsWrapped<N> = UnaryLiteral<N, AbsWrappedOperation<N>>;

crate::operation!(
    pub struct AbsWrappedOperation<console::prelude::AbsWrapped, circuit::traits::AbsWrapped, abs_wrapped, "abs.w"> {
        I8 => I8,
        I16 => I16,
        I32 => I32,
        I64 => I64,
        I128 => I128,
    }
);

/// Adds `first` with `second`, storing the outcome in `destination`.
pub type Add<N> = BinaryLiteral<N, AddOperation<N>>;

crate::operation!(
    pub struct AddOperation<core::ops::Add, core::ops::Add, add, "add"> {
        (Field, Field) => Field,
        (Group, Group) => Group,
        (I8, I8) => I8 ("ensure overflows halt"),
        (I16, I16) => I16 ("ensure overflows halt"),
        (I32, I32) => I32 ("ensure overflows halt"),
        (I64, I64) => I64 ("ensure overflows halt"),
        (I128, I128) => I128 ("ensure overflows halt"),
        (U8, U8) => U8 ("ensure overflows halt"),
        (U16, U16) => U16 ("ensure overflows halt"),
        (U32, U32) => U32 ("ensure overflows halt"),
        (U64, U64) => U64 ("ensure overflows halt"),
        (U128, U128) => U128 ("ensure overflows halt"),
        (Scalar, Scalar) => Scalar,
    }
);

/// Adds `first` with `second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
pub type AddWrapped<N> = BinaryLiteral<N, AddWrappedOperation<N>>;

crate::operation!(
    pub struct AddWrappedOperation<console::prelude::AddWrapped, circuit::traits::AddWrapped, add_wrapped, "add.w"> {
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);

/// Performs a bitwise `and` on `first` and `second`, storing the outcome in `destination`.
pub type And<N> = BinaryLiteral<N, AndOperation<N>>;

crate::operation!(
    pub struct AndOperation<core::ops::BitAnd, core::ops::BitAnd, bitand, "and"> {
        (Boolean, Boolean) => Boolean,
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);

/// Divides `first` by `second`, storing the outcome in `destination`.
pub type Div<N> = BinaryLiteral<N, DivOperation<N>>;

crate::operation!(
    pub struct DivOperation<core::ops::Div, core::ops::Div, div, "div"> {
        (Field, Field) => Field ("ensure divide by zero halts"),
        (I8, I8) => I8 ("ensure overflows halt", "ensure divide by zero halts"),
        (I16, I16) => I16 ("ensure overflows halt", "ensure divide by zero halts"),
        (I32, I32) => I32 ("ensure overflows halt", "ensure divide by zero halts"),
        (I64, I64) => I64 ("ensure overflows halt", "ensure divide by zero halts"),
        (I128, I128) => I128 ("ensure overflows halt", "ensure divide by zero halts"),
        (U8, U8) => U8 ("ensure divide by zero halts"),
        (U16, U16) => U16 ("ensure divide by zero halts"),
        (U32, U32) => U32 ("ensure divide by zero halts"),
        (U64, U64) => U64 ("ensure divide by zero halts"),
        (U128, U128) => U128 ("ensure divide by zero halts"),
        // (Scalar, Scalar) => Scalar,
    }
);

/// Divides `first` by `second`, wrapping around at the boundary of the type, storing the outcome in `destination`.
pub type DivWrapped<N> = BinaryLiteral<N, DivWrappedOperation<N>>;

crate::operation!(
    pub struct DivWrappedOperation<console::prelude::DivWrapped, circuit::traits::DivWrapped, div_wrapped, "div.w"> {
        (I8, I8) => I8 ("ensure divide by zero halts"),
        (I16, I16) => I16 ("ensure divide by zero halts"),
        (I32, I32) => I32 ("ensure divide by zero halts"),
        (I64, I64) => I64 ("ensure divide by zero halts"),
        (I128, I128) => I128 ("ensure divide by zero halts"),
        (U8, U8) => U8 ("ensure divide by zero halts"),
        (U16, U16) => U16 ("ensure divide by zero halts"),
        (U32, U32) => U32 ("ensure divide by zero halts"),
        (U64, U64) => U64 ("ensure divide by zero halts"),
        (U128, U128) => U128 ("ensure divide by zero halts"),
    }
);

/// Doubles `first`, storing the outcome in `destination`.
pub type Double<N> = UnaryLiteral<N, DoubleOperation<N>>;

crate::operation!(
    pub struct DoubleOperation<console::prelude::Double, circuit::traits::Double, double, "double"> {
        Field => Field,
        Group => Group,
    }
);

/// Computes whether `first` is greater than `second` as a boolean, storing the outcome in `destination`.
pub type GreaterThan<N> = BinaryLiteral<N, GreaterThanOperation<N>>;

crate::operation!(
    pub struct GreaterThanOperation<console::prelude::Compare, circuit::traits::Compare, is_greater_than, "gt"> {
        // (Address, Address) => Boolean,
        (Field, Field) => Boolean,
        (I8, I8) => Boolean,
        (I16, I16) => Boolean,
        (I32, I32) => Boolean,
        (I64, I64) => Boolean,
        (I128, I128) => Boolean,
        (U8, U8) => Boolean,
        (U16, U16) => Boolean,
        (U32, U32) => Boolean,
        (U64, U64) => Boolean,
        (U128, U128) => Boolean,
        (Scalar, Scalar) => Boolean,
    }
);

/// Computes whether `first` is greater than or equal to `second` as a boolean, storing the outcome in `destination`.
pub type GreaterThanOrEqual<N> = BinaryLiteral<N, GreaterThanOrEqualOperation<N>>;

crate::operation!(
    pub struct GreaterThanOrEqualOperation<console::prelude::Compare, circuit::traits::Compare, is_greater_than_or_equal, "gte"> {
        // (Address, Address) => Boolean,
        (Field, Field) => Boolean,
        (I8, I8) => Boolean,
        (I16, I16) => Boolean,
        (I32, I32) => Boolean,
        (I64, I64) => Boolean,
        (I128, I128) => Boolean,
        (U8, U8) => Boolean,
        (U16, U16) => Boolean,
        (U32, U32) => Boolean,
        (U64, U64) => Boolean,
        (U128, U128) => Boolean,
        (Scalar, Scalar) => Boolean,
    }
);

/// Computes the multiplicative inverse of `first`, storing the outcome in `destination`.
pub type Inv<N> = UnaryLiteral<N, InvOperation<N>>;

crate::operation!(
    pub struct InvOperation<console::prelude::Inverse, circuit::traits::Inverse, inverse?, "inv"> {
        Field => Field ("ensure inverse of zero halts"),
    }
);

/// Computes whether `first` is less than `second` as a boolean, storing the outcome in `destination`.
pub type LessThan<N> = BinaryLiteral<N, LessThanOperation<N>>;

crate::operation!(
    pub struct LessThanOperation<console::prelude::Compare, circuit::traits::Compare, is_less_than, "lt"> {
        // (Address, Address) => Boolean,
        (Field, Field) => Boolean,
        (I8, I8) => Boolean,
        (I16, I16) => Boolean,
        (I32, I32) => Boolean,
        (I64, I64) => Boolean,
        (I128, I128) => Boolean,
        (U8, U8) => Boolean,
        (U16, U16) => Boolean,
        (U32, U32) => Boolean,
        (U64, U64) => Boolean,
        (U128, U128) => Boolean,
        (Scalar, Scalar) => Boolean,
    }
);

/// Computes whether `first` is less than or equal to `second` as a boolean, storing the outcome in `destination`.
pub type LessThanOrEqual<N> = BinaryLiteral<N, LessThanOrEqualOperation<N>>;

crate::operation!(
    pub struct LessThanOrEqualOperation<console::prelude::Compare, circuit::traits::Compare, is_less_than_or_equal, "lte"> {
        // (Address, Address) => Boolean,
        (Field, Field) => Boolean,
        (I8, I8) => Boolean,
        (I16, I16) => Boolean,
        (I32, I32) => Boolean,
        (I64, I64) => Boolean,
        (I128, I128) => Boolean,
        (U8, U8) => Boolean,
        (U16, U16) => Boolean,
        (U32, U32) => Boolean,
        (U64, U64) => Boolean,
        (U128, U128) => Boolean,
        (Scalar, Scalar) => Boolean,
    }
);

/// Computes the result of `first` mod `second`, storing the outcome in the destination.
pub type Modulo<N> = BinaryLiteral<N, ModuloOperation<N>>;

crate::operation!(
    pub struct ModuloOperation<console::prelude::Modulo, circuit::traits::Modulo, modulo, "mod"> {
        (U8, U8) => U8("ensure divide by zero halts"),
        (U16, U16) => U16("ensure divide by zero halts"),
        (U32, U32) => U32("ensure divide by zero halts"),
        (U64, U64) => U64("ensure divide by zero halts"),
        (U128, U128) => U128("ensure divide by zero halts"),
    }
);

/// Multiplies `first` and `second`, storing the outcome in `destination`.
pub type Mul<N> = BinaryLiteral<N, MulOperation<N>>;

crate::operation!(
    pub struct MulOperation<core::ops::Mul, core::ops::Mul, mul, "mul"> {
        (Field, Field) => Field,
        (Group, Scalar) => Group,
        (Scalar, Group) => Group,
        (I8, I8) => I8 ("ensure overflows halt"),
        (I16, I16) => I16 ("ensure overflows halt"),
        (I32, I32) => I32 ("ensure overflows halt"),
        (I64, I64) => I64 ("ensure overflows halt"),
        (I128, I128) => I128 ("ensure overflows halt"),
        (U8, U8) => U8 ("ensure overflows halt"),
        (U16, U16) => U16 ("ensure overflows halt"),
        (U32, U32) => U32 ("ensure overflows halt"),
        (U64, U64) => U64 ("ensure overflows halt"),
        (U128, U128) => U128 ("ensure overflows halt"),
        // (Scalar, Scalar) => Scalar,
    }
);

/// Multiplies `first` and `second`, wrapping around at the boundary of the type, storing the outcome in `destination`.
pub type MulWrapped<N> = BinaryLiteral<N, MulWrappedOperation<N>>;

crate::operation!(
    pub struct MulWrappedOperation<console::prelude::MulWrapped, circuit::traits::MulWrapped, mul_wrapped, "mul.w"> {
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);

/// Returns `false` if `first` and `second` are `true`, storing the outcome in `destination`.
pub type Nand<N> = BinaryLiteral<N, NandOperation<N>>;

crate::operation!(
    pub struct NandOperation<console::prelude::Nand, circuit::traits::Nand, nand, "nand"> {
        (Boolean, Boolean) => Boolean,
    }
);

/// Negates `first`, storing the outcome in `destination`.
pub type Neg<N> = UnaryLiteral<N, NegOperation<N>>;

crate::operation!(
    pub struct NegOperation<core::ops::Neg, core::ops::Neg, neg, "neg"> {
        Field => Field,
        Group => Group,
        I8 => I8 ("ensure overflows halt"),
        I16 => I16 ("ensure overflows halt"),
        I32 => I32 ("ensure overflows halt"),
        I64 => I64 ("ensure overflows halt"),
        I128 => I128 ("ensure overflows halt"),
    }
);

/// Returns `true` if neither `first` nor `second` is `true`, storing the outcome in `destination`.
pub type Nor<N> = BinaryLiteral<N, NorOperation<N>>;

crate::operation!(
    pub struct NorOperation<console::prelude::Nor, circuit::traits::Nor, nor, "nor"> {
        (Boolean, Boolean) => Boolean,
    }
);

/// Flips each bit in the representation of `first`, storing the outcome in `destination`.
pub type Not<N> = UnaryLiteral<N, NotOperation<N>>;

crate::operation!(
    pub struct NotOperation<core::ops::Not, core::ops::Not, not, "not"> {
        Boolean => Boolean,
        I8 => I8,
        I16 => I16,
        I32 => I32,
        I64 => I64,
        I128 => I128,
        U8 => U8,
        U16 => U16,
        U32 => U32,
        U64 => U64,
        U128 => U128,
    }
);

/// Performs a bitwise `or` on `first` and `second`, storing the outcome in `destination`.
pub type Or<N> = BinaryLiteral<N, OrOperation<N>>;

crate::operation!(
    pub struct OrOperation<core::ops::BitOr, core::ops::BitOr, bitor, "or"> {
        (Boolean, Boolean) => Boolean,
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);

/// Raises `first` to the power of `second`, storing the outcome in `destination`.
pub type Pow<N> = BinaryLiteral<N, PowOperation<N>>;

crate::operation!(
    pub struct PowOperation<console::prelude::Pow, circuit::traits::Pow, pow, "pow"> {
        (Field, Field) => Field,
        (I8, U8) => I8 ("ensure exponentiation overflows halt"),
        (I8, U16) => I8 ("ensure exponentiation overflows halt"),
        (I8, U32) => I8 ("ensure exponentiation overflows halt"),
        (I16, U8) => I16 ("ensure exponentiation overflows halt"),
        (I16, U16) => I16 ("ensure exponentiation overflows halt"),
        (I16, U32) => I16 ("ensure exponentiation overflows halt"),
        (I32, U8) => I32 ("ensure exponentiation overflows halt"),
        (I32, U16) => I32 ("ensure exponentiation overflows halt"),
        (I32, U32) => I32 ("ensure exponentiation overflows halt"),
        (I64, U8) => I64 ("ensure exponentiation overflows halt"),
        (I64, U16) => I64 ("ensure exponentiation overflows halt"),
        (I64, U32) => I64 ("ensure exponentiation overflows halt"),
        (I128, U8) => I128 ("ensure exponentiation overflows halt"),
        (I128, U16) => I128 ("ensure exponentiation overflows halt"),
        (I128, U32) => I128 ("ensure exponentiation overflows halt"),
        (U8, U8) => U8 ("ensure exponentiation overflows halt"),
        (U8, U16) => U8 ("ensure exponentiation overflows halt"),
        (U8, U32) => U8 ("ensure exponentiation overflows halt"),
        (U16, U8) => U16 ("ensure exponentiation overflows halt"),
        (U16, U16) => U16 ("ensure exponentiation overflows halt"),
        (U16, U32) => U16 ("ensure exponentiation overflows halt"),
        (U32, U8) => U32 ("ensure exponentiation overflows halt"),
        (U32, U16) => U32 ("ensure exponentiation overflows halt"),
        (U32, U32) => U32 ("ensure exponentiation overflows halt"),
        (U64, U8) => U64 ("ensure exponentiation overflows halt"),
        (U64, U16) => U64 ("ensure exponentiation overflows halt"),
        (U64, U32) => U64 ("ensure exponentiation overflows halt"),
        (U128, U8) => U128 ("ensure exponentiation overflows halt"),
        (U128, U16) => U128 ("ensure exponentiation overflows halt"),
        (U128, U32) => U128 ("ensure exponentiation overflows halt"),
    }
);

/// Raises `first` to the power of `second`, wrapping around at the boundary of the type, storing the outcome in `destination`.
pub type PowWrapped<N> = BinaryLiteral<N, PowWrappedOperation<N>>;

crate::operation!(
    pub struct PowWrappedOperation<console::prelude::PowWrapped, circuit::traits::PowWrapped, pow_wrapped, "pow.w"> {
        (I8, U8) => I8,
        (I8, U16) => I8,
        (I8, U32) => I8,
        (I16, U8) => I16,
        (I16, U16) => I16,
        (I16, U32) => I16,
        (I32, U8) => I32,
        (I32, U16) => I32,
        (I32, U32) => I32,
        (I64, U8) => I64,
        (I64, U16) => I64,
        (I64, U32) => I64,
        (I128, U8) => I128,
        (I128, U16) => I128,
        (I128, U32) => I128,
        (U8, U8) => U8,
        (U8, U16) => U8,
        (U8, U32) => U8,
        (U16, U8) => U16,
        (U16, U16) => U16,
        (U16, U32) => U16,
        (U32, U8) => U32,
        (U32, U16) => U32,
        (U32, U32) => U32,
        (U64, U8) => U64,
        (U64, U16) => U64,
        (U64, U32) => U64,
        (U128, U8) => U128,
        (U128, U16) => U128,
        (U128, U32) => U128,
    }
);

/// Divides `first` by `second`, storing the remainder in `destination`.
pub type Rem<N> = BinaryLiteral<N, RemOperation<N>>;

crate::operation!(
    pub struct RemOperation<core::ops::Rem, core::ops::Rem, rem, "rem"> {
        (I8, I8) => I8 ("ensure overflows halt", "ensure divide by zero halts"),
        (I16, I16) => I16 ("ensure overflows halt", "ensure divide by zero halts"),
        (I32, I32) => I32 ("ensure overflows halt", "ensure divide by zero halts"),
        (I64, I64) => I64 ("ensure overflows halt", "ensure divide by zero halts"),
        (I128, I128) => I128 ("ensure overflows halt", "ensure divide by zero halts"),
        (U8, U8) => U8 ("ensure divide by zero halts"),
        (U16, U16) => U16 ("ensure divide by zero halts"),
        (U32, U32) => U32 ("ensure divide by zero halts"),
        (U64, U64) => U64 ("ensure divide by zero halts"),
        (U128, U128) => U128 ("ensure divide by zero halts"),
    }
);

/// Divides `first` by `second`, wrapping around at the boundary of the type, storing the remainder in `destination`.
pub type RemWrapped<N> = BinaryLiteral<N, RemWrappedOperation<N>>;

crate::operation!(
    pub struct RemWrappedOperation<console::prelude::RemWrapped, circuit::traits::RemWrapped, rem_wrapped, "rem.w"> {
        (I8, I8) => I8 ("ensure divide by zero halts"),
        (I16, I16) => I16 ("ensure divide by zero halts"),
        (I32, I32) => I32 ("ensure divide by zero halts"),
        (I64, I64) => I64 ("ensure divide by zero halts"),
        (I128, I128) => I128 ("ensure divide by zero halts"),
        (U8, U8) => U8 ("ensure divide by zero halts"),
        (U16, U16) => U16 ("ensure divide by zero halts"),
        (U32, U32) => U32 ("ensure divide by zero halts"),
        (U64, U64) => U64 ("ensure divide by zero halts"),
        (U128, U128) => U128 ("ensure divide by zero halts"),
    }
);

/// Shifts `first` left by `second` bits, storing the outcome in `destination`.
pub type Shl<N> = BinaryLiteral<N, ShlOperation<N>>;

crate::operation!(
    pub struct ShlOperation<console::prelude::ShlChecked, circuit::traits::ShlChecked, shl_checked, "shl"> {
        (I8, U8) => I8 ("ensure shifting past boundary halts"),
        (I8, U16) => I8 ("ensure shifting past boundary halts"),
        (I8, U32) => I8 ("ensure shifting past boundary halts"),
        (I16, U8) => I16 ("ensure shifting past boundary halts"),
        (I16, U16) => I16 ("ensure shifting past boundary halts"),
        (I16, U32) => I16 ("ensure shifting past boundary halts"),
        (I32, U8) => I32 ("ensure shifting past boundary halts"),
        (I32, U16) => I32 ("ensure shifting past boundary halts"),
        (I32, U32) => I32 ("ensure shifting past boundary halts"),
        (I64, U8) => I64 ("ensure shifting past boundary halts"),
        (I64, U16) => I64 ("ensure shifting past boundary halts"),
        (I64, U32) => I64 ("ensure shifting past boundary halts"),
        (I128, U8) => I128 ("ensure shifting past boundary halts"),
        (I128, U16) => I128 ("ensure shifting past boundary halts"),
        (I128, U32) => I128 ("ensure shifting past boundary halts"),
        (U8, U8) => U8 ("ensure shifting past boundary halts"),
        (U8, U16) => U8 ("ensure shifting past boundary halts"),
        (U8, U32) => U8 ("ensure shifting past boundary halts"),
        (U16, U8) => U16 ("ensure shifting past boundary halts"),
        (U16, U16) => U16 ("ensure shifting past boundary halts"),
        (U16, U32) => U16 ("ensure shifting past boundary halts"),
        (U32, U8) => U32 ("ensure shifting past boundary halts"),
        (U32, U16) => U32 ("ensure shifting past boundary halts"),
        (U32, U32) => U32 ("ensure shifting past boundary halts"),
        (U64, U8) => U64 ("ensure shifting past boundary halts"),
        (U64, U16) => U64 ("ensure shifting past boundary halts"),
        (U64, U32) => U64 ("ensure shifting past boundary halts"),
        (U128, U8) => U128 ("ensure shifting past boundary halts"),
        (U128, U16) => U128 ("ensure shifting past boundary halts"),
        (U128, U32) => U128 ("ensure shifting past boundary halts"),
    }
);

/// Shifts `first` left by `second` bits, continuing past the boundary of the type, storing the outcome in `destination`.
pub type ShlWrapped<N> = BinaryLiteral<N, ShlWrappedOperation<N>>;

crate::operation!(
    pub struct ShlWrappedOperation<console::prelude::ShlWrapped, circuit::traits::ShlWrapped, shl_wrapped, "shl.w"> {
        (I8, U8) => I8,
        (I8, U16) => I8,
        (I8, U32) => I8,
        (I16, U8) => I16,
        (I16, U16) => I16,
        (I16, U32) => I16,
        (I32, U8) => I32,
        (I32, U16) => I32,
        (I32, U32) => I32,
        (I64, U8) => I64,
        (I64, U16) => I64,
        (I64, U32) => I64,
        (I128, U8) => I128,
        (I128, U16) => I128,
        (I128, U32) => I128,
        (U8, U8) => U8,
        (U8, U16) => U8,
        (U8, U32) => U8,
        (U16, U8) => U16,
        (U16, U16) => U16,
        (U16, U32) => U16,
        (U32, U8) => U32,
        (U32, U16) => U32,
        (U32, U32) => U32,
        (U64, U8) => U64,
        (U64, U16) => U64,
        (U64, U32) => U64,
        (U128, U8) => U128,
        (U128, U16) => U128,
        (U128, U32) => U128,
    }
);

/// Shifts `first` right by `second` bits, storing the outcome in `destination`.
pub type Shr<N> = BinaryLiteral<N, ShrOperation<N>>;

crate::operation!(
    pub struct ShrOperation<console::prelude::ShrChecked, circuit::traits::ShrChecked, shr_checked, "shr"> {
        (I8, U8) => I8 ("ensure shifting past boundary halts"),
        (I8, U16) => I8 ("ensure shifting past boundary halts"),
        (I8, U32) => I8 ("ensure shifting past boundary halts"),
        (I16, U8) => I16 ("ensure shifting past boundary halts"),
        (I16, U16) => I16 ("ensure shifting past boundary halts"),
        (I16, U32) => I16 ("ensure shifting past boundary halts"),
        (I32, U8) => I32 ("ensure shifting past boundary halts"),
        (I32, U16) => I32 ("ensure shifting past boundary halts"),
        (I32, U32) => I32 ("ensure shifting past boundary halts"),
        (I64, U8) => I64 ("ensure shifting past boundary halts"),
        (I64, U16) => I64 ("ensure shifting past boundary halts"),
        (I64, U32) => I64 ("ensure shifting past boundary halts"),
        (I128, U8) => I128 ("ensure shifting past boundary halts"),
        (I128, U16) => I128 ("ensure shifting past boundary halts"),
        (I128, U32) => I128 ("ensure shifting past boundary halts"),
        (U8, U8) => U8 ("ensure shifting past boundary halts"),
        (U8, U16) => U8 ("ensure shifting past boundary halts"),
        (U8, U32) => U8 ("ensure shifting past boundary halts"),
        (U16, U8) => U16 ("ensure shifting past boundary halts"),
        (U16, U16) => U16 ("ensure shifting past boundary halts"),
        (U16, U32) => U16 ("ensure shifting past boundary halts"),
        (U32, U8) => U32 ("ensure shifting past boundary halts"),
        (U32, U16) => U32 ("ensure shifting past boundary halts"),
        (U32, U32) => U32 ("ensure shifting past boundary halts"),
        (U64, U8) => U64 ("ensure shifting past boundary halts"),
        (U64, U16) => U64 ("ensure shifting past boundary halts"),
        (U64, U32) => U64 ("ensure shifting past boundary halts"),
        (U128, U8) => U128 ("ensure shifting past boundary halts"),
        (U128, U16) => U128 ("ensure shifting past boundary halts"),
        (U128, U32) => U128 ("ensure shifting past boundary halts"),
    }
);

/// Shifts `first` right by `second` bits, continuing past the boundary of the type, storing the outcome in `destination`.
pub type ShrWrapped<N> = BinaryLiteral<N, ShrWrappedOperation<N>>;

crate::operation!(
    pub struct ShrWrappedOperation<console::prelude::ShrWrapped, circuit::traits::ShrWrapped, shr_wrapped, "shr.w"> {
        (I8, U8) => I8,
        (I8, U16) => I8,
        (I8, U32) => I8,
        (I16, U8) => I16,
        (I16, U16) => I16,
        (I16, U32) => I16,
        (I32, U8) => I32,
        (I32, U16) => I32,
        (I32, U32) => I32,
        (I64, U8) => I64,
        (I64, U16) => I64,
        (I64, U32) => I64,
        (I128, U8) => I128,
        (I128, U16) => I128,
        (I128, U32) => I128,
        (U8, U8) => U8,
        (U8, U16) => U8,
        (U8, U32) => U8,
        (U16, U8) => U16,
        (U16, U16) => U16,
        (U16, U32) => U16,
        (U32, U8) => U32,
        (U32, U16) => U32,
        (U32, U32) => U32,
        (U64, U8) => U64,
        (U64, U16) => U64,
        (U64, U32) => U64,
        (U128, U8) => U128,
        (U128, U16) => U128,
        (U128, U32) => U128,
    }
);

/// Squares `first`, storing the outcome in `destination`.
pub type Square<N> = UnaryLiteral<N, SquareOperation<N>>;

crate::operation!(
    pub struct SquareOperation<console::prelude::Square, circuit::traits::Square, square, "square"> {
        Field => Field,
    }
);

/// Computes the square root of `first`, storing the outcome in `destination`.
pub type SquareRoot<N> = UnaryLiteral<N, SquareRootOperation<N>>;

crate::operation!(
    pub struct SquareRootOperation<console::prelude::SquareRoot, circuit::traits::SquareRoot, square_root?, "sqrt"> {
        Field => Field ("ensure quadratic nonresidues halt"),
    }
);

/// Computes `first - second`, storing the outcome in `destination`.
pub type Sub<N> = BinaryLiteral<N, SubOperation<N>>;

crate::operation!(
    pub struct SubOperation<core::ops::Sub, core::ops::Sub, sub, "sub"> {
        (Field, Field) => Field,
        (Group, Group) => Group,
        (I8, I8) => I8 ("ensure overflows halt"),
        (I16, I16) => I16 ("ensure overflows halt"),
        (I32, I32) => I32 ("ensure overflows halt"),
        (I64, I64) => I64 ("ensure overflows halt"),
        (I128, I128) => I128 ("ensure overflows halt"),
        (U8, U8) => U8 ("ensure overflows halt"),
        (U16, U16) => U16 ("ensure overflows halt"),
        (U32, U32) => U32 ("ensure overflows halt"),
        (U64, U64) => U64 ("ensure overflows halt"),
        (U128, U128) => U128 ("ensure overflows halt"),
        // (Scalar, Scalar) => Scalar,
    }
);

/// Computes `first - second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
pub type SubWrapped<N> = BinaryLiteral<N, SubWrappedOperation<N>>;

crate::operation!(
    pub struct SubWrappedOperation<console::prelude::SubWrapped, circuit::traits::SubWrapped, sub_wrapped, "sub.w"> {
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);

/// Selects `first`, if `condition` is true, otherwise selects `second`, storing the result in `destination`.
pub type Ternary<N> = TernaryLiteral<N, TernaryOperation<N>>;

crate::operation!(
    pub struct TernaryOperation<console::prelude::Ternary, circuit::traits::Ternary, ternary, "ternary"> {
        (Boolean, Address, Address) => Address,
        (Boolean, Boolean, Boolean) => Boolean,
        (Boolean, Field, Field) => Field,
        (Boolean, Group, Group) => Group,
        (Boolean, I8, I8) => I8,
        (Boolean, I16, I16) => I16,
        (Boolean, I32, I32) => I32,
        (Boolean, I64, I64) => I64,
        (Boolean, I128, I128) => I128,
        (Boolean, U8, U8) => U8,
        (Boolean, U16, U16) => U16,
        (Boolean, U32, U32) => U32,
        (Boolean, U64, U64) => U64,
        (Boolean, U128, U128) => U128,
        (Boolean, Scalar, Scalar) => Scalar,
        (Boolean, Signature, Signature) => Signature,
        // (Boolean, StringType, StringType) => StringType,
    }
);

/// Performs a bitwise `xor` on `first` and `second`, storing the outcome in `destination`.
pub type Xor<N> = BinaryLiteral<N, XorOperation<N>>;

crate::operation!(
    pub struct XorOperation<core::ops::BitXor, core::ops::BitXor, bitxor, "xor"> {
        (Boolean, Boolean) => Boolean,
        (I8, I8) => I8,
        (I16, I16) => I16,
        (I32, I32) => I32,
        (I64, I64) => I64,
        (I128, I128) => I128,
        (U8, U8) => U8,
        (U16, U16) => U16,
        (U32, U32) => U32,
        (U64, U64) => U64,
        (U128, U128) => U128,
    }
);
