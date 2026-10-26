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

mod opcode;
pub use opcode::*;

mod operand;
pub use operand::*;

mod operation;
pub use operation::*;

mod bytes;
mod parse;

use crate::{FinalizeRegistersState, FinalizeStoreTrait, RegistersCircuit, RegistersSigner, StackTrait};
use console::{
    network::Network,
    prelude::{
        Debug,
        Display,
        Error,
        Formatter,
        FromBytes,
        FromStr,
        IoResult,
        Parser,
        ParserResult,
        Read,
        Result,
        Sanitizer,
        ToBytes,
        Write,
        alt,
        bail,
        ensure,
        error,
        fmt,
        map,
        tag,
    },
    program::{Register, RegisterType},
};
use snarkvm_synthesizer_error::*;

#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Instruction<N: Network> {
    /// Compute the absolute value of `first`, checking for overflow, and storing the outcome in `destination`.
    Abs(Abs<N>),
    /// Compute the absolute value of `first`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
    AbsWrapped(AbsWrapped<N>),
    /// Adds `first` with `second`, storing the outcome in `destination`.
    Add(Add<N>),
    /// Adds `first` with `second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
    AddWrapped(AddWrapped<N>),
    /// Performs a bitwise `and` operation on `first` and `second`, storing the outcome in `destination`.
    And(And<N>),
    /// Asserts `first` and `second` are equal.
    AssertEq(AssertEq<N>),
    /// Asserts `first` and `second` are **not** equal.
    AssertNeq(AssertNeq<N>),
    /// Calls a finalize asynchronously on the operands.
    Async(Async<N>),
    /// Calls a closure or function on the operands.
    Call(Call<N>),
    /// Dynamically calls a function on the operands.
    CallDynamic(CallDynamic<N>),
    /// Casts the operands into the declared type.
    Cast(Cast<N>),
    /// Casts the operands into the declared type, with lossy truncation if applicable.
    CastLossy(CastLossy<N>),
    /// Performs a BHP commitment on inputs of 256-bit chunks.
    CommitBHP256(CommitBHP256<N>),
    /// Performs a BHP commitment on inputs of 512-bit chunks.
    CommitBHP512(CommitBHP512<N>),
    /// Performs a BHP commitment on inputs of 768-bit chunks.
    CommitBHP768(CommitBHP768<N>),
    /// Performs a BHP commitment on inputs of 1024-bit chunks.
    CommitBHP1024(CommitBHP1024<N>),
    /// Performs a Pedersen commitment on up to a 64-bit input.
    CommitPED64(CommitPED64<N>),
    /// Performs a Pedersen commitment on up to a 128-bit input.
    CommitPED128(CommitPED128<N>),
    /// Performs a BHP commitment on the input's raw bits in 256-bit chunks.
    CommitBHP256Raw(CommitBHP256Raw<N>),
    /// Performs a BHP commitment on the input's raw bits in 512-bit chunks.
    CommitBHP512Raw(CommitBHP512Raw<N>),
    /// Performs a BHP commitment on the input's raw bits in 768-bit chunks.
    CommitBHP768Raw(CommitBHP768Raw<N>),
    /// Performs a BHP commitment on the input's raw bits in 1024-bit chunks.
    CommitBHP1024Raw(CommitBHP1024Raw<N>),
    /// Performs a Pedersen commitment on the input's raw bits up to a 64-bit input.
    CommitPED64Raw(CommitPED64Raw<N>),
    /// Performs a Pedersen commitment on the input's raw bits up to a 128-bit input.
    CommitPED128Raw(CommitPED128Raw<N>),
    /// Deserializes the bits into a value.
    DeserializeBits(DeserializeBits<N>),
    /// Deserializes the raw bits into a value.
    DeserializeBitsRaw(DeserializeBitsRaw<N>),
    /// Divides `first` by `second`, storing the outcome in `destination`.
    Div(Div<N>),
    /// Divides `first` by `second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
    DivWrapped(DivWrapped<N>),
    /// Doubles `first`, storing the outcome in `destination`.
    Double(Double<N>),
    /// Computes whether `signature` is valid for the given `signer` and `digest` using ECDSA.
    ECDSAVerifyDigest(ECDSAVerifyDigest<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `digest` using ECDSA.
    ECDSAVerifyDigestEth(ECDSAVerifyDigestEth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak256.
    ECDSAVerifyKeccak256(ECDSAVerifyKeccak256<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak256 and raw inputs.
    ECDSAVerifyKeccak256Raw(ECDSAVerifyKeccak256Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with Keccak256 and raw inputs.
    ECDSAVerifyKeccak256Eth(ECDSAVerifyKeccak256Eth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak384.
    ECDSAVerifyKeccak384(ECDSAVerifyKeccak384<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak384 and raw inputs.
    ECDSAVerifyKeccak384Raw(ECDSAVerifyKeccak384Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with Keccak384 and raw inputs.
    ECDSAVerifyKeccak384Eth(ECDSAVerifyKeccak384Eth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak512.
    ECDSAVerifyKeccak512(ECDSAVerifyKeccak512<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with Keccak512 and raw inputs.
    ECDSAVerifyKeccak512Raw(ECDSAVerifyKeccak512Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with Keccak512 and raw inputs.
    ECDSAVerifyKeccak512Eth(ECDSAVerifyKeccak512Eth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-256.
    ECDSAVerifySha3_256(ECDSAVerifySha3_256<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-256 and raw inputs.
    ECDSAVerifySha3_256Raw(ECDSAVerifySha3_256Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with SHA3-256 and raw inputs.
    ECDSAVerifySha3_256Eth(ECDSAVerifySha3_256Eth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-384.
    ECDSAVerifySha3_384(ECDSAVerifySha3_384<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-384 and raw inputs.
    ECDSAVerifySha3_384Raw(ECDSAVerifySha3_384Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with SHA3-384 and raw inputs.
    ECDSAVerifySha3_384Eth(ECDSAVerifySha3_384Eth<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-512.
    ECDSAVerifySha3_512(ECDSAVerifySha3_512<N>),
    /// Computes whether `signature` is valid for the given `signer` and `message` using ECDSA with SHA3-512 and raw inputs.
    ECDSAVerifySha3_512Raw(ECDSAVerifySha3_512Raw<N>),
    /// Computes whether `signature` is valid for the given Ethereum `address` and `message` using ECDSA with SHA3-512 and raw inputs.
    ECDSAVerifySha3_512Eth(ECDSAVerifySha3_512Eth<N>),
    /// Gets a dynamic record entry.
    GetRecordDynamic(GetRecordDynamic<N>),
    /// Computes whether `first` is greater than `second` as a boolean, storing the outcome in `destination`.
    GreaterThan(GreaterThan<N>),
    /// Computes whether `first` is greater than or equal to `second` as a boolean, storing the outcome in `destination`.
    GreaterThanOrEqual(GreaterThanOrEqual<N>),
    /// Performs a BHP hash on inputs of 256-bit chunks.
    HashBHP256(HashBHP256<N>),
    /// Performs a BHP hash on the input's raw bits in 256-bit chunks.  
    HashBHP256Raw(HashBHP256Raw<N>),
    /// Performs a BHP hash on inputs of 512-bit chunks.
    HashBHP512(HashBHP512<N>),
    /// Performs a BHP hash on the input's raw bits in 512-bit chunks.  
    HashBHP512Raw(HashBHP512Raw<N>),
    /// Performs a BHP hash on inputs of 768-bit chunks.
    HashBHP768(HashBHP768<N>),
    /// Performs a BHP hash on the input's raw bits in 768-bit chunks.  
    HashBHP768Raw(HashBHP768Raw<N>),
    /// Performs a BHP hash on inputs of 1024-bit chunks.
    HashBHP1024(HashBHP1024<N>),
    /// Performs a BHP hash on the input's raw bits in 1024-bit chunks.
    HashBHP1024Raw(HashBHP1024Raw<N>),
    /// Performs a Keccak hash on the input, outputting 256 bits, hashing the result with BHP256.
    HashKeccak256(HashKeccak256<N>),
    /// Performs a Keccak hash on the input's raw bits, hashing the result with BHP256.
    HashKeccak256Raw(HashKeccak256Raw<N>),
    /// Performs a Keccak hash on the input, outputting 256 bits.
    HashKeccak256Native(HashKeccak256Native<N>),
    /// Performs a Keccak hash on the input's raw bits, outputting 256 bits.
    HashKeccak256NativeRaw(HashKeccak256NativeRaw<N>),
    /// Performs a Keccak hash on the input, outputting 384 bits, hashing the result with BHP512.
    HashKeccak384(HashKeccak384<N>),
    /// Performs a Keccak hash on the input's raw bits, outputting 384 bits, hashing the result with BHP512.
    HashKeccak384Raw(HashKeccak384Raw<N>),
    /// Performs a Keccak hash on the input, outputting 384 bits.
    HashKeccak384Native(HashKeccak384Native<N>),
    /// Performs a Keccak hash on the input's raw bits, outputting 384 bits.
    HashKeccak384NativeRaw(HashKeccak384NativeRaw<N>),
    /// Performs a Keccak hash on the input, outputting 512 bits, hashing the result with BHP512.
    HashKeccak512(HashKeccak512<N>),
    /// Performs a Keccak hash on the input's raw bits, outputting 512 bits, hashing the result with BHP512.
    HashKeccak512Raw(HashKeccak512Raw<N>),
    /// Performs a Keccak hash on the input, outputting 512 bits.
    HashKeccak512Native(HashKeccak512Native<N>),
    /// Performs a Keccak hash on the input's raw bits, outputting 512 bits.
    HashKeccak512NativeRaw(HashKeccak512NativeRaw<N>),
    /// Performs a Pedersen hash on up to a 64-bit input.
    HashPED64(HashPED64<N>),
    /// Performs a Pedersen hash on the input's raw bits up to a 64-bit input.
    HashPED64Raw(HashPED64Raw<N>),
    /// Performs a Pedersen hash on up to a 128-bit input.
    HashPED128(HashPED128<N>),
    /// Performs a Pedersen hash on the input's raw bits up to a 128-bit input.
    HashPED128Raw(HashPED128Raw<N>),
    /// Performs a Poseidon hash with an input rate of 2.
    HashPSD2(HashPSD2<N>),
    /// Performs a Poseidon hash on the input's raw fields with an input rate of 2.
    HashPSD2Raw(HashPSD2Raw<N>),
    /// Performs a Poseidon hash with an input rate of 4.
    HashPSD4(HashPSD4<N>),
    /// Performs a Poseidon hash on the input's raw fields with an input rate of 4.
    HashPSD4Raw(HashPSD4Raw<N>),
    /// Performs a Poseidon hash with an input rate of 8.
    HashPSD8(HashPSD8<N>),
    /// Performs a Poseidon hash on the input's raw fields with an input rate of 8.
    HashPSD8Raw(HashPSD8Raw<N>),
    /// Performs a SHA-3 hash on the input, outputting 256 bits, hashing the result with BHP256.
    HashSha3_256(HashSha3_256<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 256 bits, hashing the result with BHP256.
    HashSha3_256Raw(HashSha3_256Raw<N>),
    /// Performs a SHA-3 hash on the input's bits, outputting 256 bits.
    HashSha3_256Native(HashSha3_256Native<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 256 bits.
    HashSha3_256NativeRaw(HashSha3_256NativeRaw<N>),
    /// Performs a SHA-3 hash on the input, outputting 384 bits, hashing the result with BHP512.
    HashSha3_384(HashSha3_384<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 384 bits, hashing the result with BHP512.
    HashSha3_384Raw(HashSha3_384Raw<N>),
    /// Performs a SHA-3 hash on the input's bits, outputting 384 bits.
    HashSha3_384Native(HashSha3_384Native<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 384 bits.
    HashSha3_384NativeRaw(HashSha3_384NativeRaw<N>),
    /// Performs a SHA-3 hash, outputting 512 bits, hashing the result with BHP512.
    HashSha3_512(HashSha3_512<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 512 bits, hashing the result with BHP512.
    HashSha3_512Raw(HashSha3_512Raw<N>),
    /// Performs a SHA-3 hash on the input's bits, outputting 512 bits.
    HashSha3_512Native(HashSha3_512Native<N>),
    /// Performs a SHA-3 hash on the input's raw bits, outputting 512 bits.
    HashSha3_512NativeRaw(HashSha3_512NativeRaw<N>),
    /// Performs a Poseidon hash with an input rate of 2.
    HashManyPSD2(HashManyPSD2<N>),
    /// Performs a Poseidon hash with an input rate of 4.
    HashManyPSD4(HashManyPSD4<N>),
    /// Performs a Poseidon hash with an input rate of 8.
    HashManyPSD8(HashManyPSD8<N>),
    /// Computes the multiplicative inverse of `first`, storing the outcome in `destination`.
    Inv(Inv<N>),
    /// Computes whether `first` equals `second` as a boolean, storing the outcome in `destination`.
    IsEq(IsEq<N>),
    /// Computes whether `first` does **not** equals `second` as a boolean, storing the outcome in `destination`.
    IsNeq(IsNeq<N>),
    /// Computes whether `first` is less than `second` as a boolean, storing the outcome in `destination`.
    LessThan(LessThan<N>),
    /// Computes whether `first` is less than or equal to `second` as a boolean, storing the outcome in `destination`.
    LessThanOrEqual(LessThanOrEqual<N>),
    /// Computes `first` mod `second`, storing the outcome in `destination`.
    Modulo(Modulo<N>),
    /// Multiplies `first` with `second`, storing the outcome in `destination`.
    Mul(Mul<N>),
    /// Multiplies `first` with `second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
    MulWrapped(MulWrapped<N>),
    /// Returns `false` if `first` and `second` are true, storing the outcome in `destination`.
    Nand(Nand<N>),
    /// Negates `first`, storing the outcome in `destination`.
    Neg(Neg<N>),
    /// Returns `true` if neither `first` nor `second` is `true`, storing the outcome in `destination`.
    Nor(Nor<N>),
    /// Flips each bit in the representation of `first`, storing the outcome in `destination`.
    Not(Not<N>),
    /// Performs a bitwise `or` on `first` and `second`, storing the outcome in `destination`.
    Or(Or<N>),
    /// Raises `first` to the power of `second`, storing the outcome in `destination`.
    Pow(Pow<N>),
    /// Raises `first` to the power of `second`, wrapping around at the boundary of the type, storing the outcome in `destination`.
    PowWrapped(PowWrapped<N>),
    /// Divides `first` by `second`, storing the remainder in `destination`.
    Rem(Rem<N>),
    /// Divides `first` by `second`, wrapping around at the boundary of the type, storing the remainder in `destination`.
    RemWrapped(RemWrapped<N>),
    /// Serializes the bits of the input.
    SerializeBits(SerializeBits<N>),
    /// Serializes the raw bits of the input.
    SerializeBitsRaw(SerializeBitsRaw<N>),
    /// Shifts `first` left by `second` bits, storing the outcome in `destination`.
    Shl(Shl<N>),
    /// Shifts `first` left by `second` bits, wrapping around at the boundary of the type, storing the outcome in `destination`.
    ShlWrapped(ShlWrapped<N>),
    /// Shifts `first` right by `second` bits, storing the outcome in `destination`.
    Shr(Shr<N>),
    /// Shifts `first` right by `second` bits, wrapping around at the boundary of the type, storing the outcome in `destination`.
    ShrWrapped(ShrWrapped<N>),
    /// Computes whether `signature` is valid for the given `address` and `message`.
    SignVerify(SignVerify<N>),
    /// Computes whether `proof` is valid for the given `verifying_key` and `public inputs`.
    SnarkVerify(SnarkVerify<N>),
    /// Computes whether a `batch_proof` is valid for the given `verifying_keys` and `public inputs`.
    SnarkVerifyBatch(SnarkVerifyBatch<N>),
    /// Squares 'first', storing the outcome in `destination`.
    Square(Square<N>),
    /// Compute the square root of 'first', storing the outcome in `destination`.
    SquareRoot(SquareRoot<N>),
    /// Computes `first - second`, storing the outcome in `destination`.
    Sub(Sub<N>),
    /// Computes `first - second`, wrapping around at the boundary of the type, and storing the outcome in `destination`.
    SubWrapped(SubWrapped<N>),
    /// Selects `first`, if `condition` is true, otherwise selects `second`, storing the result in `destination`.
    Ternary(Ternary<N>),
    /// Performs a bitwise `xor` on `first` and `second`, storing the outcome in `destination`.
    Xor(Xor<N>),
}

/// Creates a match statement that applies the given operation for each instruction.
///
/// ## Example
/// This example will print the opcode and the instruction to the given stream.
/// ```rust,ignore
/// instruction!(self, |instruction| write!(f, "{} {};", self.opcode(), instruction))
/// ```
/// The above example is equivalent to the following logic:
/// ```rust,ignore
///     match self {
///         Self::Add(instruction) => write!(f, "{} {};", self.opcode(), instruction),
///         Self::Sub(instruction) => write!(f, "{} {};", self.opcode(), instruction),
///         Self::Mul(instruction) => write!(f, "{} {};", self.opcode(), instruction),
///         Self::Div(instruction) => write!(f, "{} {};", self.opcode(), instruction),
///     }
/// ```
#[macro_export]
macro_rules! instruction {
    // A variant **with** curly braces:
    // i.e. `instruction!(self, |instruction| { operation(instruction) })`.
    ($object:expr, |$input:ident| $operation:block) => {{ $crate::instruction!(instruction, $object, |$input| $operation) }};
    // A variant **without** curly braces:
    // i.e. `instruction!(self, |instruction| operation(instruction))`.
    ($object:expr, |$input:ident| $operation:expr) => {{ $crate::instruction!(instruction, $object, |$input| { $operation }) }};
    // A variant **with** curly braces:
    // i.e. `instruction!(custom_macro, self, |instruction| { operation(instruction) })`.
    ($macro_:ident, $object:expr, |$input:ident| $operation:block) => {
        $macro_!{$object, |$input| $operation, {
            // The original opcodes.
            Abs,
            AbsWrapped,
            Add,
            AddWrapped,
            And,
            AssertEq,
            AssertNeq,
            Async,
            Call,
            Cast,
            CastLossy,
            CommitBHP256,
            CommitBHP512,
            CommitBHP768,
            CommitBHP1024,
            CommitPED64,
            CommitPED128,
            Div,
            DivWrapped,
            Double,
            GreaterThan,
            GreaterThanOrEqual,
            HashBHP256,
            HashBHP512,
            HashBHP768,
            HashBHP1024,
            HashKeccak256,
            HashKeccak384,
            HashKeccak512,
            HashPED64,
            HashPED128,
            HashPSD2,
            HashPSD4,
            HashPSD8,
            HashSha3_256,
            HashSha3_384,
            HashSha3_512,
            HashManyPSD2,
            HashManyPSD4,
            HashManyPSD8,
            Inv,
            IsEq,
            IsNeq,
            LessThan,
            LessThanOrEqual,
            Modulo,
            Mul,
            MulWrapped,
            Nand,
            Neg,
            Nor,
            Not,
            Or,
            Pow,
            PowWrapped,
            Rem,
            RemWrapped,
            Shl,
            ShlWrapped,
            Shr,
            ShrWrapped,
            SignVerify,
            Square,
            SquareRoot,
            Sub,
            SubWrapped,
            Ternary,
            Xor,

            // New opcodes added in `ConsensusVersion::V11`
            DeserializeBits,
            DeserializeBitsRaw,
            ECDSAVerifyDigest,
            ECDSAVerifyDigestEth,
            ECDSAVerifyKeccak256,
            ECDSAVerifyKeccak256Raw,
            ECDSAVerifyKeccak256Eth,
            ECDSAVerifyKeccak384,
            ECDSAVerifyKeccak384Raw,
            ECDSAVerifyKeccak384Eth,
            ECDSAVerifyKeccak512,
            ECDSAVerifyKeccak512Raw,
            ECDSAVerifyKeccak512Eth,
            ECDSAVerifySha3_256,
            ECDSAVerifySha3_256Raw,
            ECDSAVerifySha3_256Eth,
            ECDSAVerifySha3_384,
            ECDSAVerifySha3_384Raw,
            ECDSAVerifySha3_384Eth,
            ECDSAVerifySha3_512,
            ECDSAVerifySha3_512Raw,
            ECDSAVerifySha3_512Eth,
            HashBHP256Raw,
            HashBHP512Raw,
            HashBHP768Raw,
            HashBHP1024Raw,
            HashKeccak256Raw,
            HashKeccak256Native,
            HashKeccak256NativeRaw,
            HashKeccak384Raw,
            HashKeccak384Native,
            HashKeccak384NativeRaw,
            HashKeccak512Raw,
            HashKeccak512Native,
            HashKeccak512NativeRaw,
            HashPED64Raw,
            HashPED128Raw,
            HashPSD2Raw,
            HashPSD4Raw,
            HashPSD8Raw,
            HashSha3_256Raw,
            HashSha3_256Native,
            HashSha3_256NativeRaw,
            HashSha3_384Raw,
            HashSha3_384Native,
            HashSha3_384NativeRaw,
            HashSha3_512Raw,
            HashSha3_512Native,
            HashSha3_512NativeRaw,
            SerializeBits,
            SerializeBitsRaw,

            // New opcodes added in `ConsensusVersion::V14`
            CallDynamic,
            GetRecordDynamic,
            SnarkVerify,
            SnarkVerifyBatch,

            // New opcodes added in `ConsensusVersion::V15`
            CommitBHP256Raw,
            CommitBHP512Raw,
            CommitBHP768Raw,
            CommitBHP1024Raw,
            CommitPED64Raw,
            CommitPED128Raw,

            // New opcodes should be added here, with a comment on which consensus version they were added in.
        }}
    };
    // A variant **without** curly braces:
    // i.e. `instruction!(custom_macro, self, |instruction| operation(instruction))`.
    ($macro_:ident, $object:expr, |$input:ident| $operation:expr) => {{ $crate::instruction!($macro_, $object, |$input| { $operation }) }};
    // A variant invoking a macro internally:
    // i.e. `instruction!(instruction_to_bytes_le!(self, writer))`.
    ($macro_:ident!($object:expr, $input:ident)) => {{ $crate::instruction!($macro_, $object, |$input| {}) }};

    ////////////////////
    // Private Macros //
    ////////////////////

    // A static variant **with** curly braces:
    // i.e. `instruction!(self, |InstructionMember| { InstructionMember::opcode() })`.
    ($object:expr, |InstructionMember| $operation:block, { $( $variant:ident, )+ }) => {{
        // Build the match cases.
        match $object {
            $( Self::$variant(..) => {{
                // Set the variant to be called `InstructionMember`.
                type InstructionMember<N> = $variant<N>;
                // Perform the operation.
                $operation
            }} ),+
        }
    }};
    // A static variant **without** curly braces:
    // i.e. `instruction!(self, |InstructionMember| InstructionMember::opcode())`.
    ($object:expr, |InstructionMember| $operation:expr, { $( $variant:ident, )+ }) => {{
        $crate::instruction!($object, |InstructionMember| { $operation }, { $( $variant, )+ })
    }};
    // A non-static variant **with** curly braces:
    // i.e. `instruction!(self, |instruction| { operation(instruction) })`.
    ($object:expr, |$instruction:ident| $operation:block, { $( $variant:ident, )+ }) => {{
        // Build the match cases.
        match $object { $( Self::$variant($instruction) => { $operation } ),+ }
    }};
    // A non-static variant **without** curly braces:
    // i.e. `instruction!(self, |instruction| operation(instruction))`.
    ($object:expr, |$instruction:ident| $operation:expr, { $( $variant:ident, )+ }) => {{
        $crate::instruction!($object, |$instruction| { $operation }, { $( $variant, )+ })
    }};
}

/// Derives `From<Operation>` for the instruction.
///
/// ## Example
/// ```ignore
/// derive_from_operation!(Instruction, |None| {}, { Add, Sub, Mul, Div })
/// ```
macro_rules! derive_from_operation {
    ($_object:expr, |$_reader:ident| $_operation:block, { $( $variant:ident, )+ }) => {
        $(impl<N: Network> From<$variant<N>> for Instruction<N> {
            #[inline]
            fn from(operation: $variant<N>) -> Self {
                Self::$variant(operation)
            }
        })+
    }
}
instruction!(derive_from_operation, Instruction, |None| {});

/// Returns a slice of all instruction opcodes.
///
/// ## Example
/// ```ignore
/// opcodes!(Instruction, |None| {}, { Add, Sub, Mul, Div })
/// ```
macro_rules! opcodes {
    ($_object:expr, |$_reader:ident| $_operation:block, { $( $variant:ident, )+ }) => { [$( $variant::<N>::opcode() ),+] }
}

impl<N: Network> Instruction<N> {
    /// The list of all instruction opcodes.
    pub const OPCODES: &'static [Opcode] = &instruction!(opcodes, Instruction, |None| {});

    /// Returns `true` if the given name is a reserved opcode.
    pub fn is_reserved_opcode(name: &str) -> bool {
        // Check if the given name matches any opcode (in its entirety; including past the first '.' if it exists).
        Instruction::<N>::OPCODES.iter().any(|opcode| **opcode == name)
    }

    /// Returns the operands of the instruction.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        instruction!(self, |instruction| instruction.operands())
    }

    /// Returns the destination registers of the instruction.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        instruction!(self, |instruction| instruction.destinations())
    }

    /// Returns the `CallOperator` if the instruction is a `call` instruction, otherwise `None`.
    #[inline]
    pub fn call_operator(&self) -> Option<&CallOperator<N>> {
        match self {
            Self::Call(call) => Some(call.operator()),
            _ => None,
        }
    }

    /// Returns the opcode of the instruction.
    #[inline]
    pub const fn opcode(&self) -> Opcode {
        instruction!(self, |InstructionMember| InstructionMember::<N>::opcode())
    }

    /// Evaluates the instruction.
    // Temporary until all instruction evaluate methods return EvalError (#2941, #3055).
    #[allow(clippy::useless_conversion)]
    #[inline]
    pub fn evaluate(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersSigner<N>,
    ) -> Result<(), EvalError> {
        instruction!(self, |instruction| instruction.evaluate(stack, registers).map_err(Into::into))
    }

    /// Executes the instruction.
    // Temporary until all instruction execute methods return ExecError (#2941, #3055).
    #[allow(clippy::useless_conversion)]
    #[inline]
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        stack: &impl StackTrait<N>,
        registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<(), ExecError> {
        instruction!(self, |instruction| instruction.execute::<A>(stack, registers).map_err(Into::into))
    }

    /// Finalizes the instruction.
    // Temporary until all instruction finalize methods return FinalizeError (#2941, #3055).
    #[allow(clippy::useless_conversion)]
    #[inline]
    pub fn finalize(
        &self,
        stack: &impl StackTrait<N>,
        store: Option<&dyn FinalizeStoreTrait<N>>,
        registers: &mut impl FinalizeRegistersState<N>,
    ) -> Result<(), FinalizeError> {
        instruction!(self, |instruction| instruction.finalize(stack, store, registers).map_err(Into::into))
    }

    /// Returns the output type from the given input types.
    #[inline]
    pub fn output_types(
        &self,
        stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        instruction!(self, |instruction| instruction.output_types(stack, input_types))
    }

    /// Returns whether this instruction refers to an external struct.
    pub fn contains_external_struct(&self) -> bool {
        instruction!(self, |instruction| instruction.contains_external_struct())
    }

    /// Returns `true` if the instruction contains a literal string type.
    pub fn contains_string_type(&self) -> bool {
        self.operands().iter().any(|operand| operand.contains_string_type())
    }

    /// Returns `true` if the instruction contains an identifier type in its type declarations.
    /// Checks cast destination types and serialize/deserialize operand/destination types.
    pub fn contains_identifier_type(&self) -> Result<bool> {
        match self {
            Self::Cast(instruction) => instruction.cast_type().contains_identifier_type(),
            Self::CastLossy(instruction) => instruction.cast_type().contains_identifier_type(),
            Self::SerializeBits(instruction) => instruction.operand_type().contains_identifier_type(),
            Self::SerializeBitsRaw(instruction) => instruction.operand_type().contains_identifier_type(),
            Self::DeserializeBits(instruction) => instruction.destination_type().contains_identifier_type(),
            Self::DeserializeBitsRaw(instruction) => instruction.destination_type().contains_identifier_type(),
            _ => Ok(false),
        }
    }

    /// Returns `true` if the instruction contains an array type with a size that exceeds the given maximum.
    pub fn exceeds_max_array_size(&self, max_array_size: u32) -> bool {
        // Only cast and serialize instructions may contain an explicit reference to an array.
        // Calls may produce them, but they don't explicitly reference the type.
        match self {
            Self::Cast(instruction) => instruction.cast_type().exceeds_max_array_size(max_array_size),
            Self::SerializeBits(instruction) => instruction.destination_type().exceeds_max_array_size(max_array_size),
            Self::SerializeBitsRaw(instruction) => {
                instruction.destination_type().exceeds_max_array_size(max_array_size)
            }
            Self::DeserializeBits(instruction) => instruction.operand_type().exceeds_max_array_size(max_array_size),
            Self::DeserializeBitsRaw(instruction) => instruction.operand_type().exceeds_max_array_size(max_array_size),
            _ => false,
        }
    }
}

impl<N: Network> Debug for Instruction<N> {
    /// Prints the instruction as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Instruction<N> {
    /// Prints the instruction as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        instruction!(self, |instruction| write!(f, "{instruction};"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_opcodes() {
        // Sanity check the number of instructions is unchanged.
        // Note that the number of opcodes **MUST NOT** exceed u16::MAX.
        assert_eq!(
            129,
            Instruction::<CurrentNetwork>::OPCODES.len(),
            "Update me if the number of instructions changes."
        );
    }
}
