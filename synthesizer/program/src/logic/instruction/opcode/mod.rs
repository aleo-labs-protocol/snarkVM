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

use console::network::prelude::*;

/// The `Opcode` enum stores the mnemonic for the instruction.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// The opcode is for an assert operation (i.e. `assert`).
    Assert(&'static str),
    /// The opcode is for an async call operation (i.e. `async`).
    Async,
    /// The opcode is for a call operation (i.e. `call`).
    Call(&'static str),
    /// The opcode is for a cast operation (i.e. `cast`).
    Cast(&'static str),
    /// The opcode is for a finalize command (i.e. `increment`).
    Command(&'static str),
    /// The opcode is for a commit operation (i.e. `commit.psd4`).
    Commit(&'static str),
    /// The opcdode is a for a deserialize operation (i.e. `deserialize.bytes.raw`).
    Deserialize(&'static str),
    /// The opcode is for ECDSA signature verification (i.e. `ecdsa.verify.keccak`).
    ECDSA(&'static str),
    /// The opcode is for a get.record.dynamic operation (i.e. `get.record.dynamic`).
    GetRecordDynamic(&'static str),
    /// The opcode is for a hash operation (i.e. `hash.psd4`).
    Hash(&'static str),
    /// The opcode is for an 'is' operation (i.e. `is.eq`).
    Is(&'static str),
    /// The opcode is for a literal operation (i.e. `add`).
    Literal(&'static str),
    /// The opcode is for a serialize operation. (i.e. `serialize.bytes.raw`).
    Serialize(&'static str),
    /// The opcode is for signature verification (i.e. `sign.verify`).
    Sign(&'static str),
    /// The opcode is for snark verification (i.e. `snark.verify`).
    Snark(&'static str),
}

impl Deref for Opcode {
    type Target = &'static str;

    /// Returns the opcode as a string.
    fn deref(&self) -> &Self::Target {
        match self {
            Opcode::Assert(opcode) => opcode,
            Opcode::Async => &"async",
            Opcode::Call(opcode) => opcode,
            Opcode::Cast(opcode) => opcode,
            Opcode::Command(opcode) => opcode,
            Opcode::Commit(opcode) => opcode,
            Opcode::Deserialize(opcode) => opcode,
            Opcode::ECDSA(opcode) => opcode,
            Opcode::GetRecordDynamic(opcode) => opcode,
            Opcode::Hash(opcode) => opcode,
            Opcode::Is(opcode) => opcode,
            Opcode::Literal(opcode) => opcode,
            Opcode::Serialize(opcode) => opcode,
            Opcode::Sign(opcode) => opcode,
            Opcode::Snark(opcode) => opcode,
        }
    }
}

impl Debug for Opcode {
    /// Prints the opcode as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for Opcode {
    /// Prints the opcode as a string, i.e. `add`.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::Assert(opcode) => write!(f, "{opcode}"),
            Self::Async => write!(f, "{}", self.deref()),
            Self::Call(opcode) => write!(f, "{opcode}"),
            Self::Cast(opcode) => write!(f, "{opcode}"),
            Self::Command(opcode) => write!(f, "{opcode}"),
            Self::Commit(opcode) => write!(f, "{opcode}"),
            Self::Deserialize(opcode) => write!(f, "{opcode}"),
            Self::ECDSA(opcode) => write!(f, "{opcode}"),
            Self::GetRecordDynamic(opcode) => write!(f, "{opcode}"),
            Self::Hash(opcode) => write!(f, "{opcode}"),
            Self::Is(opcode) => write!(f, "{opcode}"),
            Self::Literal(opcode) => write!(f, "{opcode}"),
            Self::Serialize(opcode) => write!(f, "{opcode}"),
            Self::Sign(opcode) => write!(f, "{opcode}"),
            Self::Snark(opcode) => write!(f, "{opcode}"),
        }
    }
}
