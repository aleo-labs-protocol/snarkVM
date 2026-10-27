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

use core::fmt::Debug;
use snarkvm_utilities::{FromBytes, ToBytes, io_error};
use std::io;

/// A trait to specify the SNARK mode.
pub trait SNARKMode: 'static + Copy + Clone + Debug + PartialEq + Eq + Sync + Send {
    const ZK: bool;
}

/// This mode produces a hiding SNARK proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VarunaHidingMode;

impl SNARKMode for VarunaHidingMode {
    const ZK: bool = true;
}

/// This mode produces a non-hiding SNARK proof.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VarunaNonHidingMode;

impl SNARKMode for VarunaNonHidingMode {
    const ZK: bool = false;
}

/// The different Varuna Versions.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VarunaVersion {
    V1 = 1,
    V2 = 2,
    V3 = 3,
}

impl ToBytes for VarunaVersion {
    fn write_le<W: io::Write>(&self, writer: W) -> io::Result<()> {
        (*self as u8).write_le(writer)
    }
}

impl FromBytes for VarunaVersion {
    fn read_le<R: io::Read>(reader: R) -> io::Result<Self> {
        match u8::read_le(reader)? {
            0 => Err(io_error("Zero is not a valid Varuna version")),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            _ => Err(io_error("Invalid Varuna version")),
        }
    }
}
