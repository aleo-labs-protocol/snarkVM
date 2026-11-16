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

use snarkvm_console_network::prelude::*;

/// A helper enum for the visibility of an entry.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum PublicOrPrivate {
    Public,
    Private,
}

impl PublicOrPrivate {
    /// Returns `true` if the entry is public.
    pub const fn is_public(&self) -> bool {
        matches!(self, PublicOrPrivate::Public)
    }

    /// Returns `true` if the entry is private.
    pub const fn is_private(&self) -> bool {
        matches!(self, PublicOrPrivate::Private)
    }
}

impl FromBytes for PublicOrPrivate {
    /// Reads the visibility from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the indicator for the visibility. Only the two bytes `write_le` produces are
        // accepted, so that each record type has exactly one encoding.
        match u8::read_le(&mut reader)? {
            0 => Ok(PublicOrPrivate::Public),
            1 => Ok(PublicOrPrivate::Private),
            indicator => Err(error(format!("Invalid visibility indicator '{indicator}'"))),
        }
    }
}

impl ToBytes for PublicOrPrivate {
    /// Writes the visibility to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the indicator for the visibility.
        (*self as u8).write_le(&mut writer)
    }
}

impl Debug for PublicOrPrivate {
    /// Prints the visibility as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for PublicOrPrivate {
    /// Prints the visibility as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            PublicOrPrivate::Public => write!(f, "public"),
            PublicOrPrivate::Private => write!(f, "private"),
        }
    }
}
