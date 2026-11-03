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

use crate::prelude::*;
use snarkvm_utilities::{FromBytes, ToBytes, error};
use std::io::{Read, Result as IoResult, Write};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Constant,
    Public,
    Private,
}

impl Mode {
    /// Returns `true` if the mode is a constant.
    pub const fn is_constant(&self) -> bool {
        matches!(self, Self::Constant)
    }

    /// Returns `true` if the mode is public.
    pub const fn is_public(&self) -> bool {
        matches!(self, Self::Public)
    }

    /// Returns `true` if the mode is private.
    pub const fn is_private(&self) -> bool {
        matches!(self, Self::Private)
    }

    /// Parses a string into a mode.
    #[inline]
    pub fn parse(string: &str) -> ParserResult<'_, Self> {
        alt((
            map(tag("constant"), |_| Self::Constant),
            map(tag("public"), |_| Self::Public),
            map(tag("private"), |_| Self::Private),
        ))(string)
    }

    /// A static helper to deduce the mode from a list of modes.
    #[inline]
    pub fn combine<M: IntoIterator<Item = Mode>>(starting_mode: Mode, modes: M) -> Mode {
        // Initialize the current mode.
        let mut current_mode = starting_mode;
        // Intuition: Start from `Mode::Constant`, and see if one needs to lift to `Mode::Public` or `Mode::Private`.
        //   - If `current_mode == Mode::Constant`, then `current_mode = next_mode`.
        //   - If `current_mode == Mode::Public` && `next_mode == Mode::Private`, then `current_mode = next_mode`.
        //   - Otherwise, do nothing.
        for next_mode in modes {
            // If the current mode is `Mode::Private`, we can return early.
            if current_mode.is_private() {
                break;
            }
            // Check if the current mode matches the next mode.
            if current_mode != next_mode {
                match (current_mode, next_mode) {
                    (Mode::Constant, Mode::Public)
                    | (Mode::Constant, Mode::Private)
                    | (Mode::Public, Mode::Private) => current_mode = next_mode,
                    (_, _) => (), // Do nothing.
                }
            }
        }
        current_mode
    }
}

impl IntoIterator for Mode {
    type IntoIter = std::iter::Once<Self>;
    type Item = Mode;

    /// Returns an iterator over the mode.
    fn into_iter(self) -> Self::IntoIter {
        std::iter::once(self)
    }
}

impl FromStr for Mode {
    type Err = Error;

    /// Parses a string into a mode.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl Display for Mode {
    /// Formats the mode as a lowercase string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Constant => write!(f, "constant"),
            Self::Public => write!(f, "public"),
            Self::Private => write!(f, "private"),
        }
    }
}

impl ToBytes for Mode {
    /// Writes the mode to the writer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (*self as u8).write_le(&mut writer)
    }
}

impl FromBytes for Mode {
    /// Reads the mode from the reader.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let mode = u8::read_le(&mut reader)?;
        match mode {
            0 => Ok(Self::Constant),
            1 => Ok(Self::Public),
            2 => Ok(Self::Private),
            _ => Err(error("Invalid mode")),
        }
    }
}
