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

use anyhow::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::borrow::Borrow;

pub trait Bech32ID<F: FieldTrait>:
    From<F>
    + Deref<Target = F>
    + Into<Vec<F>>
    + Uniform
    + Copy
    + Clone
    + Default
    + Debug
    + Display
    + FromStr
    + ToBytes
    + FromBytes
    + Serialize
    + DeserializeOwned
    + PartialEq
    + Eq
    + core::hash::Hash
    + Sync
    + Send
{
    fn prefix() -> String;
    fn size_in_bytes() -> usize;
    fn number_of_data_characters() -> usize;
}

#[rustfmt::skip]
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(,)*) => {
        pub const ASSERT: [(); 1] = [()];
        pub const fn bool_assert(x: bool) -> bool { x }
        let _ = ASSERT[!bool_assert($x) as usize];
    };
}

/// Converts a string of 2 characters into a `u16` for a human-readable prefix in Bech32.
#[macro_export]
macro_rules! hrp2 {
    ( $persona: expr ) => {{
        const_assert!($persona.len() == 2);
        let p = $persona.as_bytes();
        u16::from_le_bytes([p[0], p[1]])
    }};
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct AleoID<F: FieldTrait, const PREFIX: u16>(F);

impl<F: FieldTrait, const PREFIX: u16> Bech32ID<F> for AleoID<F, PREFIX> {
    #[inline]
    fn prefix() -> String {
        String::from_utf8(PREFIX.to_le_bytes().to_vec()).expect("Failed to convert prefix to string")
    }

    #[inline]
    fn size_in_bytes() -> usize {
        F::size_in_bits().div_ceil(8)
    }

    #[inline]
    fn number_of_data_characters() -> usize {
        (Self::size_in_bytes() * 8).div_ceil(5)
    }
}

impl<F: FieldTrait, const PREFIX: u16> From<F> for AleoID<F, PREFIX> {
    #[inline]
    fn from(data: F) -> Self {
        Self(data)
    }
}

impl<F: FieldTrait, const PREFIX: u16> Default for AleoID<F, PREFIX> {
    #[inline]
    fn default() -> Self {
        Self(F::zero())
    }
}

impl<F: FieldTrait, const PREFIX: u16> FromBytes for AleoID<F, PREFIX> {
    /// Reads data into a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Ok(Self(F::read_le(&mut reader)?))
    }
}

impl<F: FieldTrait, const PREFIX: u16> ToBytes for AleoID<F, PREFIX> {
    /// Writes the data to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write_le(&mut writer)
    }
}

impl<F: FieldTrait, const PREFIX: u16> FromStr for AleoID<F, PREFIX> {
    type Err = Error;

    /// Reads in a bech32m string.
    #[inline]
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        const CHECKSUM_STRING_LENGTH: usize = 6;
        if string.len() != 3 + Self::number_of_data_characters() + CHECKSUM_STRING_LENGTH {
            bail!("Invalid byte size for a bech32m hash: {} bytes", string.len())
        }

        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(string)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_bytes() != PREFIX.to_le_bytes() {
            bail!("Invalid prefix for a bech32m hash: {hrp}")
        };
        if data.is_empty() {
            bail!("Bech32m hash data is empty")
        }
        Ok(Self::read_le(&*data)?)
    }
}

impl<F: FieldTrait, const PREFIX: u16> Display for AleoID<F, PREFIX> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        bech32::encode_to_fmt::<LongBech32m, _>(
            f,
            bech32::Hrp::parse_unchecked(&Self::prefix()),
            &self.0.to_bytes_le().expect("Failed to write data as bytes"),
        )
        .map_err(|_| fmt::Error)
    }
}

impl<F: FieldTrait, const PREFIX: u16> Debug for AleoID<F, PREFIX> {
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "AleoLocator {{ hrp: {:?}, data: {:?} }}", &Self::prefix(), self.0)
    }
}

impl<F: FieldTrait, const PREFIX: u16> Serialize for AleoID<F, PREFIX> {
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => serializer.collect_str(self),
            false => ToBytesSerializer::serialize(self, serializer),
        }
    }
}

impl<'de, F: FieldTrait, const PREFIX: u16> Deserialize<'de> for AleoID<F, PREFIX> {
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => FromStr::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom),
            false => FromBytesDeserializer::<Self>::deserialize(deserializer, &Self::prefix(), Self::size_in_bytes()),
        }
    }
}

impl<F: FieldTrait, const PREFIX: u16> Deref for AleoID<F, PREFIX> {
    type Target = F;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: FieldTrait, const PREFIX: u16> Borrow<F> for AleoID<F, PREFIX> {
    #[inline]
    fn borrow(&self) -> &F {
        &self.0
    }
}

#[allow(clippy::from_over_into)]
impl<F: FieldTrait, const PREFIX: u16> Into<Vec<F>> for AleoID<F, PREFIX> {
    #[inline]
    fn into(self) -> Vec<F> {
        vec![self.0]
    }
}

impl<F: FieldTrait, const PREFIX: u16> Distribution<AleoID<F, PREFIX>> for StandardUniform {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> AleoID<F, PREFIX> {
        AleoID::<F, PREFIX>(Uniform::rand(rng))
    }
}
