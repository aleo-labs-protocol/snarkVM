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

pub trait Bech32Object<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send>:
    From<T>
    + Deref<Target = T>
    + Clone
    + Debug
    + Display
    + ToBytes
    + FromBytes
    + PartialEq
    + Eq
    + Serialize
    + DeserializeOwned
    + Sync
    + Send
{
    fn prefix() -> String;
}

/// Converts a string of 4 characters into a `u32` for a human-readable prefix in Bech32.
#[macro_export]
macro_rules! hrp4 {
    ( $persona: expr ) => {{
        $crate::const_assert!($persona.len() == 4);
        let p = $persona.as_bytes();
        u32::from_le_bytes([p[0], p[1], p[2], p[3]])
    }};
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AleoObject<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32>(T);

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Bech32Object<T>
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn prefix() -> String {
        String::from_utf8(PREFIX.to_le_bytes().to_vec()).expect("Failed to convert prefix to string")
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> From<T>
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn from(data: T) -> Self {
        Self(data)
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> FromBytes
    for AleoObject<T, PREFIX>
{
    /// Reads data into a buffer.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Ok(Self(FromBytes::read_le(&mut reader)?))
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> ToBytes
    for AleoObject<T, PREFIX>
{
    /// Writes the data to a buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write_le(&mut writer)
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> FromStr
    for AleoObject<T, PREFIX>
{
    type Err = Error;

    /// Reads in a bech32m string.
    #[inline]
    fn from_str(string: &str) -> Result<Self, Self::Err> {
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

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Display
    for AleoObject<T, PREFIX>
{
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

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Debug
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "AleoObject {{ hrp: {:?}, data: {:?} }}", &Self::prefix(), self.0)
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Serialize
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => serializer.collect_str(self),
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Deserialize<'de>
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => FromStr::from_str(&String::deserialize(deserializer)?).map_err(de::Error::custom),
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, &Self::prefix()),
        }
    }
}

impl<T: Default + Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Default
    for AleoObject<T, PREFIX>
{
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Deref
    for AleoObject<T, PREFIX>
{
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Clone + Debug + ToBytes + FromBytes + PartialEq + Eq + Sync + Send, const PREFIX: u32> Borrow<T>
    for AleoObject<T, PREFIX>
{
    #[inline]
    fn borrow(&self) -> &T {
        &self.0
    }
}
