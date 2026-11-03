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

use std::{
    cell::Cell,
    fmt,
    io::{Read, Result as IoResult, Write},
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{
    Deserializer,
    Serializer,
    de::{self, Error, SeqAccess, Visitor},
    ser::{self, SerializeTuple},
};
use smol_str::SmolStr;

thread_local! {
    static UNCHECKED_DESERIALIZE: Cell<bool> = const { Cell::new(false) };
}

/// Performs a bincode deserialization without any checks of the data.
///
/// Important: This should only be used when deserializing from local storage.
#[inline(always)]
pub fn unchecked_deserialize<T: de::DeserializeOwned>(data: &[u8]) -> Result<T, bincode::Error> {
    UNCHECKED_DESERIALIZE.set(true);
    let result = bincode::deserialize(data);
    UNCHECKED_DESERIALIZE.set(false);
    result
}

/// Takes as input a sequence of structs, and converts them to a series of little-endian bytes.
/// All traits that implement `ToBytes` can be automatically converted to bytes in this manner.
#[macro_export]
macro_rules! to_bytes_le {
    ($($x:expr),*) => ({
        let mut buffer = vec![];
        buffer.reserve(64);
        {$crate::push_bytes_to_vec!(buffer, $($x),*)}.map(|_| buffer)
    });
}

#[macro_export]
macro_rules! push_bytes_to_vec {
    ($buffer:expr, $y:expr, $($x:expr),*) => ({
        {ToBytes::write_le(&$y, &mut $buffer)}.and({$crate::push_bytes_to_vec!($buffer, $($x),*)})
    });

    ($buffer:expr, $x:expr) => ({
        ToBytes::write_le(&$x, &mut $buffer)
    })
}

pub trait ToBytes {
    /// Writes `self` into `writer` as little-endian bytes.
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()>
    where
        Self: Sized;

    /// Returns `self` as a byte array in little-endian order.
    fn to_bytes_le(&self) -> anyhow::Result<Vec<u8>>
    where
        Self: Sized,
    {
        Ok(to_bytes_le![self]?)
    }
}

pub trait FromBytes {
    /// Reads `Self` from `reader` as little-endian bytes.
    fn read_le<R: Read>(reader: R) -> IoResult<Self>
    where
        Self: Sized;

    /// Returns `Self` from a byte array in little-endian order.
    fn from_bytes_le(bytes: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::read_le(bytes)?)
    }

    /// Same behavior as `Self::from_bytes_le` but avoids costly checks.
    /// This shall only be called when deserializing from a trusted source, such as local storage.
    ///
    /// Returns `Self` from a byte array in little-endian order.
    fn from_bytes_le_unchecked(bytes: &[u8]) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self::read_le_unchecked(bytes)?)
    }

    /// Same behavior as [`Self::read_le`] but avoids costly checks.
    /// This shall only be called when deserializing from a trusted source, such as local storage.
    ///
    /// The default implementation simply calls [`Self::read_le`].
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self>
    where
        Self: Sized,
    {
        Self::read_le(reader)
    }

    /// Helper function that deserializes either unchecked or checked based on the given boolean flag.
    fn read_le_with_unchecked<R: Read>(reader: R, unchecked: bool) -> IoResult<Self>
    where
        Self: Sized,
    {
        if unchecked { Self::read_le_unchecked(reader) } else { Self::read_le(reader) }
    }
}

/// Helper struct to serialize an object.
pub struct ToBytesSerializer<T: ToBytes>(PhantomData<T>);

impl<T: ToBytes> ToBytesSerializer<T> {
    /// Serializes a static-sized object as a byte array (without length encoding).
    pub fn serialize<S: Serializer>(object: &T, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = object.to_bytes_le().map_err(ser::Error::custom)?;
        let mut tuple = serializer.serialize_tuple(bytes.len())?;
        for byte in &bytes {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    /// Serializes a dynamically-sized object as a byte array with length encoding.
    pub fn serialize_with_size_encoding<S: Serializer>(object: &T, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = object.to_bytes_le().map_err(ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

pub struct FromBytesDeserializer<T: FromBytes>(PhantomData<T>);

impl<'de, T: FromBytes> FromBytesDeserializer<T> {
    /// Deserializes a static-sized byte array (without length encoding).
    ///
    /// This method fails if `deserializer` is given an insufficient `size`.
    pub fn deserialize<D: Deserializer<'de>>(deserializer: D, name: &str, size: usize) -> Result<T, D::Error> {
        let mut buffer = Vec::with_capacity(size);
        deserializer.deserialize_tuple(size, FromBytesVisitor::new(&mut buffer, name))?;
        FromBytes::read_le(&*buffer).map_err(de::Error::custom)
    }

    /// Deserializes a static-sized byte array, with a u8 length encoding at the start.
    pub fn deserialize_with_u8<D: Deserializer<'de>>(deserializer: D, name: &str) -> Result<T, D::Error> {
        deserializer.deserialize_tuple(1usize << 8usize, FromBytesWithU8Visitor::<T>::new(name))
    }

    /// Deserializes a static-sized byte array, with a u16 length encoding at the start.
    pub fn deserialize_with_u16<D: Deserializer<'de>>(deserializer: D, name: &str) -> Result<T, D::Error> {
        deserializer.deserialize_tuple(1usize << 16usize, FromBytesWithU16Visitor::<T>::new(name))
    }

    /// Deserializes a dynamically-sized byte array.
    pub fn deserialize_with_size_encoding<D: Deserializer<'de>>(deserializer: D, name: &str) -> Result<T, D::Error> {
        deserializer.deserialize_bytes(FromBytesValueVisitor::new(name, false))
    }

    /// Attempts to deserialize a byte array (without length encoding).
    ///
    /// This method does *not* fail if `deserializer` is given an insufficient `size`,
    /// however this method fails if `FromBytes` fails to read the value of `T`.
    pub fn deserialize_extended<D: Deserializer<'de>>(
        deserializer: D,
        name: &str,
        size_a: usize,
        size_b: usize,
    ) -> Result<T, D::Error> {
        // Order the given sizes from smallest to largest.
        let (size_a, size_b) = match size_a < size_b {
            true => (size_a, size_b),
            false => (size_b, size_a),
        };

        // Ensure 'size_b' is within bounds.
        if size_b > i32::MAX as usize {
            return Err(D::Error::custom(format!("size_b ({size_b}) exceeds maximum")));
        }

        // Reserve a new `Vec` with the larger size capacity.
        let mut buffer = Vec::with_capacity(size_b);

        // Attempt to deserialize on the larger size, to load up to the maximum buffer size.
        match deserializer.deserialize_tuple(size_b, FromBytesVisitor::new(&mut buffer, name)) {
            // Deserialized a full buffer, attempt to read up to `size_b`.
            Ok(()) => FromBytes::read_le(&buffer[..size_b]).map_err(de::Error::custom),
            // Deserialized a partial buffer, attempt to read up to `size_a`, if exactly `size_a` was read.
            Err(error) => match buffer.len() == size_a {
                true => FromBytes::read_le(&buffer[..size_a]).map_err(de::Error::custom),
                false => Err(error),
            },
        }
    }
}

pub struct FromBytesUncheckedDeserializer<T: FromBytes>(PhantomData<T>);

impl<'de, T: FromBytes> FromBytesUncheckedDeserializer<T> {
    /// Deserializes a dynamically-sized byte array.
    pub fn deserialize_with_size_encoding<D: Deserializer<'de>>(deserializer: D, name: &str) -> Result<T, D::Error> {
        deserializer.deserialize_bytes(FromBytesValueVisitor::new(name, UNCHECKED_DESERIALIZE.get()))
    }
}

struct FromBytesValueVisitor<T: FromBytes>(SmolStr, bool, PhantomData<T>);

impl<T: FromBytes> FromBytesValueVisitor<T> {
    fn new(name: &str, unchecked: bool) -> Self {
        Self(SmolStr::new(name), unchecked, PhantomData)
    }

    fn read<E: de::Error>(&self, bytes: &[u8]) -> Result<T, E> {
        FromBytes::read_le_with_unchecked(bytes, self.1).map_err(de::Error::custom)
    }
}

impl<'de, T: FromBytes> Visitor<'de> for FromBytesValueVisitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_fmt(format_args!("a valid {} ", self.0))
    }

    fn visit_borrowed_bytes<E: de::Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
        self.read(bytes)
    }

    fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        self.read(bytes)
    }

    fn visit_byte_buf<E: de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        self.read(&bytes)
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut bytes = Vec::with_capacity(32);
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        self.read(&bytes)
    }
}

pub struct FromBytesVisitor<'a>(&'a mut Vec<u8>, SmolStr);

impl<'a> FromBytesVisitor<'a> {
    /// Initializes a new `FromBytesVisitor` with the given `buffer` and `name`.
    pub fn new(buffer: &'a mut Vec<u8>, name: &str) -> Self {
        Self(buffer, SmolStr::new(name))
    }
}

impl<'de> Visitor<'de> for FromBytesVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&format!("a valid {} ", self.1))
    }

    fn visit_borrowed_bytes<E: serde::de::Error>(self, bytes: &'de [u8]) -> Result<Self::Value, E> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        while let Some(byte) = seq.next_element()? {
            self.0.push(byte);
        }
        Ok(())
    }
}

struct FromBytesWithU8Visitor<T: FromBytes>(String, PhantomData<T>);

impl<T: FromBytes> FromBytesWithU8Visitor<T> {
    /// Initializes a new `FromBytesWithU8Visitor` with the given `name`.
    pub fn new(name: &str) -> Self {
        Self(name.to_string(), PhantomData)
    }
}

impl<'de, T: FromBytes> Visitor<'de> for FromBytesWithU8Visitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&format!("a valid {} ", self.0))
    }

    fn visit_seq<V: SeqAccess<'de>>(self, mut seq: V) -> Result<Self::Value, V::Error> {
        // Read the size of the object.
        let length: u8 = seq.next_element()?.ok_or_else(|| Error::invalid_length(0, &self))?;

        // Initialize the vector with the correct length.
        let mut bytes: Vec<u8> = Vec::with_capacity((length as usize) + 1);
        // Push the length into the vector.
        bytes.push(length);
        // Read the bytes.
        for i in 0..length {
            // Push the next byte into the vector.
            bytes.push(seq.next_element()?.ok_or_else(|| Error::invalid_length((i as usize) + 1, &self))?);
        }
        // Deserialize the vector.
        FromBytes::read_le(&*bytes).map_err(de::Error::custom)
    }
}

struct FromBytesWithU16Visitor<T: FromBytes>(String, PhantomData<T>);

impl<T: FromBytes> FromBytesWithU16Visitor<T> {
    /// Initializes a new `FromBytesWithU16Visitor` with the given `name`.
    pub fn new(name: &str) -> Self {
        Self(name.to_string(), PhantomData)
    }
}

impl<'de, T: FromBytes> Visitor<'de> for FromBytesWithU16Visitor<T> {
    type Value = T;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(&format!("a valid {} ", self.0))
    }

    fn visit_seq<V: SeqAccess<'de>>(self, mut seq: V) -> Result<Self::Value, V::Error> {
        // Read the size of the object.
        let length: u16 = seq.next_element()?.ok_or_else(|| Error::invalid_length(0, &self))?;

        // Initialize the vector with the correct length.
        let mut bytes: Vec<u8> = Vec::with_capacity((length as usize) + 2);
        // Push the length into the vector.
        bytes.extend(length.to_le_bytes());
        // Read the bytes.
        for i in 0..length {
            // Push the next byte into the vector.
            bytes.push(seq.next_element()?.ok_or_else(|| Error::invalid_length((i as usize) + 2, &self))?);
        }
        // Deserialize the vector.
        FromBytes::read_le(&*bytes).map_err(de::Error::custom)
    }
}

impl ToBytes for () {
    #[inline]
    fn write_le<W: Write>(&self, _writer: W) -> IoResult<()> {
        Ok(())
    }
}

impl FromBytes for () {
    #[inline]
    fn read_le<R: Read>(_bytes: R) -> IoResult<Self> {
        Ok(())
    }
}

impl ToBytes for bool {
    #[inline]
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        u8::write_le(&(*self as u8), writer)
    }
}

impl FromBytes for bool {
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        match u8::read_le(reader) {
            Ok(0) => Ok(false),
            Ok(1) => Ok(true),
            Ok(_) => Err(std::io::Error::other("FromBytes::read failed")),
            Err(err) => Err(err),
        }
    }
}

impl ToBytes for SocketAddr {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the IP address.
        match self.ip() {
            IpAddr::V4(ipv4) => {
                0u8.write_le(&mut writer)?;
                u32::from(ipv4).write_le(&mut writer)?;
            }
            IpAddr::V6(ipv6) => {
                1u8.write_le(&mut writer)?;
                u128::from(ipv6).write_le(&mut writer)?;
            }
        }
        // Write the port.
        self.port().write_le(&mut writer)?;
        Ok(())
    }
}

impl FromBytes for SocketAddr {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the IP address.
        let ip = match u8::read_le(&mut reader)? {
            0 => IpAddr::V4(Ipv4Addr::from(u32::read_le(&mut reader)?)),
            1 => IpAddr::V6(Ipv6Addr::from(u128::read_le(&mut reader)?)),
            _ => return Err(std::io::Error::other("Invalid IP address")),
        };
        // Read the port.
        let port = u16::read_le(&mut reader)?;
        Ok(SocketAddr::new(ip, port))
    }
}

macro_rules! impl_bytes_for_integer {
    ($int:ty) => {
        impl ToBytes for $int {
            #[inline]
            fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
                writer.write_all(&self.to_le_bytes())
            }
        }

        impl FromBytes for $int {
            #[inline]
            fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
                let mut bytes = [0u8; core::mem::size_of::<$int>()];
                reader.read_exact(&mut bytes)?;
                Ok(<$int>::from_le_bytes(bytes))
            }
        }
    };
}

impl_bytes_for_integer!(u8);
impl_bytes_for_integer!(u16);
impl_bytes_for_integer!(u32);
impl_bytes_for_integer!(u64);
impl_bytes_for_integer!(u128);

impl_bytes_for_integer!(i8);
impl_bytes_for_integer!(i16);
impl_bytes_for_integer!(i32);
impl_bytes_for_integer!(i64);
impl_bytes_for_integer!(i128);

impl<const N: usize> ToBytes for [u8; N] {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        writer.write_all(self)
    }
}

impl<const N: usize> FromBytes for [u8; N] {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let mut arr = [0u8; N];
        reader.read_exact(&mut arr)?;
        Ok(arr)
    }
}

macro_rules! impl_bytes_for_integer_array {
    ($int:ty) => {
        impl<const N: usize> ToBytes for [$int; N] {
            #[inline]
            fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
                for num in self {
                    writer.write_all(&num.to_le_bytes())?;
                }
                Ok(())
            }
        }

        impl<const N: usize> FromBytes for [$int; N] {
            #[inline]
            fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
                let mut res: [$int; N] = [0; N];
                for num in res.iter_mut() {
                    let mut bytes = [0u8; core::mem::size_of::<$int>()];
                    reader.read_exact(&mut bytes)?;
                    *num = <$int>::from_le_bytes(bytes);
                }
                Ok(res)
            }
        }
    };
}

// u8 has a dedicated, faster implementation above
impl_bytes_for_integer_array!(u16);
impl_bytes_for_integer_array!(u32);
impl_bytes_for_integer_array!(u64);

impl<L: ToBytes, R: ToBytes> ToBytes for (L, R) {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.0.write_le(&mut writer)?;
        self.1.write_le(&mut writer)?;
        Ok(())
    }
}

impl<L: FromBytes, R: FromBytes> FromBytes for (L, R) {
    #[inline]
    fn read_le<Reader: Read>(mut reader: Reader) -> IoResult<Self> {
        let left: L = FromBytes::read_le(&mut reader)?;
        let right: R = FromBytes::read_le(&mut reader)?;
        Ok((left, right))
    }
}

impl<T: ToBytes> ToBytes for Vec<T> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        for item in self {
            item.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<'a, T: 'a + ToBytes> ToBytes for &'a [T] {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        for item in *self {
            item.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<'a, T: 'a + ToBytes> ToBytes for &'a T {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (*self).write_le(&mut writer)
    }
}

#[inline]
pub fn bits_from_bytes_le(bytes: &[u8]) -> impl DoubleEndedIterator<Item = bool> + '_ {
    bytes.iter().flat_map(|byte| (0..8).map(move |i| (*byte >> i) & 1 == 1))
}

#[inline]
pub fn bytes_from_bits_le(bits: &[bool]) -> Vec<u8> {
    let desired_size = if bits.len().is_multiple_of(8) { bits.len() / 8 } else { bits.len() / 8 + 1 };

    let mut bytes = Vec::with_capacity(desired_size);
    for bits in bits.chunks(8) {
        let mut result = 0u8;
        for (i, bit) in bits.iter().enumerate() {
            let bit_value = *bit as u8;
            result += bit_value << i as u8;
        }

        bytes.push(result);
    }

    bytes
}

/// A wrapper around a `Write` instance that limits the number of bytes that can be written.
pub struct LimitedWriter<W: Write> {
    writer: W,
    limit: usize,
    remaining: usize,
}

impl<W: Write> LimitedWriter<W> {
    pub fn new(writer: W, limit: usize) -> Self {
        Self { writer, limit, remaining: limit }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if self.remaining == 0 && !buf.is_empty() {
            return Err(std::io::Error::other(format!("Byte limit exceeded: {}", self.limit)));
        }

        let max_write = std::cmp::min(buf.len(), self.remaining);
        match self.writer.write(&buf[..max_write]) {
            Ok(n) => {
                self.remaining -= n;
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TestRng;

    use rand::RngExt;
    use serde::{Deserialize, Serialize};

    const ITERATIONS: usize = 1000;

    #[derive(Debug, Deserialize, PartialEq)]
    struct DeserializedBytes(#[serde(deserialize_with = "deserialize_bytes")] [u8; 4]);

    #[derive(Serialize)]
    struct SerializedBytes<'a>(#[serde(serialize_with = "serialize_bytes")] &'a [u8]);

    #[derive(Debug, PartialEq)]
    struct UncheckedBytes([u8; 4]);

    impl FromBytes for UncheckedBytes {
        fn read_le<R: Read>(_reader: R) -> IoResult<Self> {
            Err(std::io::Error::other("checked deserialization"))
        }

        fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
            Ok(Self(FromBytes::read_le(reader)?))
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct UncheckedDeserializedBytes(#[serde(deserialize_with = "deserialize_unchecked_bytes")] UncheckedBytes);

    fn deserialize_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 4], D::Error> {
        FromBytesDeserializer::deserialize_with_size_encoding(deserializer, "bytes")
    }

    fn serialize_bytes<S: Serializer>(bytes: &&[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    fn deserialize_unchecked_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<UncheckedBytes, D::Error> {
        FromBytesUncheckedDeserializer::deserialize_with_size_encoding(deserializer, "bytes")
    }

    #[test]
    fn test_deserialize_with_size_encoding() -> anyhow::Result<()> {
        let expected = [1, 2, 3, 4];

        let bincode = bincode::serialize(&SerializedBytes(&expected))?;
        assert_eq!(bincode::deserialize::<DeserializedBytes>(&bincode)?, DeserializedBytes(expected));

        let json = serde_json::to_string(&SerializedBytes(&expected))?;
        assert_eq!(serde_json::from_str::<DeserializedBytes>(&json)?, DeserializedBytes(expected));

        Ok(())
    }

    #[test]
    fn test_deserialize_with_size_encoding_unchecked() -> anyhow::Result<()> {
        let expected = [1, 2, 3, 4];
        let bincode = bincode::serialize(&SerializedBytes(&expected))?;

        assert!(bincode::deserialize::<UncheckedDeserializedBytes>(&bincode).is_err());
        assert_eq!(
            unchecked_deserialize::<UncheckedDeserializedBytes>(&bincode)?,
            UncheckedDeserializedBytes(UncheckedBytes(expected))
        );

        Ok(())
    }

    #[test]
    fn test_macro_empty() {
        let array: Vec<u8> = vec![];
        let bytes_a: Vec<u8> = to_bytes_le![array].unwrap();
        assert_eq!(&array, &bytes_a);
        assert_eq!(0, bytes_a.len());

        let bytes_b: Vec<u8> = array.to_bytes_le().unwrap();
        assert_eq!(&array, &bytes_b);
        assert_eq!(0, bytes_b.len());
    }

    #[test]
    fn test_macro() {
        let array1 = [1u8; 32];
        let array2 = [2u8; 16];
        let array3 = [3u8; 8];
        let bytes = to_bytes_le![array1, array2, array3].unwrap();
        assert_eq!(bytes.len(), 56);

        let mut actual_bytes = Vec::new();
        actual_bytes.extend_from_slice(&array1);
        actual_bytes.extend_from_slice(&array2);
        actual_bytes.extend_from_slice(&array3);
        assert_eq!(bytes, actual_bytes);
    }

    #[test]
    fn test_bits_from_bytes_le() {
        assert_eq!(bits_from_bytes_le(&[204, 76]).collect::<Vec<bool>>(), [
            false, false, true, true, false, false, true, true, // 204
            false, false, true, true, false, false, true, false, // 76
        ]);
    }

    #[test]
    fn test_bytes_from_bits_le() {
        let bits = [
            false, false, true, true, false, false, true, true, // 204
            false, false, true, true, false, false, true, false, // 76
        ];
        assert_eq!(bytes_from_bits_le(&bits), [204, 76]);
    }

    #[test]
    fn test_from_bits_le_to_bytes_le_roundtrip() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let given_bytes: [u8; 32] = rng.random();

            let bits = bits_from_bytes_le(&given_bytes).collect::<Vec<_>>();
            let recovered_bytes = bytes_from_bits_le(&bits);

            assert_eq!(given_bytes.to_vec(), recovered_bytes);
        }
    }

    #[test]
    fn test_socketaddr_bytes() {
        fn random_ipv4_address(rng: &mut TestRng) -> Ipv4Addr {
            Ipv4Addr::new(rng.random(), rng.random(), rng.random(), rng.random())
        }

        fn random_ipv6_address(rng: &mut TestRng) -> Ipv6Addr {
            Ipv6Addr::new(
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
                rng.random(),
            )
        }

        fn random_port(rng: &mut TestRng) -> u16 {
            rng.random_range(1025..=65535) // excluding well-known ports
        }

        let rng = &mut TestRng::default();

        for _ in 0..1_000_000 {
            let ipv4 = SocketAddr::new(IpAddr::V4(random_ipv4_address(rng)), random_port(rng));
            let bytes = ipv4.to_bytes_le().unwrap();
            let ipv4_2 = SocketAddr::read_le(&bytes[..]).unwrap();
            assert_eq!(ipv4, ipv4_2);

            let ipv6 = SocketAddr::new(IpAddr::V6(random_ipv6_address(rng)), random_port(rng));
            let bytes = ipv6.to_bytes_le().unwrap();
            let ipv6_2 = SocketAddr::read_le(&bytes[..]).unwrap();
            assert_eq!(ipv6, ipv6_2);
        }
    }
}
