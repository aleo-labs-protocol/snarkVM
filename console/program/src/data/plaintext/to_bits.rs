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

use super::*;

impl<N: Network> Plaintext<N> {
    /// Writes this plaintext as little-endian bits, or returns an error when a length prefix does not fit.
    pub fn try_write_bits_le(&self, vec: &mut Vec<bool>) -> Result<()> {
        match self {
            Self::Literal(literal, bits_le) => {
                let bits = bits_le.get_or_init(|| {
                    let mut bits_le = PlaintextType::<N>::LITERAL_PREFIX_BITS.to_vec(); // Variant bits.
                    literal.variant().write_bits_le(&mut bits_le);
                    literal.size_in_bits().write_bits_le(&mut bits_le);
                    literal.write_bits_le(&mut bits_le);
                    bits_le
                });
                vec.extend_from_slice(bits);
                Ok(())
            }
            Self::Struct(struct_, bits_le) => {
                let bits = match bits_le.get() {
                    Some(bits) => bits,
                    None => {
                        let computed = Self::encode_struct_bits_le(struct_)?;
                        let _ = bits_le.set(computed);
                        // The cache holds this encoding, or one computed concurrently.
                        bits_le.get().ok_or_else(|| anyhow!("Plaintext struct bits were unset after encoding"))?
                    }
                };
                vec.extend_from_slice(bits);
                Ok(())
            }
            Self::Array(array, bits_le) => {
                let bits = match bits_le.get() {
                    Some(bits) => bits,
                    None => {
                        let computed = Self::encode_array_bits_le(array)?;
                        let _ = bits_le.set(computed);
                        // The cache holds this encoding, or one computed concurrently.
                        bits_le.get().ok_or_else(|| anyhow!("Plaintext array bits were unset after encoding"))?
                    }
                };
                vec.extend_from_slice(bits);
                Ok(())
            }
        }
    }

    /// Returns this plaintext as little-endian bits, or an error when a length prefix does not fit.
    pub fn try_to_bits_le(&self) -> Result<Vec<bool>> {
        let mut bits = Vec::new();
        self.try_write_bits_le(&mut bits)?;
        Ok(bits)
    }

    /// Writes this plaintext as big-endian bits, or returns an error when a length prefix does not fit.
    pub fn try_write_bits_be(&self, vec: &mut Vec<bool>) -> Result<()> {
        match self {
            Self::Literal(literal, bits_be) => {
                let bits = bits_be.get_or_init(|| {
                    let mut bits_be = PlaintextType::<N>::LITERAL_PREFIX_BITS.to_vec(); // Variant bits.
                    literal.variant().write_bits_be(&mut bits_be);
                    literal.size_in_bits().write_bits_be(&mut bits_be);
                    literal.write_bits_be(&mut bits_be);
                    bits_be
                });
                vec.extend_from_slice(bits);
                Ok(())
            }
            Self::Struct(struct_, bits_be) => {
                let bits = match bits_be.get() {
                    Some(bits) => bits,
                    None => {
                        let computed = Self::encode_struct_bits_be(struct_)?;
                        let _ = bits_be.set(computed);
                        // The cache holds this encoding, or one computed concurrently.
                        bits_be.get().ok_or_else(|| anyhow!("Plaintext struct bits were unset after encoding"))?
                    }
                };
                vec.extend_from_slice(bits);
                Ok(())
            }
            Self::Array(array, bits_be) => {
                let bits = match bits_be.get() {
                    Some(bits) => bits,
                    None => {
                        let computed = Self::encode_array_bits_be(array)?;
                        let _ = bits_be.set(computed);
                        // The cache holds this encoding, or one computed concurrently.
                        bits_be.get().ok_or_else(|| anyhow!("Plaintext array bits were unset after encoding"))?
                    }
                };
                vec.extend_from_slice(bits);
                Ok(())
            }
        }
    }

    /// Returns this plaintext as big-endian bits, or an error when a length prefix does not fit.
    pub fn try_to_bits_be(&self) -> Result<Vec<bool>> {
        let mut bits = Vec::new();
        self.try_write_bits_be(&mut bits)?;
        Ok(bits)
    }

    /// Encodes a plaintext struct as little-endian bits.
    fn encode_struct_bits_le(struct_: &IndexMap<Identifier<N>, Self>) -> Result<Vec<bool>> {
        let mut bits_le = PlaintextType::<N>::STRUCT_PREFIX_BITS.to_vec(); // Variant bits.

        // Write the length of the struct.
        u8::try_from(struct_.len())
            .map_err(|error| anyhow!("Plaintext struct length exceeds u8::MAX: {error}"))?
            .write_bits_le(&mut bits_le);

        // Write each member of the struct.
        for (identifier, value) in struct_ {
            // Write the identifier of the member.
            identifier.size_in_bits().write_bits_le(&mut bits_le);
            identifier.write_bits_le(&mut bits_le);

            // Write the value of the member.
            let value_bits = value.try_to_bits_le()?;
            u16::try_from(value_bits.len())
                .map_err(|error| anyhow!("Plaintext member exceeds u16::MAX bits: {error}"))?
                .write_bits_le(&mut bits_le);
            bits_le.extend_from_slice(&value_bits);
        }
        Ok(bits_le)
    }

    /// Encodes a plaintext array as little-endian bits.
    fn encode_array_bits_le(array: &[Self]) -> Result<Vec<bool>> {
        let mut bits_le = PlaintextType::<N>::ARRAY_PREFIX_BITS.to_vec(); // Variant bits.

        // Write the length of the array.
        u32::try_from(array.len())
            .map_err(|error| anyhow!("Plaintext array length exceeds u32::MAX: {error}"))?
            .write_bits_le(&mut bits_le);

        // Write each element of the array.
        for element in array {
            let element_bits = element.try_to_bits_le()?;

            // Write the size of the element.
            u16::try_from(element_bits.len())
                .map_err(|error| anyhow!("Plaintext element exceeds u16::MAX bits: {error}"))?
                .write_bits_le(&mut bits_le);

            // Write the element.
            bits_le.extend(element_bits);
        }
        Ok(bits_le)
    }

    /// Encodes a plaintext struct as big-endian bits.
    fn encode_struct_bits_be(struct_: &IndexMap<Identifier<N>, Self>) -> Result<Vec<bool>> {
        let mut bits_be = PlaintextType::<N>::STRUCT_PREFIX_BITS.to_vec(); // Variant bits.

        // Write the length of the struct.
        u8::try_from(struct_.len())
            .map_err(|error| anyhow!("Plaintext struct length exceeds u8::MAX: {error}"))?
            .write_bits_be(&mut bits_be);

        // Write each member of the struct.
        for (identifier, value) in struct_ {
            // Write the identifier of the member.
            identifier.size_in_bits().write_bits_be(&mut bits_be);
            identifier.write_bits_be(&mut bits_be);

            // Write the value of the member.
            let value_bits = value.try_to_bits_be()?;
            u16::try_from(value_bits.len())
                .map_err(|error| anyhow!("Plaintext member exceeds u16::MAX bits: {error}"))?
                .write_bits_be(&mut bits_be);
            bits_be.extend_from_slice(&value_bits);
        }
        Ok(bits_be)
    }

    /// Encodes a plaintext array as big-endian bits.
    fn encode_array_bits_be(array: &[Self]) -> Result<Vec<bool>> {
        let mut bits_be = PlaintextType::<N>::ARRAY_PREFIX_BITS.to_vec(); // Variant bits.

        // Write the length of the array.
        u32::try_from(array.len())
            .map_err(|error| anyhow!("Plaintext array length exceeds u32::MAX: {error}"))?
            .write_bits_be(&mut bits_be);

        // Write each element of the array.
        for element in array {
            let element_bits = element.try_to_bits_be()?;

            // Write the size of the element.
            u16::try_from(element_bits.len())
                .map_err(|error| anyhow!("Plaintext element exceeds u16::MAX bits: {error}"))?
                .write_bits_be(&mut bits_be);

            // Write the element.
            bits_be.extend(element_bits);
        }
        Ok(bits_be)
    }
}

impl<N: Network> ToBits for Plaintext<N> {
    /// Returns this plaintext as a list of **little-endian** bits.
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        self.try_write_bits_le(vec).unwrap_or_else(|error| N::halt(error.to_string()));
    }

    /// Returns this plaintext as a list of **big-endian** bits.
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        self.try_write_bits_be(vec).unwrap_or_else(|error| N::halt(error.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Entry;
    use snarkvm_console_network::MainnetV0;

    use core::str::FromStr;

    type CurrentNetwork = MainnetV0;

    /// The largest number of `u64` elements whose array encoding fits in a `u16` length prefix.
    /// Each element takes 106 bits and the array header takes 34 bits.
    const MAX_NESTED_U64S: usize = 617;

    /// Returns an array of `num_elements` `u64`s.
    fn u64_array(num_elements: usize) -> Plaintext<CurrentNetwork> {
        Plaintext::Array(
            (0..num_elements).map(|_| Plaintext::from(Literal::U64(U64::new(1)))).collect(),
            Default::default(),
        )
    }

    /// Returns `inner` nested as an array element and as a struct member.
    fn nest(inner: Plaintext<CurrentNetwork>) -> [Plaintext<CurrentNetwork>; 2] {
        let mut members = IndexMap::new();
        members.insert(Identifier::from_str("inner").unwrap(), inner.clone());
        [Plaintext::Array(vec![inner], Default::default()), Plaintext::Struct(members, Default::default())]
    }

    #[test]
    fn test_try_to_bits_accepts_nested_values_at_the_size_limit() {
        let inner = u64_array(MAX_NESTED_U64S);
        assert_eq!(inner.try_to_bits_le().unwrap().len(), 65_436);

        for plaintext in nest(inner) {
            assert_eq!(plaintext.try_to_bits_le().unwrap(), plaintext.to_bits_le());
            assert_eq!(plaintext.try_to_bits_be().unwrap(), plaintext.to_bits_be());
        }
    }

    #[test]
    fn test_try_to_bits_rejects_nested_values_over_the_size_limit() {
        let inner = u64_array(MAX_NESTED_U64S + 1);
        assert_eq!(inner.try_to_bits_le().unwrap().len(), 65_542);

        for plaintext in nest(inner) {
            assert!(plaintext.try_to_bits_le().is_err());
            // A failed encoding is not cached, so it fails again.
            assert!(plaintext.try_to_bits_le().is_err());
            assert!(plaintext.try_to_bits_be().is_err());
            assert!(plaintext.to_fields().is_err());
            assert!(plaintext.size_in_fields().is_err());
            assert!(Entry::Private(plaintext).to_fields().is_err());
        }
    }
}
