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

use snarkvm_utilities::{FromBytes, error};
use std::io::{Read, Result as IoResult};

/// Returns the variable length integer of the given value.
/// <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
pub fn variable_length_integer(value: &u64) -> Vec<u8> {
    match value {
        // bounded by u8::max_value()
        #[allow(clippy::cast_possible_truncation)]
        0..=252 => vec![*value as u8],
        // bounded by u16::max_value()
        #[allow(clippy::cast_possible_truncation)]
        253..=65535 => [vec![0xfd], (*value as u16).to_le_bytes().to_vec()].concat(),
        // bounded by u32::max_value()
        #[allow(clippy::cast_possible_truncation)]
        65536..=4_294_967_295 => [vec![0xfe], (*value as u32).to_le_bytes().to_vec()].concat(),
        // bounded by u64::max_value()
        _ => [vec![0xff], value.to_le_bytes().to_vec()].concat(),
    }
}

/// Decode the value of a variable length integer.
/// <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer>
pub fn read_variable_length_integer<R: Read>(mut reader: R) -> IoResult<u64> {
    let flag = u8::read_le(&mut reader)?;

    match flag {
        0..=252 => Ok(flag as u64),
        0xfd => match u16::read_le(&mut reader)? {
            s if s < 253 => Err(error("Invalid variable size integer")),
            s => Ok(s as u64),
        },
        0xfe => match u32::read_le(&mut reader)? {
            s if s < 65536 => Err(error("Invalid variable size integer")),
            s => Ok(s as u64),
        },
        _ => match u64::read_le(&mut reader)? {
            s if s < 4_294_967_296 => Err(error("Invalid variable size integer")),
            s => Ok(s),
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const LENGTH_VALUES: [(u64, [u8; 9]); 14] = [
        (20, [0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (32, [0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (200, [0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (252, [0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (253, [0xfd, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (40000, [0xfd, 0x40, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (65535, [0xfd, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (65536, [0xfe, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
        (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
        (2000000000, [0xfe, 0x00, 0x94, 0x35, 0x77, 0x00, 0x00, 0x00, 0x00]),
        (4294967295, [0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
        (4294967296, [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
        (500000000000000000, [0xff, 0x00, 0x00, 0xb2, 0xd3, 0x59, 0x5b, 0xf0, 0x06]),
        (18446744073709551615, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
    ];

    #[test]
    fn test_variable_length_integer() {
        LENGTH_VALUES.iter().for_each(|(size, expected_output)| {
            let variable_length_int = variable_length_integer(size);
            let pruned_expected_output = &expected_output[..variable_length_int.len()];
            assert_eq!(pruned_expected_output, &variable_length_int[..]);
        });
    }

    #[test]
    fn test_read_variable_length_integer() {
        LENGTH_VALUES.iter().for_each(|(expected_size, _expected_output)| {
            let variable_length_int = variable_length_integer(expected_size);
            let size = read_variable_length_integer(&variable_length_int[..]).unwrap();
            assert_eq!(*expected_size, size);
        });
    }
}
