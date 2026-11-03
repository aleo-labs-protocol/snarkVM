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

static VERIFYING_KEY: &str = "verifier";

impl<N: Network> Parser for VerifyingKey<N> {
    /// Parses a string into the verifying key.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo verifying key.
        let parse_key = recognize(pair(
            pair(tag(VERIFYING_KEY), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the verifying key from the string.
        map_res(parse_key, |key: &str| -> Result<_, Error> { Self::from_str(&key.replace('_', "")) })(string)
    }
}

impl<N: Network> FromStr for VerifyingKey<N> {
    type Err = Error;

    /// Reads in the verifying key string.
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        // Decode the verifying key string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(key)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != VERIFYING_KEY {
            bail!("Failed to decode verifying key: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode verifying key: data field is empty")
        }
        // Decode the verifying key data into the verifying key.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for VerifyingKey<N> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for VerifyingKey<N> {
    /// Writes the verifying key as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the verifying key to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(VERIFYING_KEY), &bytes)
            .map_err(|_| fmt::Error)?;
        // Output the string.
        Display::fmt(&string, f)
    }
}
