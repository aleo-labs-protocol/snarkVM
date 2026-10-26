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

static RECORD_CIPHERTEXT_PREFIX: &str = "record";

impl<N: Network> Parser for Record<N, Ciphertext<N>> {
    /// Parses a string into an ciphertext.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the record ciphertext.
        let parse_record_ciphertext = recognize(pair(
            pair(tag(RECORD_CIPHERTEXT_PREFIX), tag("1")),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the record ciphertext from the string.
        map_res(parse_record_ciphertext, |record_ciphertext: &str| -> Result<_, Error> {
            Self::from_str(&record_ciphertext.replace('_', ""))
        })(string)
    }
}

impl<N: Network> FromStr for Record<N, Ciphertext<N>> {
    type Err = Error;

    /// Reads in the ciphertext string.
    fn from_str(ciphertext: &str) -> Result<Self, Self::Err> {
        // Decode the ciphertext string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(ciphertext)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != RECORD_CIPHERTEXT_PREFIX {
            bail!("Failed to decode record ciphertext: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode record ciphertext: data field is empty")
        }
        // Decode the record ciphertext data into the record ciphertext.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<N: Network> Debug for Record<N, Ciphertext<N>> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Record<N, Ciphertext<N>> {
    /// Writes the record ciphertext as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the ciphertext to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(RECORD_CIPHERTEXT_PREFIX), &bytes)
            .map_err(|_| fmt::Error)?;
        // Output the string.
        Display::fmt(&string, f)
    }
}
