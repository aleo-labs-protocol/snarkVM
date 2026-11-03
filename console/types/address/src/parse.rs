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

static ADDRESS_PREFIX: &str = "aleo";

impl<E: Environment> Parser for Address<E> {
    /// Parses a string into an address.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Prepare a parser for the Aleo address.
        let parse_address = recognize(pair(
            tag("aleo1"),
            many1(terminated(one_of("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), many0(char('_')))),
        ));

        // Parse the address from the string.
        map_res(parse_address, |address: &str| -> Result<_, Error> { Self::from_str(&address.replace('_', "")) })(
            string,
        )
    }
}

impl<E: Environment> FromStr for Address<E> {
    type Err = Error;

    /// Reads in an account address string.
    fn from_str(address: &str) -> Result<Self, Self::Err> {
        // Ensure the address string length is 63 characters.
        if address.len() != 63 {
            bail!("Invalid account address length: found {}, expected 63", address.len())
        }
        // Decode the address string from bech32m.
        let checked = bech32::primitives::decode::CheckedHrpstring::new::<LongBech32m>(address)?;
        let hrp = checked.hrp();
        let data: Vec<u8> = checked.byte_iter().collect();
        if hrp.as_str() != ADDRESS_PREFIX {
            bail!("Failed to decode address: '{hrp}' is an invalid prefix")
        } else if data.is_empty() {
            bail!("Failed to decode address: data field is empty")
        }
        // Decode the address data into an account address.
        Ok(Self::read_le(&data[..])?)
    }
}

impl<E: Environment> Debug for Address<E> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<E: Environment> Display for Address<E> {
    /// Writes an account address as a bech32m string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Convert the address to bytes.
        let bytes = self.to_bytes_le().map_err(|_| fmt::Error)?;
        // Encode the bytes into bech32m.
        let string = bech32::encode::<LongBech32m>(bech32::Hrp::parse_unchecked(ADDRESS_PREFIX), &bytes)
            .map_err(|_| fmt::Error)?;
        // Output the string.
        Display::fmt(&string, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 1_000;

    #[test]
    fn test_parse() -> Result<()> {
        // Ensure type and empty value fails.
        assert!(Address::<CurrentEnvironment>::parse(Address::<CurrentEnvironment>::type_name()).is_err());
        assert!(Address::<CurrentEnvironment>::parse("").is_err());

        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let address = Address::<CurrentEnvironment>::rand(&mut rng);

            let expected = format!("{address}");
            let (remainder, candidate) = Address::<CurrentEnvironment>::parse(&expected).unwrap();
            assert_eq!(format!("{expected}"), candidate.to_string());
            assert_eq!(ADDRESS_PREFIX, candidate.to_string().split('1').next().unwrap());
            assert_eq!("", remainder);
        }
        Ok(())
    }

    #[test]
    fn test_string() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let expected = Address::<CurrentEnvironment>::rand(&mut rng);

            // Check the string representation.
            let candidate = format!("{expected}");
            assert_eq!(expected, Address::from_str(&candidate)?);
            assert_eq!(ADDRESS_PREFIX, candidate.split('1').next().unwrap());
        }
        Ok(())
    }

    #[test]
    fn test_display() -> Result<()> {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a new address.
            let expected = Address::<CurrentEnvironment>::rand(&mut rng);

            let candidate = expected.to_string();
            assert_eq!(format!("{expected}"), candidate);
            assert_eq!(ADDRESS_PREFIX, candidate.split('1').next().unwrap());

            let candidate_recovered = Address::<CurrentEnvironment>::from_str(&candidate.to_string())?;
            assert_eq!(expected, candidate_recovered);
        }
        Ok(())
    }
}
