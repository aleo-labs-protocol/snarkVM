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

impl<N: Network> Parser for Register<N> {
    /// Parses a string into a register.
    /// The register is of the form `r{locator}` or `r{locator}.{identifier}`.
    #[inline]
    fn parse(string: &str) -> ParserResult<'_, Self> {
        // Parse the register character from the string.
        let (string, _) = tag("r")(string)?;
        // Parse the locator from the string.
        let (string, locator) =
            map_res(recognize(many1(one_of("0123456789"))), |locator: &str| locator.parse::<u64>())(string)?;
        // Parse the accesses from the string, if it is a register access.
        let (string, accesses): (&str, Vec<Access<N>>) = map_res(many0(Access::parse), |accesses| {
            // Ensure the number of identifiers is within the limit.
            if accesses.len() <= N::MAX_DATA_DEPTH {
                Ok(accesses)
            } else {
                Err(error(format!("Register \'r{locator}\' has too many accesses ({})", accesses.len())))
            }
        })(string)?;
        // Return the register.
        Ok((string, match accesses.len() {
            0 => Self::Locator(locator),
            _ => Self::Access(locator, accesses),
        }))
    }
}

impl<N: Network> FromStr for Register<N> {
    type Err = Error;

    /// Parses a string into a register.
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

impl<N: Network> Debug for Register<N> {
    /// Prints the register as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Register<N> {
    /// Prints the register as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            // Prints the register, i.e. r0
            Self::Locator(locator) => write!(f, "r{locator}"),
            // Prints the register access, i.e. r0.owner
            Self::Access(locator, accesses) => {
                write!(f, "r{locator}")?;
                for access in accesses {
                    write!(f, "{access}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identifier, U32};
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;
    #[test]
    fn test_register_display() -> Result<()> {
        // Register::Locator
        assert_eq!("r0", Register::<CurrentNetwork>::Locator(0).to_string());
        assert_eq!("r1", Register::<CurrentNetwork>::Locator(1).to_string());
        assert_eq!("r2", Register::<CurrentNetwork>::Locator(2).to_string());
        assert_eq!("r3", Register::<CurrentNetwork>::Locator(3).to_string());
        assert_eq!("r4", Register::<CurrentNetwork>::Locator(4).to_string());

        // Register::Access with Access::Member
        assert_eq!(
            "r0.owner",
            Register::<CurrentNetwork>::Access(0, vec![Access::Member(Identifier::from_str("owner")?)]).to_string()
        );
        assert_eq!(
            "r1.owner",
            Register::<CurrentNetwork>::Access(1, vec![Access::Member(Identifier::from_str("owner")?)]).to_string()
        );
        assert_eq!(
            "r2.owner",
            Register::<CurrentNetwork>::Access(2, vec![Access::Member(Identifier::from_str("owner")?)]).to_string()
        );
        assert_eq!(
            "r3.owner",
            Register::<CurrentNetwork>::Access(3, vec![Access::Member(Identifier::from_str("owner")?)]).to_string()
        );
        assert_eq!(
            "r4.owner",
            Register::<CurrentNetwork>::Access(4, vec![Access::Member(Identifier::from_str("owner")?)]).to_string()
        );

        // Register::Access with Access::Index
        assert_eq!("r0[0u32]", Register::<CurrentNetwork>::Access(0, vec![Access::Index(U32::new(0))]).to_string());
        assert_eq!(
            "r1[0u32][1u32]",
            Register::<CurrentNetwork>::Access(1, vec![Access::Index(U32::new(0)), Access::Index(U32::new(1))])
                .to_string()
        );
        assert_eq!(
            "r2[0u32][1u32][2u32]",
            Register::<CurrentNetwork>::Access(2, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2))
            ])
            .to_string()
        );
        assert_eq!(
            "r3[0u32][1u32][2u32][3u32]",
            Register::<CurrentNetwork>::Access(3, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2)),
                Access::Index(U32::new(3))
            ])
            .to_string()
        );
        assert_eq!(
            "r4[0u32][1u32][2u32][3u32][4u32]",
            Register::<CurrentNetwork>::Access(4, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2)),
                Access::Index(U32::new(3)),
                Access::Index(U32::new(4))
            ])
            .to_string()
        );

        // Register::Access with Access::Member and Access::Index
        assert_eq!(
            "r0.owner[0u32]",
            Register::<CurrentNetwork>::Access(0, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0))
            ])
            .to_string()
        );
        assert_eq!(
            "r1.owner[0u32].owner",
            Register::<CurrentNetwork>::Access(1, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?)
            ])
            .to_string()
        );
        assert_eq!(
            "r2.owner[0u32].owner[1u32]",
            Register::<CurrentNetwork>::Access(2, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1))
            ])
            .to_string()
        );
        assert_eq!(
            "r3.owner[0u32].owner[1u32].owner",
            Register::<CurrentNetwork>::Access(3, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1)),
                Access::Member(Identifier::from_str("owner")?)
            ])
            .to_string()
        );
        assert_eq!(
            "r4.owner[0u32].owner[1u32].owner[2u32]",
            Register::<CurrentNetwork>::Access(4, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(2))
            ])
            .to_string()
        );

        Ok(())
    }

    #[test]
    fn test_register_to_string() -> Result<()> {
        // Register::Locator
        assert_eq!(Register::<CurrentNetwork>::Locator(0).to_string(), "r0".to_string());
        assert_eq!(Register::<CurrentNetwork>::Locator(1).to_string(), "r1".to_string());
        assert_eq!(Register::<CurrentNetwork>::Locator(2).to_string(), "r2".to_string());
        assert_eq!(Register::<CurrentNetwork>::Locator(3).to_string(), "r3".to_string());
        assert_eq!(Register::<CurrentNetwork>::Locator(4).to_string(), "r4".to_string());

        // Register::Access with Access::Member
        assert_eq!(
            Register::<CurrentNetwork>::Access(0, vec![Access::Member(Identifier::from_str("owner")?)]).to_string(),
            "r0.owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(1, vec![Access::Member(Identifier::from_str("owner")?)]).to_string(),
            "r1.owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(2, vec![Access::Member(Identifier::from_str("owner")?)]).to_string(),
            "r2.owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(3, vec![Access::Member(Identifier::from_str("owner")?)]).to_string(),
            "r3.owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(4, vec![Access::Member(Identifier::from_str("owner")?)]).to_string(),
            "r4.owner".to_string()
        );

        // Register::Access with Access::Index
        assert_eq!(
            Register::<CurrentNetwork>::Access(0, vec![Access::Index(U32::new(0))]).to_string(),
            "r0[0u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(1, vec![Access::Index(U32::new(0)), Access::Index(U32::new(1))])
                .to_string(),
            "r1[0u32][1u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(2, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2))
            ])
            .to_string(),
            "r2[0u32][1u32][2u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(3, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2)),
                Access::Index(U32::new(3))
            ])
            .to_string(),
            "r3[0u32][1u32][2u32][3u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(4, vec![
                Access::Index(U32::new(0)),
                Access::Index(U32::new(1)),
                Access::Index(U32::new(2)),
                Access::Index(U32::new(3)),
                Access::Index(U32::new(4))
            ])
            .to_string(),
            "r4[0u32][1u32][2u32][3u32][4u32]".to_string()
        );

        // Register::Access with Access::Member and Access::Index
        assert_eq!(
            Register::<CurrentNetwork>::Access(0, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0))
            ])
            .to_string(),
            "r0.owner[0u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(1, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?)
            ])
            .to_string(),
            "r1.owner[0u32].owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(2, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1))
            ])
            .to_string(),
            "r2.owner[0u32].owner[1u32]".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(3, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1)),
                Access::Member(Identifier::from_str("owner")?)
            ])
            .to_string(),
            "r3.owner[0u32].owner[1u32].owner".to_string()
        );
        assert_eq!(
            Register::<CurrentNetwork>::Access(4, vec![
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(0)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(1)),
                Access::Member(Identifier::from_str("owner")?),
                Access::Index(U32::new(2))
            ])
            .to_string(),
            "r4.owner[0u32].owner[1u32].owner[2u32]".to_string()
        );

        Ok(())
    }

    #[test]
    fn test_register_parse() -> Result<()> {
        // Register::Locator
        assert_eq!(("", Register::<CurrentNetwork>::Locator(0)), Register::parse("r0").unwrap());
        assert_eq!(("", Register::<CurrentNetwork>::Locator(1)), Register::parse("r1").unwrap());
        assert_eq!(("", Register::<CurrentNetwork>::Locator(2)), Register::parse("r2").unwrap());
        assert_eq!(("", Register::<CurrentNetwork>::Locator(3)), Register::parse("r3").unwrap());
        assert_eq!(("", Register::<CurrentNetwork>::Locator(4)), Register::parse("r4").unwrap());

        // Register::Access with Access::Member
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(0, vec![Access::Member(Identifier::from_str("owner")?)])),
            Register::parse("r0.owner").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(1, vec![Access::Member(Identifier::from_str("owner")?)])),
            Register::parse("r1.owner").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(2, vec![Access::Member(Identifier::from_str("owner")?)])),
            Register::parse("r2.owner").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(3, vec![Access::Member(Identifier::from_str("owner")?)])),
            Register::parse("r3.owner").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(4, vec![Access::Member(Identifier::from_str("owner")?)])),
            Register::parse("r4.owner").unwrap()
        );

        for i in 1..=CurrentNetwork::MAX_DATA_DEPTH {
            let mut string = "r0".to_string();
            for _ in 0..i {
                string.push_str(".owner");
            }

            assert_eq!(
                ("", Register::<CurrentNetwork>::Access(0, vec![Access::Member(Identifier::from_str("owner")?); i])),
                Register::<CurrentNetwork>::parse(&string).unwrap()
            );
        }

        // Register::Access with Access::Index
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(0, vec![Access::Index(U32::new(0))])),
            Register::parse("r0[0u32]").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(1, vec![Access::Index(U32::new(0))])),
            Register::parse("r1[0u32]").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(2, vec![Access::Index(U32::new(0))])),
            Register::parse("r2[0u32]").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(3, vec![Access::Index(U32::new(0))])),
            Register::parse("r3[0u32]").unwrap()
        );
        assert_eq!(
            ("", Register::<CurrentNetwork>::Access(4, vec![Access::Index(U32::new(0))])),
            Register::parse("r4[0u32]").unwrap()
        );

        for i in 1..=CurrentNetwork::MAX_DATA_DEPTH {
            let mut string = "r0".to_string();
            for _ in 0..i {
                string.push_str("[0u32]");
            }

            assert_eq!(
                ("", Register::<CurrentNetwork>::Access(0, vec![Access::Index(U32::new(0)); i])),
                Register::<CurrentNetwork>::parse(&string).unwrap()
            );
        }

        // Register::Access with Access::Member and Access::Index
        assert_eq!(
            (
                "",
                Register::<CurrentNetwork>::Access(0, vec![
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0))
                ])
            ),
            Register::parse("r0.owner[0u32]").unwrap()
        );
        assert_eq!(
            (
                "",
                Register::<CurrentNetwork>::Access(1, vec![
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?)
                ])
            ),
            Register::parse("r1.owner[0u32].owner").unwrap()
        );
        assert_eq!(
            (
                "",
                Register::<CurrentNetwork>::Access(2, vec![
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0))
                ])
            ),
            Register::parse("r2.owner[0u32].owner[0u32]").unwrap()
        );
        assert_eq!(
            (
                "",
                Register::<CurrentNetwork>::Access(3, vec![
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?)
                ])
            ),
            Register::parse("r3.owner[0u32].owner[0u32].owner").unwrap()
        );
        assert_eq!(
            (
                "",
                Register::<CurrentNetwork>::Access(4, vec![
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0)),
                    Access::Member(Identifier::from_str("owner")?),
                    Access::Index(U32::new(0))
                ])
            ),
            Register::parse("r4.owner[0u32].owner[0u32].owner[0u32]").unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_register_parser_fails() {
        assert!(Register::<CurrentNetwork>::parse("").is_err());
        assert!(Register::<CurrentNetwork>::parse("r").is_err());

        // Register::Access with multiple identifiers that exceed the maximum depth.
        for i in CurrentNetwork::MAX_DATA_DEPTH + 1..CurrentNetwork::MAX_DATA_DEPTH * 2 {
            let mut string = "r0".to_string();
            for _ in 0..i {
                string.push_str(".owner");
            }

            assert!(Register::<CurrentNetwork>::parse(&string).is_err());
        }

        // Register::Access with multiple indices that exceed the maximum depth.
        for i in CurrentNetwork::MAX_DATA_DEPTH + 1..CurrentNetwork::MAX_DATA_DEPTH * 2 {
            let mut string = "r0".to_string();
            for _ in 0..i {
                string.push_str("[0u32]");
            }

            assert!(Register::<CurrentNetwork>::parse(&string).is_err());
        }

        // Register::Access with multiple indices and members that exceed the maximum depth.
        for i in CurrentNetwork::MAX_DATA_DEPTH + 1..CurrentNetwork::MAX_DATA_DEPTH * 2 {
            let mut string = "r0".to_string();
            for n in 0..i {
                if n % 2 == 0 {
                    string.push_str("[0u32]");
                } else {
                    string.push_str(".owner");
                }
            }

            assert!(Register::<CurrentNetwork>::parse(&string).is_err());
        }
    }
}
