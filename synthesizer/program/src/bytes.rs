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

impl<N: Network> FromBytes for ProgramCore<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid program version"));
        }

        // Read the program ID.
        let id = ProgramID::read_le(&mut reader)?;

        // Initialize the program.
        let mut program = ProgramCore::new(id).map_err(error)?;

        // Read the number of program imports.
        let imports_len = u8::read_le(&mut reader)?;
        // Read the program imports.
        for _ in 0..imports_len {
            program.add_import(Import::read_le(&mut reader)?).map_err(error)?;
        }

        // Read the number of components.
        let components_len = u16::read_le(&mut reader)?;
        for _ in 0..components_len {
            // Read the variant.
            let variant = u8::read_le(&mut reader)?;
            // Match the variant.
            match variant {
                // Read the mapping.
                0 => program.add_mapping(Mapping::read_le(&mut reader)?).map_err(error)?,
                // Read the struct.
                1 => program.add_struct(StructType::read_le(&mut reader)?).map_err(error)?,
                // Read the record.
                2 => program.add_record(RecordType::read_le(&mut reader)?).map_err(error)?,
                // Read the closure.
                3 => program.add_closure(ClosureCore::read_le(&mut reader)?).map_err(error)?,
                // Read the function.
                4 => program.add_function(FunctionCore::read_le(&mut reader)?).map_err(error)?,
                // Read the constructor.
                5 => program.add_constructor(ConstructorCore::read_le(&mut reader)?).map_err(error)?,
                // Read the view function.
                6 => program.add_view(ViewCore::read_le(&mut reader)?).map_err(error)?,
                // Invalid variant.
                _ => return Err(error(format!("Failed to parse program. Invalid component variant '{variant}'"))),
            }
        }

        Ok(program)
    }
}

impl<N: Network> ToBytes for ProgramCore<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;

        // Write the program ID.
        self.id.write_le(&mut writer)?;

        // Write the number of program imports.
        u8::try_from(self.imports.len()).map_err(error)?.write_le(&mut writer)?;
        // Write the program imports.
        for import in self.imports.values() {
            import.write_le(&mut writer)?;
        }

        // Write the number of components.
        u16::try_from(self.components.len()).map_err(error)?.write_le(&mut writer)?;

        // Write the components.
        for (label, definition) in self.components.iter() {
            match label {
                ProgramLabel::Constructor => {
                    // Write the constructor, if it exists.
                    if let Some(constructor) = &self.constructor {
                        // Write the variant.
                        5u8.write_le(&mut writer)?;
                        // Write the constructor.
                        constructor.write_le(&mut writer)?;
                    }
                }
                ProgramLabel::Identifier(identifier) => {
                    match definition {
                        ProgramDefinition::Constructor => {
                            return Err(error("A program constructor cannot have a named label"));
                        }
                        ProgramDefinition::Mapping => match self.mappings.get(identifier) {
                            Some(mapping) => {
                                // Write the variant.
                                0u8.write_le(&mut writer)?;
                                // Write the mapping.
                                mapping.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("Mapping '{identifier}' is not defined"))),
                        },
                        ProgramDefinition::Struct => match self.structs.get(identifier) {
                            Some(struct_) => {
                                // Write the variant.
                                1u8.write_le(&mut writer)?;
                                // Write the struct.
                                struct_.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("Struct '{identifier}' is not defined."))),
                        },
                        ProgramDefinition::Record => match self.records.get(identifier) {
                            Some(record) => {
                                // Write the variant.
                                2u8.write_le(&mut writer)?;
                                // Write the record.
                                record.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("Record '{identifier}' is not defined."))),
                        },
                        ProgramDefinition::Closure => match self.closures.get(identifier) {
                            Some(closure) => {
                                // Write the variant.
                                3u8.write_le(&mut writer)?;
                                // Write the closure.
                                closure.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("Closure '{identifier}' is not defined."))),
                        },
                        ProgramDefinition::Function => match self.functions.get(identifier) {
                            Some(function) => {
                                // Write the variant.
                                4u8.write_le(&mut writer)?;
                                // Write the function.
                                function.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("Function '{identifier}' is not defined."))),
                        },
                        ProgramDefinition::View => match self.views.get(identifier) {
                            Some(view) => {
                                // Write the variant.
                                6u8.write_le(&mut writer)?;
                                // Write the view function.
                                view.write_le(&mut writer)?;
                            }
                            None => return Err(error(format!("View '{identifier}' is not defined."))),
                        },
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Program;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_bytes_with_view() -> Result<()> {
        let program = r"
program token_with_view.aleo;

mapping balances:
    key as address.public;
    value as u64.public;

function noop:
    input r0 as u64.private;
    output r0 as u64.private;

view total_balance:
    input r0 as address.public;
    get.or_use balances[r0] 0u64 into r1;
    output r1 as u64.public;";

        let (string, expected) = Program::<CurrentNetwork>::parse(program).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        let expected_bytes = expected.to_bytes_le()?;
        let candidate = Program::<CurrentNetwork>::from_bytes_le(&expected_bytes)?;
        assert_eq!(expected, candidate);
        assert_eq!(expected_bytes, candidate.to_bytes_le()?);

        Ok(())
    }

    #[test]
    fn test_bytes() -> Result<()> {
        let program = r"
program token.aleo;

record token:
    owner as address.private;
    token_amount as u64.private;

function compute:
    input r0 as token.record;
    add r0.token_amount r0.token_amount into r1;
    output r1 as u64.private;";

        // Initialize a new program.
        let (string, expected) = Program::<CurrentNetwork>::parse(program).unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");

        let expected_bytes = expected.to_bytes_le()?;

        let candidate = Program::<CurrentNetwork>::from_bytes_le(&expected_bytes)?;
        assert_eq!(expected, candidate);
        assert_eq!(expected_bytes, candidate.to_bytes_le()?);

        Ok(())
    }
}
