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

#[macro_export]
macro_rules! matches_type {
    (
        $($type_path:ident)::+,
        { $($declaration_generics:tt)* },
        $type_generic:ident,
        $ejection_function:ident,
        $matches_register_type:ident,
        $matches_external_record:ident,
        $matches_record:ident,
        $matches_plaintext:ident,
        $matches_future:ident,
        $matches_record_internal:ident,
        $matches_entry_internal:ident,
        $matches_plaintext_internal:ident,
        $matches_future_internal:ident,
    ) => {
        // Checks that the given stack value matches the layout of the register type.
        pub(super) fn $matches_register_type $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            value: &$($type_path)::+::Value<$type_generic>,
            register_type: &RegisterType<N>,
        ) -> Result<()> {

            match (value, register_type) {
                ($($type_path)::+::Value::Plaintext(plaintext), RegisterType::Plaintext(plaintext_type)) => {
                    $matches_plaintext(stack, plaintext, plaintext_type)
                }
                ($($type_path)::+::Value::Record(record), RegisterType::Record(record_name)) => $matches_record(stack, record, record_name),
                ($($type_path)::+::Value::Record(record), RegisterType::ExternalRecord(locator)) => {
                    $matches_external_record(stack, record, locator)
                }
                ($($type_path)::+::Value::Future(future), RegisterType::Future(locator)) => $matches_future(stack, future, locator),
                ($($type_path)::+::Value::DynamicRecord(_), RegisterType::DynamicRecord) => Ok(()),
                ($($type_path)::+::Value::DynamicFuture(_), RegisterType::DynamicFuture) => Ok(()),
                _ => {
                    let value_kind = match value {
                        $($type_path)::+::Value::Plaintext($($type_path)::+::Plaintext::Literal(literal, _)) => {
                            format!("plaintext literal of type '{}'", literal.to_type())
                        }
                        $($type_path)::+::Value::Plaintext($($type_path)::+::Plaintext::Struct(..)) => "plaintext struct".to_string(),
                        $($type_path)::+::Value::Plaintext($($type_path)::+::Plaintext::Array(..)) => "plaintext array".to_string(),
                        $($type_path)::+::Value::Record(..) => "record".to_string(),
                        $($type_path)::+::Value::Future(..) => "future".to_string(),
                        $($type_path)::+::Value::DynamicRecord(..) => "dynamic record".to_string(),
                        $($type_path)::+::Value::DynamicFuture(..) => "dynamic future".to_string(),
                    };

                    bail!("A value of type '{value_kind}' does not match its declared register type '{register_type}'")
                },
            }
        }

        // Checks that the given record matches the layout of the external record type.
        fn $matches_external_record $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            record: &$($type_path)::+::Record<$type_generic, $($type_path)::+::Plaintext<$type_generic>>,
            locator: &Locator<N>,
        ) -> Result<()> {
            // Retrieve the record name.
            let record_name = locator.resource();

            // Ensure the record name is valid.
            ensure!(!Program::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

            // Retrieve the external stack.
            let external_stack = stack.get_external_stack(locator.program_id())?;
            // Retrieve the record type from the program.
            let Ok(record_type) = external_stack.program().get_record(locator.resource()) else {
                bail!("External '{locator}' is not defined in the program")
            };

            // Ensure the record name matches.
            if record_type.name() != record_name {
                bail!("Expected external record '{record_name}', found external record '{}'", record_type.name())
            }

            $matches_record_internal(&*external_stack, record, record_type, 0)
        }

        // Checks that the given record matches the layout of the record type.
        fn $matches_record $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            record: &$($type_path)::+::Record<$type_generic, $($type_path)::+::Plaintext<$type_generic>>,
            record_name: &Identifier<N>,
        ) -> Result<()> {
            // Ensure the record name is valid.
            ensure!(!Program::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

            // Retrieve the record type from the program.
            let Ok(record_type) = stack.program().get_record(record_name) else {
                bail!("Record '{record_name}' is not defined in the program")
            };

            // Ensure the record name matches.
            if record_type.name() != record_name {
                bail!("Expected record '{record_name}', found record '{}'", record_type.name())
            }

            $matches_record_internal(stack, record, record_type, 0)
        }

        // Checks that the given plaintext matches the layout of the plaintext type.
        fn $matches_plaintext $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            plaintext: &$($type_path)::+::Plaintext<$type_generic>,
            plaintext_type: &PlaintextType<N>,
        ) -> Result<()> {
            $matches_plaintext_internal(stack, plaintext, plaintext_type, 0)
        }

        // Checks that the given future matches the layout of the future type.
        fn $matches_future $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            future: &$($type_path)::+::Future<$type_generic>,
            locator: &Locator<N>,
        ) -> Result<()> {
            $matches_future_internal(stack, future, locator, 0)
        }

        // Checks that the given record matches the layout of the record type.
        fn $matches_record_internal $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            record: &$($type_path)::+::Record<$type_generic, $($type_path)::+::Plaintext<$type_generic>>,
            record_type: &RecordType<N>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

            // Retrieve the record name.
            let record_name = record_type.name();

            // Ensure the record name is valid.
            ensure!(!Program::is_reserved_keyword(record_name), "Record name '{record_name}' is reserved");

            // Ensure the visibility of the record owner matches the visibility in the record type.
            let record_owner_is_public: bool = record.owner().is_public().$ejection_function();
            let record_owner_is_private: bool = record.owner().is_private().$ejection_function();

            ensure!(
                record_owner_is_public == record_type.owner().is_public(),
                "Visibility of record entry 'owner' does not match"
            );
            ensure!(
                record_owner_is_private == record_type.owner().is_private(),
                "Visibility of record entry 'owner' does not match"
            );

            // Ensure the number of record entries does not exceed the maximum.
            let num_entries = record.data().len();
            ensure!(num_entries <= N::MAX_DATA_ENTRIES, "'{record_name}' cannot exceed {} entries", N::MAX_DATA_ENTRIES);

            // Ensure the number of record entries match.
            let expected_num_entries = record_type.entries().len();
            if expected_num_entries != num_entries {
                bail!("'{record_name}' expected {expected_num_entries} entries, found {num_entries} entries")
            }

            // Ensure the record data match, in the same order.
            for (i, ((expected_name, expected_type), (entry_name, entry))) in
                record_type.entries().iter().zip_eq(record.data().iter()).enumerate()
            {
                let accessible_entry_name = (*entry_name).$ejection_function();

                // Ensure the entry name matches.
                if expected_name != &accessible_entry_name {
                    bail!("Entry '{i}' in '{record_name}' is incorrect: expected '{expected_name}', found '{accessible_entry_name}'")
                }
                // Ensure the entry name is valid.
                ensure!(!Program::is_reserved_keyword(&accessible_entry_name), "Entry name '{accessible_entry_name}' is reserved");
                // Ensure the entry matches (recursive call).
                $matches_entry_internal(stack, record_name, entry_name, entry, expected_type, depth + 1)?;
            }

            Ok(())
        }

        // Checks that the given entry matches the layout of the entry type.
        fn $matches_entry_internal $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            record_name: &Identifier<N>,
            entry_name: &$($type_path)::+::Identifier<$type_generic>,
            entry: &$($type_path)::+::Entry<$type_generic, $($type_path)::+::Plaintext<$type_generic>>,
            entry_type: &EntryType<N>,
            depth: usize,
        ) -> Result<()> {
            match (entry, entry_type) {
                ($($type_path)::+::Entry::Constant(plaintext), EntryType::Constant(plaintext_type))
                | ($($type_path)::+::Entry::Public(plaintext), EntryType::Public(plaintext_type))
                | ($($type_path)::+::Entry::Private(plaintext), EntryType::Private(plaintext_type)) => {
                    match $matches_plaintext_internal(stack, plaintext, plaintext_type, depth) {
                        Ok(()) => Ok(()),
                        Err(error) => bail!("Invalid record entry '{record_name}.{entry_name}': {error}"),
                    }
                }
                _ => bail!(
                    "Type mismatch in record entry '{record_name}.{entry_name}': value does not match\n'{entry_type}'"
                ),
            }
        }

        // Checks that the given plaintext matches the layout of the plaintext type.
        fn $matches_plaintext_internal $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            plaintext: &$($type_path)::+::Plaintext<$type_generic>,
            plaintext_type: &PlaintextType<N>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the plaintext type is invalid.
            ensure!(depth <= N::MAX_DATA_DEPTH, "Plaintext exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

            // Ensure the plaintext matches the plaintext definition in the program.
            match plaintext_type {
                PlaintextType::Literal(literal_type) => match plaintext {
                    // If `plaintext` is a literal, it must match the literal type.
                    $($type_path)::+::Plaintext::Literal(literal, ..) => {
                        // Ensure the literal type matches.
                        match literal.to_type() == *literal_type {
                            true => Ok(()),
                            false => bail!("'{literal}' is invalid: expected {literal_type}"),
                        }
                    }
                    // If `plaintext` is a struct, this is a mismatch.
                    $($type_path)::+::Plaintext::Struct(..) => bail!("'{plaintext_type}' is invalid: expected literal, found struct"),
                    // If `plaintext` is an array, this is a mismatch.
                    $($type_path)::+::Plaintext::Array(..) => bail!("'{plaintext_type}' is invalid: expected literal, found array"),
                },
                PlaintextType::ExternalStruct(locator) => {
                    let external_stack = stack.get_external_stack(locator.program_id())?;
                    let new_type = PlaintextType::Struct(*locator.resource());
                    $matches_plaintext_internal(&*external_stack, plaintext, &new_type, depth)
                }
                PlaintextType::Struct(struct_name) => {
                    // Ensure the struct name is valid.
                    ensure!(!Program::is_reserved_keyword(struct_name), "Struct '{struct_name}' is reserved");

                    // Retrieve the struct from the program.
                    let Ok(struct_) = stack.program().get_struct(struct_name) else {
                        bail!("Struct '{struct_name}' is not defined in the program")
                    };

                    // Ensure the struct name matches.
                    if struct_.name() != struct_name {
                        bail!("Expected struct '{struct_name}', found struct '{}'", struct_.name())
                    }

                    // Retrieve the struct members.
                    let members = match plaintext {
                        $($type_path)::+::Plaintext::Literal(..) => bail!("'{struct_name}' is invalid: expected struct, found literal"),
                        $($type_path)::+::Plaintext::Struct(members, ..) => members,
                        $($type_path)::+::Plaintext::Array(..) => bail!("'{struct_name}' is invalid: expected struct, found array"),
                    };

                    let num_members = members.len();
                    // Ensure the number of struct members does not go below the minimum.
                    ensure!(
                        num_members >= N::MIN_STRUCT_ENTRIES,
                        "'{struct_name}' cannot be less than {} entries",
                        N::MIN_STRUCT_ENTRIES
                    );
                    // Ensure the number of struct members does not exceed the maximum.
                    ensure!(
                        num_members <= N::MAX_STRUCT_ENTRIES,
                        "'{struct_name}' cannot exceed {} entries",
                        N::MAX_STRUCT_ENTRIES
                    );

                    // Ensure the number of struct members match.
                    let expected_num_members = struct_.members().len();
                    if expected_num_members != num_members {
                        bail!("'{struct_name}' expected {expected_num_members} members, found {num_members} members")
                    }

                    // Ensure the struct members match, in the same order.
                    for (i, ((expected_name, expected_type), (member_name, member))) in
                        struct_.members().iter().zip_eq(members.iter()).enumerate()
                    {
                        // Ensure the member name matches.
                        if expected_name != &member_name.$ejection_function() {
                            bail!(
                                "Member '{i}' in '{struct_name}' is incorrect: expected '{expected_name}', found '{member_name}'"
                            )
                        }
                        // Ensure the member name is valid.
                        ensure!(!Program::is_reserved_keyword(&member_name.$ejection_function()), "Member name '{member_name}' is reserved");
                        // Ensure the member plaintext matches (recursive call).
                        $matches_plaintext_internal(stack, member, expected_type, depth + 1)?;
                    }

                    Ok(())
                }
                PlaintextType::Array(array_type) => match plaintext {
                    // If `plaintext` is a literal, this is a mismatch.
                    $($type_path)::+::Plaintext::Literal(..) => bail!("'{plaintext_type}' is invalid: expected array, found literal"),
                    // If `plaintext` is a struct, this is a mismatch.
                    $($type_path)::+::Plaintext::Struct(..) => bail!("'{plaintext_type}' is invalid: expected array, found struct"),
                    // If `plaintext` is an array, it must match the array type.
                    $($type_path)::+::Plaintext::Array(array, ..) => {
                        // Ensure the array length matches.
                        let (actual_length, expected_length) = (array.len(), array_type.length());
                        if **expected_length as usize != actual_length {
                            bail!(
                                "'{plaintext_type}' is invalid: expected {expected_length} elements, found {actual_length} elements"
                            )
                        }
                        // Ensure the array elements match.
                        for element in array.iter() {
                            $matches_plaintext_internal(stack, element, array_type.next_element_type(), depth + 1)?;
                        }
                        Ok(())
                    }
                },
            }
        }

        // Checks that the given future matches the layout of the future type.
        fn $matches_future_internal $($declaration_generics)*(
            stack: &impl StackTrait<N>,
            future: &$($type_path)::+::Future<$type_generic>,
            locator: &Locator<N>,
            depth: usize,
        ) -> Result<()> {
            // If the depth exceeds the maximum depth, then the future type is invalid.
            ensure!(depth <= N::MAX_DATA_DEPTH, "Future exceeded maximum depth of {}", N::MAX_DATA_DEPTH);

            // Ensure that the program IDs match.
            ensure!(*locator.program_id() == future.program_id().$ejection_function(), "Future program ID does not match");

            // Ensure that the function names match.
            ensure!(*locator.resource() == future.function_name().$ejection_function(), "Future name does not match");

            // Retrieve the external stack, if needed.
            let external_stack = match locator.program_id() == stack.program_id() {
                true => None,
                // Attention - This method must fail here and early return if the external program is missing.
                // Otherwise, this method will proceed to look for the requested function in its own program.
                false => Some(stack.get_external_stack(locator.program_id())?),
            };
            // Retrieve the associated function.
            let function = match &external_stack {
                Some(external_stack) => external_stack.get_function_ref(locator.resource())?,
                None => stack.get_function_ref(locator.resource())?,
            };
            // Retrieve the finalize inputs.
            let inputs = match function.finalize_logic() {
                Some(finalize_logic) => finalize_logic.inputs(),
                None => bail!("Function '{locator}' does not have a finalize block"),
            };

            // Ensure the number of arguments matches the number of inputs.
            ensure!(future.arguments().len() == inputs.len(), "Future arguments do not match");

            // Check that the arguments match the inputs.
            // Use the external stack if the future is from an external program.
            for (argument, input) in future.arguments().iter().zip_eq(inputs.iter()) {
                match (argument, input.finalize_type()) {
                    ($($type_path)::+::Argument::Plaintext(plaintext), FinalizeType::Plaintext(plaintext_type)) => match &external_stack {
                        Some(external_stack) => {
                            $matches_plaintext_internal(&**external_stack, plaintext, plaintext_type, depth + 1)?
                        }
                        None => $matches_plaintext_internal(stack, plaintext, plaintext_type, depth + 1)?,
                    },
                    ($($type_path)::+::Argument::Future(future), FinalizeType::Future(locator)) => match &external_stack {
                        Some(external_stack) => $matches_future_internal(&**external_stack, future, locator, depth + 1)?,
                        None => $matches_future_internal(stack, future, locator, depth + 1)?,
                    },
                    ($($type_path)::+::Argument::DynamicFuture(_), FinalizeType::DynamicFuture) => {}
                    (_, input_type) => {
                        bail!("Argument type does not match input type: expected '{input_type}'")
                    }
                }
            }

            Ok(())
        }
    }
}
