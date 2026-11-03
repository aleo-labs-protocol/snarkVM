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

impl<N: Network> FromBytes for Transaction<N> {
    /// Reads the transaction from the buffer, recomputing the transaction ID unless `unchecked` is set.
    #[inline]
    fn read_le_with_unchecked<R: Read>(mut reader: R, unchecked: bool) -> IoResult<Self> {
        // Read the version.
        let version = u8::read_le(&mut reader)?;
        // Ensure the version is valid.
        if version != 1 {
            return Err(error("Invalid transaction version"));
        }

        // Read the variant.
        let variant = u8::read_le(&mut reader)?;
        // Match the variant.
        let (id, transaction) = match variant {
            0 => {
                // Read the ID.
                let id = N::TransactionID::read_le(&mut reader)?;
                // Read the owner.
                let owner = ProgramOwner::read_le(&mut reader)?;
                // Read the deployment.
                let deployment = Deployment::read_le_with_unchecked(&mut reader, unchecked)?;
                // Read the fee.
                let fee = Fee::read_le_with_unchecked(&mut reader, unchecked)?;

                // Initialize the transaction.
                let transaction = match unchecked {
                    true => deployment
                        .to_deployment_id()
                        .map(|deployment_id| Self::Deploy(id, deployment_id, owner, Box::new(deployment), fee)),
                    false => Self::from_deployment(owner, deployment, fee),
                }
                .map_err(|e| error(e.to_string()))?;
                // Return the ID and the transaction.
                (id, transaction)
            }
            1 => {
                // Read the ID.
                let id = N::TransactionID::read_le(&mut reader)?;
                // Read the execution.
                let execution = Execution::read_le_with_unchecked(&mut reader, unchecked)?;

                // Read the fee variant.
                let fee_variant = u8::read_le(&mut reader)?;
                // Read the fee.
                let fee = match fee_variant {
                    0u8 => None,
                    1u8 => Some(Fee::read_le_with_unchecked(&mut reader, unchecked)?),
                    _ => return Err(error("Invalid fee variant")),
                };

                // Initialize the transaction.
                let transaction = match unchecked {
                    true => execution
                        .to_execution_id()
                        .map(|execution_id| Self::Execute(id, execution_id, Box::new(execution), fee)),
                    false => Self::from_execution(execution, fee),
                }
                .map_err(|e| error(e.to_string()))?;
                // Return the ID and the transaction.
                (id, transaction)
            }
            2 => {
                // Read the ID.
                let id = N::TransactionID::read_le(&mut reader)?;
                // Read the fee.
                let fee = Fee::read_le_with_unchecked(&mut reader, unchecked)?;

                // Initialize the transaction.
                let transaction = match unchecked {
                    true => Ok(Self::Fee(id, fee)),
                    false => Self::from_fee(fee),
                }
                .map_err(|e| error(e.to_string()))?;
                // Return the ID and the transaction.
                (id, transaction)
            }
            3.. => return Err(error("Invalid transaction variant")),
        };

        // Ensure the transaction ID matches.
        match transaction.id() == id {
            // Return the transaction.
            true => Ok(transaction),
            false => Err(error("Transaction ID mismatch")),
        }
    }

    /// Reads the transaction from the buffer.
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, false)
    }

    /// Reads the transaction from the buffer without checking the data, trusting the stored transaction ID.
    #[inline]
    fn read_le_unchecked<R: Read>(reader: R) -> IoResult<Self> {
        Self::read_le_with_unchecked(reader, true)
    }
}

impl<N: Network> ToBytes for Transaction<N> {
    /// Writes the transaction to the buffer.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the version.
        1u8.write_le(&mut writer)?;

        // Write the transaction.
        // Note: We purposefully do not write out the deployment or execution ID,
        // and instead recompute it when reconstructing the transaction, to ensure there was no malleability.
        match self {
            Self::Deploy(id, _, owner, deployment, fee) => {
                // Write the variant.
                0u8.write_le(&mut writer)?;
                // Write the ID.
                id.write_le(&mut writer)?;
                // Write the owner.
                owner.write_le(&mut writer)?;
                // Write the deployment.
                deployment.write_le(&mut writer)?;
                // Write the fee.
                fee.write_le(&mut writer)
            }
            Self::Execute(id, _, execution, fee) => {
                // Write the variant.
                1u8.write_le(&mut writer)?;
                // Write the ID.
                id.write_le(&mut writer)?;
                // Write the execution.
                execution.write_le(&mut writer)?;
                // Write the fee.
                match fee {
                    None => 0u8.write_le(&mut writer),
                    Some(fee) => {
                        1u8.write_le(&mut writer)?;
                        fee.write_le(&mut writer)
                    }
                }
            }
            Self::Fee(id, fee) => {
                // Write the variant.
                2u8.write_le(&mut writer)?;
                // Write the ID.
                id.write_le(&mut writer)?;
                // Write the fee.
                fee.write_le(&mut writer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::MainnetV0;

    #[test]
    fn test_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for expected in [
            crate::transaction::test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, true, rng),
            crate::transaction::test_helpers::sample_deployment_transaction(1, Uniform::rand(rng), false, false, rng),
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, true, rng),
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, false, rng),
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, true, rng),
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), true, false, rng),
            crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            crate::transaction::test_helpers::sample_execution_transaction_with_fee(false, rng, 0),
        ]
        .into_iter()
        {
            // Check the byte representation.
            let expected_bytes = expected.to_bytes_le()?;
            assert_eq!(expected, Transaction::read_le(&expected_bytes[..])?);
            assert_eq!(expected, Transaction::read_le_unchecked(&expected_bytes[..])?);
        }
        Ok(())
    }

    #[test]
    fn test_unchecked_trusts_id() -> Result<()> {
        let rng = &mut TestRng::default();

        for transaction in [
            crate::transaction::test_helpers::sample_deployment_transaction(2, Uniform::rand(rng), false, true, rng),
            crate::transaction::test_helpers::sample_execution_transaction_with_fee(true, rng, 0),
            crate::transaction::test_helpers::sample_fee_public_transaction(rng),
        ] {
            let mut bytes = transaction.to_bytes_le()?;
            let id: <CurrentNetwork as Network>::TransactionID = Field::<CurrentNetwork>::rand(rng).into();
            bytes[2..34].copy_from_slice(&id.to_bytes_le()?);

            assert!(Transaction::<CurrentNetwork>::read_le(&bytes[..]).is_err());
            let candidate = Transaction::<CurrentNetwork>::read_le_unchecked(&bytes[..])?;
            assert_eq!(candidate.id(), id);
            assert_eq!(candidate.to_bytes_le()?, bytes);
        }
        Ok(())
    }
}
