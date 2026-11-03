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

impl<N: Network> Serialize for Transactions<N> {
    /// Serializes the transactions to a JSON-string or buffer.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut transactions = serializer.serialize_seq(Some(self.transactions.len()))?;
                for transaction in self.transactions.values() {
                    transactions.serialize_element(transaction)?;
                }
                transactions.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Transactions<N> {
    /// Deserializes the transactions from a JSON-string or buffer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                use core::marker::PhantomData;

                struct TransactionsDeserializer<N: Network>(PhantomData<N>);

                impl<'de, N: Network> Visitor<'de> for TransactionsDeserializer<N> {
                    type Value = Vec<ConfirmedTransaction<N>>;

                    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                        formatter.write_str("Vec<ConfirmedTransaction> sequence.")
                    }

                    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                        let mut transactions = Vec::new();
                        while let Some(transaction) = seq.next_element()? {
                            transactions.push(transaction);
                        }
                        Ok(transactions)
                    }
                }

                Ok(Self::from(&deserializer.deserialize_seq(TransactionsDeserializer(PhantomData))?))
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "transactions"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u32 = 6;

    fn sample_transactions(index: u32, rng: &mut TestRng) -> Transactions<CurrentNetwork> {
        if index == 0 {
            [
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
            ]
            .into_iter()
            .collect()
        } else if index == 1 {
            [
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(Uniform::rand(rng), true, rng),
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(Uniform::rand(rng), false, rng),
            ]
            .into_iter()
            .collect()
        } else if index == 2 {
            [
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(1, true, rng),
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(2, false, rng),
            ]
            .into_iter()
            .collect()
        } else if index == 3 {
            [
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(0, true, rng),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_rejected_execute(2, false, rng),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
            ]
            .into_iter()
            .collect()
        } else {
            [
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(0, true, rng),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_accepted_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    true,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_rejected_execute(3, true, rng),
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(4, false, rng),
                crate::transactions::confirmed::test_helpers::sample_rejected_execute(5, false, rng),
                crate::transactions::confirmed::test_helpers::sample_accepted_execute(6, false, rng),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    1,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
                crate::transactions::confirmed::test_helpers::sample_rejected_deploy(
                    Uniform::rand(rng),
                    2,
                    Uniform::rand(rng),
                    false,
                    false,
                    rng,
                ),
            ]
            .into_iter()
            .collect()
        }
    }

    #[test]
    fn test_serde_json() {
        let rng = &mut TestRng::default();

        let check_serde_json = |expected: Transactions<CurrentNetwork>| {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected).unwrap();

            // Deserialize
            assert_eq!(expected, Transactions::from_str(expected_string).unwrap());
            assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
        };

        // Check the serialization.
        check_serde_json(crate::transactions::test_helpers::sample_block_transactions(rng));

        for i in 0..ITERATIONS {
            // Construct the transactions.
            let expected: Transactions<CurrentNetwork> = sample_transactions(i, rng);
            // Check the serialization.
            check_serde_json(expected);
        }
    }

    #[test]
    fn test_bincode() {
        let rng = &mut TestRng::default();

        let check_bincode = |expected: Transactions<CurrentNetwork>| {
            // Serialize
            let expected_bytes = expected.to_bytes_le().unwrap();
            let expected_bytes_with_size_encoding = bincode::serialize(&expected).unwrap();
            assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

            // Deserialize
            assert_eq!(expected, Transactions::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding[..]).unwrap());
        };

        // Check the serialization.
        check_bincode(crate::transactions::test_helpers::sample_block_transactions(rng));

        for i in 0..ITERATIONS {
            // Construct the transactions.
            let expected: Transactions<CurrentNetwork> = sample_transactions(i, rng);
            // Check the serialization.
            check_bincode(expected);
        }
    }
}
