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

use snarkvm_utilities::DeserializeExt;

impl<N: Network> Serialize for Request<N> {
    /// Serializes the request into string or bytes.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut request = serializer.serialize_struct("Request", 12)?;
                request.serialize_field("signer", &self.signer)?;
                request.serialize_field("network", &self.network_id)?;
                request.serialize_field("program", &self.program_id)?;
                request.serialize_field("function", &self.function_name)?;
                request.serialize_field("input_ids", &self.input_ids)?;
                request.serialize_field("inputs", &self.inputs)?;
                request.serialize_field("signature", &self.signature)?;
                request.serialize_field("sk_tag", &self.sk_tag)?;
                request.serialize_field("tvk", &self.tvk)?;
                request.serialize_field("tcm", &self.tcm)?;
                request.serialize_field("scm", &self.scm)?;
                request.serialize_field("is_dynamic", &self.is_dynamic)?;
                request.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Request<N> {
    /// Deserializes the request from a string or bytes.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                // Parse the request from a string into a value.
                let mut request = serde_json::Value::deserialize(deserializer)?;

                // Recover the request.
                Ok(Self::from((
                    // Retrieve the signer.
                    DeserializeExt::take_from_value::<D>(&mut request, "signer")?,
                    // Retrieve the network ID.
                    DeserializeExt::take_from_value::<D>(&mut request, "network")?,
                    // Retrieve the program ID.
                    DeserializeExt::take_from_value::<D>(&mut request, "program")?,
                    // Retrieve the function name.
                    DeserializeExt::take_from_value::<D>(&mut request, "function")?,
                    // Retrieve the input IDs.
                    DeserializeExt::take_from_value::<D>(&mut request, "input_ids")?,
                    // Retrieve the inputs.
                    DeserializeExt::take_from_value::<D>(&mut request, "inputs")?,
                    // Retrieve the signature.
                    DeserializeExt::take_from_value::<D>(&mut request, "signature")?,
                    // Retrieve the `sk_tag`.
                    DeserializeExt::take_from_value::<D>(&mut request, "sk_tag")?,
                    // Retrieve the `tvk`.
                    DeserializeExt::take_from_value::<D>(&mut request, "tvk")?,
                    // Retrieve the `tcm`.
                    DeserializeExt::take_from_value::<D>(&mut request, "tcm")?,
                    // Retrieve the `scm`.
                    DeserializeExt::take_from_value::<D>(&mut request, "scm")?,
                    // Retrieve the `is_dynamic` flag. V1 requests don't have this field, default to false.
                    DeserializeExt::take_from_value::<D>(&mut request, "is_dynamic").unwrap_or(false),
                )))
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "request"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_json() -> Result<()> {
        let mut rng = TestRng::default();

        for expected in test_helpers::sample_requests(&mut rng).into_iter() {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected)?;

            // Deserialize
            assert_eq!(expected, Request::from_str(expected_string)?);
            assert_eq!(expected, serde_json::from_str(&candidate_string)?);
        }
        Ok(())
    }

    #[test]
    fn test_bincode() {
        let mut rng = TestRng::default();

        for expected in test_helpers::sample_requests(&mut rng).into_iter() {
            // Serialize
            let expected_bytes = expected.to_bytes_le().unwrap();
            let expected_bytes_with_size_encoding = bincode::serialize(&expected).unwrap();
            assert_eq!(&expected_bytes[..], &expected_bytes_with_size_encoding[8..]);

            // Deserialize
            assert_eq!(expected, Request::read_le(&expected_bytes[..]).unwrap());
            assert_eq!(expected, bincode::deserialize(&expected_bytes_with_size_encoding).unwrap());
        }
    }
}
