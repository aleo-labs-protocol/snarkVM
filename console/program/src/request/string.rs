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

impl<N: Network> FromStr for Request<N> {
    type Err = Error;

    /// Initializes the request from a JSON-string.
    fn from_str(request: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(request)?)
    }
}

impl<N: Network> Debug for Request<N> {
    /// Prints the request's signer and function, without its inputs or secrets.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Request")
            .field("signer", &self.signer)
            .field("network_id", &self.network_id)
            .field("program_id", &self.program_id)
            .field("function_name", &self.function_name)
            .finish_non_exhaustive()
    }
}

impl<N: Network> Display for Request<N> {
    /// Displays the request as a JSON-string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).map_err::<fmt::Error, _>(ser::Error::custom)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string() {
        let mut rng = TestRng::default();

        for expected in test_helpers::sample_requests(&mut rng).into_iter() {
            // Serialize
            let expected_string = &expected.to_string();
            let candidate_string = serde_json::to_string(&expected).unwrap();

            // Deserialize
            assert_eq!(expected, Request::from_str(expected_string).unwrap());
            assert_eq!(expected, serde_json::from_str(&candidate_string).unwrap());
        }
    }

    #[test]
    fn test_debug_is_redacted() {
        let mut rng = TestRng::default();

        for request in test_helpers::sample_requests(&mut rng).into_iter() {
            // Check the debug representation reveals no secret.
            let candidate = format!("{request:#?}");
            assert!(candidate.contains(&request.signer().to_string()));
            for secret in [request.sk_tag().to_string(), request.tvk().to_string()] {
                assert!(!candidate.contains(&secret));
            }
            for input in request.inputs() {
                assert!(!candidate.contains(&input.to_string()));
            }
        }
    }
}
