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

impl<N: Network> FromStr for Authorization<N> {
    type Err = Error;

    /// Initializes the authorization from a JSON-string.
    fn from_str(authorization: &str) -> Result<Self, Self::Err> {
        Ok(serde_json::from_str(authorization)?)
    }
}

impl<N: Network> Debug for Authorization<N> {
    /// Prints the authorization's requests and transition IDs, without the requests' inputs or secrets.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("requests", &*self.requests.read())
            .field("transition_ids", &self.transitions.read().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl<N: Network> Display for Authorization<N> {
    /// Displays the authorization as a JSON-string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).map_err::<fmt::Error, _>(ser::Error::custom)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_is_redacted() {
        let rng = &mut TestRng::default();

        // Sample the authorization.
        let authorization = crate::stack::authorization::test_helpers::sample_authorization(rng);

        // Check the debug representation reveals no secret.
        let candidate = format!("{authorization:#?}");
        for request in authorization.to_vec_deque() {
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
