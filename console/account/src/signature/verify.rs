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

impl<N: Network> Signature<N> {
    /// Verifies (challenge == challenge') && (address == address') where:
    ///     challenge' := HashToScalar(G^response pk_sig^challenge, pk_sig, pr_sig, address, message)
    pub fn verify(&self, address: &Address<N>, message: &[Field<N>]) -> bool {
        self.verify_challenge(address, message, None) && *address == self.to_address()
    }

    /// Returns the signer's address if the signature is valid for `message`, and `None` otherwise.
    pub fn verify_and_recover_signer(&self, message: &[Field<N>]) -> Option<Address<N>> {
        // A normalized address converts to affine, for hashing and comparison, without an inversion.
        let address = Address::new(self.to_address().normalized());
        self.verify_challenge(&address, message, None).then_some(address)
    }

    /// Verifies challenge == challenge', where:
    ///     challenge' := HashToScalar(G^response pk_sig^challenge, pk_sig, pr_sig, address, message)
    ///
    /// A `pk_sig_table` built from this signature's `pk_sig` speeds up the check. Any other table is ignored.
    pub(crate) fn verify_challenge(
        &self,
        address: &Address<N>,
        message: &[Field<N>],
        pk_sig_table: Option<&GroupWindowTable<N>>,
    ) -> bool {
        // Ensure the number of field elements does not exceed the maximum allowed size.
        if message.len() > N::MAX_DATA_SIZE_IN_FIELDS as usize {
            eprintln!("Cannot sign the signature: the signed message exceeds maximum allowed size");
            return false;
        }

        // Retrieve pk_sig.
        let pk_sig = self.compute_key.pk_sig();
        // Retrieve pr_sig.
        let pr_sig = self.compute_key.pr_sig();

        // Compute `challenge * pk_sig`. A table built from another element would bind the signature to the wrong key.
        let pk_sig_challenge = match pk_sig_table {
            Some(table) if table.base() == pk_sig => table.mul(&self.challenge),
            _ => pk_sig * self.challenge,
        };
        // Compute `g_r` := (response * G) + (challenge * pk_sig).
        let g_r = N::g_scalar_multiply_public(&self.response) + pk_sig_challenge;

        // Construct the hash input as (r * G, pk_sig, pr_sig, address, message).
        let mut preimage = Vec::with_capacity(4 + message.len());
        preimage.extend([g_r, pk_sig, pr_sig, **address].map(|point| point.to_x_coordinate()));
        preimage.extend(message);

        // Hash to derive the verifier challenge, and return `false` if this operation fails.
        match N::hash_to_scalar_psd8(&preimage) {
            Ok(candidate_challenge) => self.challenge == candidate_challenge,
            Err(_) => false,
        }
    }

    /// Verifies a signature for the given address and message (as bytes).
    pub fn verify_bytes(&self, address: &Address<N>, message: &[u8]) -> bool {
        // Convert the message into bits, and verify the signature.
        self.verify_bits(address, &message.to_bits_le())
    }

    /// Verifies a signature for the given address and message (as bits).
    pub fn verify_bits(&self, address: &Address<N>, message: &[bool]) -> bool {
        // Pack the bits into field elements.
        match message.chunks(Field::<N>::size_in_data_bits()).map(Field::from_bits_le).collect::<Result<Vec<_>>>() {
            Ok(fields) => self.verify(address, &fields),
            Err(error) => {
                eprintln!("Failed to verify signature: {error}");
                false
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "private_key")]
mod tests {
    use super::*;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    const ITERATIONS: u64 = 100;

    #[test]
    fn test_sign_and_verify() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign(&private_key, &message, rng)?;
            assert!(signature.verify(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify(&address, &failure_message));
            }
        }
        Ok(())
    }

    #[test]
    fn test_verify_and_recover_signer() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign(&private_key, &message, rng)?;
            let table = GroupWindowTable::new(&signature.compute_key().pk_sig());

            // Check that a valid signature recovers its signer.
            assert_eq!(signature.verify_and_recover_signer(&message), Some(address));
            assert!(signature.verify_challenge(&address, &message, Some(&table)));
            // Check that a signature over another message recovers nothing.
            if message != failure_message {
                assert_eq!(signature.verify_and_recover_signer(&failure_message), None);
                assert!(!signature.verify_challenge(&address, &failure_message, Some(&table)));
            }

            // Check that a message over the size limit recovers nothing, as `verify` rejects it.
            let oversized = vec![Field::<CurrentNetwork>::zero(); CurrentNetwork::MAX_DATA_SIZE_IN_FIELDS as usize + 1];
            assert!(!signature.verify(&address, &oversized));
            assert_eq!(signature.verify_and_recover_signer(&oversized), None);
        }
        Ok(())
    }

    #[test]
    fn test_verify_ignores_a_table_for_another_key() -> Result<()> {
        let rng = &mut TestRng::default();

        for _ in 0..ITERATIONS {
            // A signer whose secret key is known to the forger.
            let forger_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let forger_table = GroupWindowTable::new(&ComputeKey::try_from(&forger_key)?.pk_sig());

            // The victim's compute key, with a signature made with the forger's `sk_sig`.
            let victim = ComputeKey::try_from(&PrivateKey::<CurrentNetwork>::new(rng)?)?;
            let victim_address = victim.to_address();
            let message = [Field::<CurrentNetwork>::rand(rng)];
            let nonce = Scalar::<CurrentNetwork>::rand(rng);
            let g_r = CurrentNetwork::g_scalar_multiply(&nonce);
            let preimage = [g_r, victim.pk_sig(), victim.pr_sig(), *victim_address]
                .map(|point| point.to_x_coordinate())
                .into_iter()
                .chain(message)
                .collect::<Vec<_>>();
            let challenge = CurrentNetwork::hash_to_scalar_psd8(&preimage)?;
            let response = nonce - challenge * forger_key.sk_sig();
            let forgery = Signature::from((challenge, response, victim));

            // With the forger's table in place of the victim's `pk_sig`, the forgery would verify.
            assert_eq!(forger_table.mul(&challenge) + CurrentNetwork::g_scalar_multiply(&response), g_r);
            // `verify_challenge` ignores the mismatched table, so the forgery fails.
            assert!(!forgery.verify_challenge(&victim_address, &message, Some(&forger_table)));
        }
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_bytes() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign_bytes(&private_key, &message, rng)?;
            assert!(signature.verify_bytes(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bytes(&address, &failure_message));
            }
        }
        Ok(())
    }

    #[test]
    fn test_sign_and_verify_bits() -> Result<()> {
        let rng = &mut TestRng::default();

        for i in 0..ITERATIONS {
            // Sample an address and a private key.
            let private_key = PrivateKey::<CurrentNetwork>::new(rng)?;
            let address = Address::try_from(&private_key)?;

            // Check that the signature is valid for the message.
            let message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            let signature = Signature::sign_bits(&private_key, &message, rng)?;
            assert!(signature.verify_bits(&address, &message));

            // Check that the signature is invalid for an incorrect message.
            let failure_message: Vec<_> = (0..i).map(|_| Uniform::rand(rng)).collect();
            if message != failure_message {
                assert!(!signature.verify_bits(&address, &failure_message));
            }
        }
        Ok(())
    }
}
