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

#[cfg(test)]
pub mod tests;

mod serialize;

use super::*;
use snarkvm_utilities::bytes_from_bits_le;

use k256::{
    Secp256k1,
    ecdsa::{
        RecoveryId as ECDSARecoveryId,
        Signature,
        SigningKey,
        VerifyingKey,
        signature::hazmat::{PrehashSigner, PrehashVerifier},
    },
    elliptic_curve::{Curve, array::typenum::Unsigned},
};

/// The recovery ID for an ECDSA/Secp256k1 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryID {
    /// The recovery ID.
    pub recovery_id: ECDSARecoveryId,
    /// The Ethereum chain ID (if applicable).
    /// None = non-Ethereum canonical
    /// Some(0) = ETH legacy (v = 27 or 28)
    /// Some(id>=1) = EIP-155(id).
    pub chain_id: Option<u64>,
}

impl RecoveryID {
    /// The offset to add to the recovery ID for EIP-155 signatures (>= 35).
    const ETH_EIP155_OFFSET: u8 = 35;
    /// The offset to add to the recovery ID for legacy Ethereum signatures (27 or 28).
    const ETH_LEGACY_OFFSET: u8 = 27;

    /// For your *byte* encoding (not raw Ethereum tx `v`):
    /// - Standard (None): write 0..=3
    /// - ETH legacy (Some(0)): write 27/28
    /// - EIP-155 (Some(id>=1)): still just write y (0/1); full `v` is derived via `to_eth_v`.
    #[inline]
    fn encoded_byte(&self) -> Result<u8> {
        let recovery_id = self.recovery_id.to_byte();
        match self.chain_id {
            // Standard
            None => Ok(recovery_id),
            // ETH legacy
            Some(0) => Ok(recovery_id.saturating_add(Self::ETH_LEGACY_OFFSET)), // 27/28
            // EIP-155
            Some(chain_id) => {
                let recovery_id = (recovery_id as u64)
                    .saturating_add(chain_id.saturating_mul(2))
                    .saturating_add(Self::ETH_EIP155_OFFSET as u64);
                Ok(u8::try_from(recovery_id)?)
            }
        }
    }
}

impl ToBytes for RecoveryID {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let encoded_byte = self.encoded_byte().map_err(error)?;
        encoded_byte.write_le(&mut writer)
    }
}

impl FromBytes for RecoveryID {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the recovery ID byte.
        let recovery_id_byte = u8::read_le(&mut reader)?;

        // Determine if the recovery ID follows the Ethereum convention.
        let (recovery_id_without_offset, chain_id) = match recovery_id_byte {
            27 | 28 => (recovery_id_byte.saturating_sub(Self::ETH_LEGACY_OFFSET), Some(0u64)),
            v if v >= Self::ETH_EIP155_OFFSET => {
                let y = (v.saturating_sub(Self::ETH_EIP155_OFFSET)) % 2;
                let id = (v.saturating_sub(Self::ETH_EIP155_OFFSET)) / 2;
                (y, Some(id as u64))
            }
            _ => (recovery_id_byte, None),
        };

        // Construct the recovery ID from the byte.
        let recovery_id = ECDSARecoveryId::from_byte(recovery_id_without_offset)
            .ok_or_else(|| error(format!("Invalid recovery ID byte {recovery_id_byte}")))?;
        Ok(Self { recovery_id, chain_id })
    }
}

/// An ECDSA/Secp256k1 signature (r,s) signature along with the recovery ID.
#[derive(Clone, PartialEq, Eq)]
pub struct ECDSASignature {
    /// The (r,s) signature.
    pub signature: Signature,
    /// The recovery ID.
    pub recovery_id: RecoveryID,
}

impl ECDSASignature {
    ///  The base signature size in bytes for secp256k1.
    pub const BASE_SIGNATURE_SIZE_IN_BYTES: usize = <Secp256k1 as Curve>::FieldBytesSize::USIZE * 2;
    /// The size of an Ethereum address in bytes.
    pub const ETHEREUM_ADDRESS_SIZE_IN_BYTES: usize = 20;
    /// The prehash size in bytes for secp256k1.
    pub const PREHASH_SIZE_IN_BYTES: usize = <Secp256k1 as Curve>::FieldBytesSize::USIZE;
    /// The ECDSA Signature size in bits for secp256k1 (including the one-byte recovery ID).
    pub const SIGNATURE_SIZE_IN_BYTES: usize = Self::BASE_SIGNATURE_SIZE_IN_BYTES + 1;
    /// The compressed VerifyingKey size in bytes for secp256k1 (32 byte field + one-byte header).
    pub const VERIFYING_KEY_SIZE_IN_BYTES: usize = <Secp256k1 as Curve>::FieldBytesSize::USIZE + 1;

    /// Returns the recovery ID.
    pub const fn recovery_id(&self) -> ECDSARecoveryId {
        self.recovery_id.recovery_id
    }

    /// Returns a signature on a `message` using the given `signing_key` and hash function.
    pub fn sign<H: Hash<Output = Vec<bool>>>(
        signing_key: &SigningKey,
        hasher: &H,
        message: &[H::Input],
    ) -> Result<Self> {
        // Hash the message.
        let hash_bits = hasher.hash(message)?;
        // Convert the hash output to bytes.
        let hash_bytes = bytes_from_bits_le(&hash_bits);

        // Sign the prehashed message.
        signing_key
            .sign_prehash(&hash_bytes)
            .map(|(signature, recovery_id)| {
                let recovery_id = RecoveryID { recovery_id, chain_id: None };
                Self { signature, recovery_id }
            })
            .map_err(|e| anyhow!("Failed to sign message: {e:?}"))
    }

    /// Recover the public key from `(r,s, recovery_id)` using *your* hasher on `message`.
    pub fn recover_public_key<H: Hash<Output = Vec<bool>>>(
        &self,
        hasher: &H,
        message: &[H::Input],
    ) -> Result<VerifyingKey> {
        // Hash the message.
        let hash_bits = hasher.hash(message)?;

        // Recover the public key using the prehash.
        self.recover_public_key_with_digest(&hash_bits)
    }

    /// Recover the public key from `(r,s, recovery_id)` using *your* hasher on `message`.
    pub fn recover_public_key_with_digest(&self, digest_bits: &[bool]) -> Result<VerifyingKey> {
        // Convert the digest output to bytes.
        let digest = bytes_from_bits_le(digest_bits);

        // Recover the public key using the prehash.
        VerifyingKey::recover_from_prehash(&digest, &self.signature, self.recovery_id())
            .map_err(|e| anyhow!("Failed to recover public key: {e:?}"))
    }

    /// Verify `(r,s)` against `verifying_key` using *your* hasher on `message`.
    pub fn verify<H: Hash<Output = Vec<bool>>>(
        &self,
        verifying_key: &VerifyingKey,
        hasher: &H,
        message: &[H::Input],
    ) -> Result<()> {
        // Hash the message.
        let hash_bits = hasher.hash(message)?;

        // Verify the signature using the prehash.
        self.verify_with_digest(verifying_key, &hash_bits)
    }

    /// Verify `(r,s)` against `verifying_key` using the provided `digest`.
    pub fn verify_with_digest(&self, verifying_key: &VerifyingKey, digest_bits: &[bool]) -> Result<()> {
        // Convert the digest output to bytes.
        let digest = bytes_from_bits_le(digest_bits);

        // Verify the signature using the prehash digest.
        verifying_key.verify_prehash(&digest, &self.signature).map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
    }

    /// Verify `(r,s)` against `verifying_key` using *your* hasher on `message`.
    pub fn verify_ethereum<H: Hash<Output = Vec<bool>>>(
        &self,
        ethereum_address: &[u8; Self::ETHEREUM_ADDRESS_SIZE_IN_BYTES],
        hasher: &H,
        message: &[H::Input],
    ) -> Result<()> {
        // Hash the message.
        let hash_bits = hasher.hash(message)?;

        // Ensure that the derived Ethereum address matches the provided one.
        self.verify_ethereum_with_digest(ethereum_address, &hash_bits)
    }

    /// Verify `(r,s)` against `verifying_key` using *your* hasher on `message`.
    pub fn verify_ethereum_with_digest(
        &self,
        ethereum_address: &[u8; Self::ETHEREUM_ADDRESS_SIZE_IN_BYTES],
        digest_bits: &[bool],
    ) -> Result<()> {
        // Derive the verifying key from the signature.
        let verifying_key = self.recover_public_key_with_digest(digest_bits)?;

        // Ensure that the derived Ethereum address matches the provided one.
        let derived_ethereum_address = Self::ethereum_address_from_public_key(&verifying_key)?;
        ensure!(
            &derived_ethereum_address == ethereum_address,
            "Derived Ethereum address does not match the provided address."
        );

        Ok(())
    }

    /// Converts a VerifyingKey to an Ethereum address (20 bytes).
    pub fn ethereum_address_from_public_key(
        verifying_key: &VerifyingKey,
    ) -> Result<[u8; Self::ETHEREUM_ADDRESS_SIZE_IN_BYTES]> {
        // Get the uncompressed public key bytes as [0x04, x_bytes..., y_bytes...]
        let public_key_point = verifying_key.to_sec1_point(false);
        let public_key_bytes = public_key_point.as_bytes();

        // Skip the 0x04 prefix, keep only the x and y coordinates (64 bytes)
        let coordinates_only = &public_key_bytes[1..]; // 32 bytes x + 32 bytes y

        // Step 3: Hash the coordinates with Keccak256
        let address_hash = Keccak256::default().hash(&coordinates_only.to_bits_le())?;
        let address_bytes = bytes_from_bits_le(&address_hash);

        // Step 4: Take the last 20 bytes as the Ethereum address
        let mut ethereum_address = [0u8; Self::ETHEREUM_ADDRESS_SIZE_IN_BYTES];
        ethereum_address.copy_from_slice(&address_bytes[12..32]);

        Ok(ethereum_address)
    }

    /// Parses a verifying key from bytes.
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
        VerifyingKey::from_sec1_bytes(bytes).map_err(|e| anyhow!("Failed to parse verifying key: {e:?}"))
    }
}

impl ToBytes for ECDSASignature {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the signature bytes.
        self.signature.to_bytes().to_vec().write_le(&mut writer)?;
        // Write the recovery ID.
        self.recovery_id.write_le(&mut writer)
    }
}

impl FromBytes for ECDSASignature {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the signature bytes.
        let mut bytes = vec![0u8; Self::BASE_SIGNATURE_SIZE_IN_BYTES];
        reader.read_exact(&mut bytes)?;
        // Construct the signature from the bytes.
        let signature = Signature::from_slice(&bytes).map_err(error)?;

        // Read the recovery ID
        let recovery_id = RecoveryID::read_le(&mut reader)?;

        Ok(Self { signature, recovery_id })
    }
}

impl FromStr for ECDSASignature {
    type Err = Error;

    /// Parses a hex-encoded string into an ECDSASignature.
    fn from_str(signature: &str) -> Result<Self, Self::Err> {
        let mut s = signature.trim();

        // Accept optional 0x prefix
        if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            s = rest;
        }

        // Decode the hex string into bytes.
        let bytes = hex::decode(s)?;

        // Construct the signature from the bytes.
        Self::from_bytes_le(&bytes)
    }
}

impl Debug for ECDSASignature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for ECDSASignature {
    /// Writes the signature as a hex string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes_le().map_err(|_| fmt::Error)?))
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    use k256::elliptic_curve::Generate;

    pub(crate) type DefaultHasher = Keccak256;

    /// Samples a random ecdsa signature.
    pub(super) fn sample_ecdsa_signature<H: Hash<Output = Vec<bool>, Input = bool>>(
        num_bytes: usize,
        hasher: &H,
        rng: &mut TestRng,
    ) -> (SigningKey, Vec<u8>, ECDSASignature) {
        // Sample a random signing key.
        let signing_key = SigningKey::generate_from_rng(rng);

        // Sample a random message.
        let message: Vec<u8> = (0..num_bytes).map(|_| rng.random()).collect::<Vec<_>>();

        // Sign the message.
        let signature = ECDSASignature::sign::<H>(&signing_key, hasher, &message.to_bits_le()).unwrap();

        // Return the signing key, message, and signature.
        (signing_key, message, signature)
    }
}
