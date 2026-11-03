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

use crate::{
    polycommit::sonic_pc,
    snark::varuna::{CircuitVerifyingKey, SNARKMode, UniversalSRS, ahp::indexer::*},
};
use snarkvm_curves::PairingEngine;
use snarkvm_utilities::{FromBytes, ToBytes, serialize::*};
use std::io::{self, Read, Write};

use std::{cmp::Ordering, sync::Arc};

/// Proving key for a specific circuit (i.e., R1CS matrices).
#[derive(Clone, Debug)]
pub struct CircuitProvingKey<E: PairingEngine, SM: SNARKMode> {
    /// The circuit verifying key.
    pub circuit_verifying_key: CircuitVerifyingKey<E>,
    // NOTE: The circuit verifying key's circuit_info and circuit id are also stored in Circuit for convenience.
    /// The circuit itself.
    pub circuit: Arc<Circuit<E::Fr, SM>>,
    /// The committer key for this index, trimmed from the universal SRS.
    pub committer_key: Arc<sonic_pc::CommitterKey<E>>,
}

impl<E: PairingEngine, SM: SNARKMode> ToBytes for CircuitProvingKey<E, SM> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize_compressed(&self.circuit_verifying_key, &mut writer)?;
        CanonicalSerialize::serialize_compressed(&self.circuit, &mut writer)?;

        self.committer_key.write_le(&mut writer)
    }
}

impl<E: PairingEngine, SM: SNARKMode> FromBytes for CircuitProvingKey<E, SM> {
    #[inline]
    fn read_le<R: Read>(reader: R) -> io::Result<Self> {
        Self::read_le_sharing(reader, None)
    }
}

impl<E: PairingEngine, SM: SNARKMode> CircuitProvingKey<E, SM> {
    /// Reads a key as `read_le` does, but shares its committer key's powers
    /// with `srs`. Fails if `srs` does not hold them; see
    /// `CommitterKey::read_le_with_srs`.
    pub fn read_le_with_srs<R: Read>(reader: R, srs: &UniversalSRS<E>) -> io::Result<Self> {
        Self::read_le_sharing(reader, Some(srs))
    }

    fn read_le_sharing<R: Read>(mut reader: R, srs: Option<&UniversalSRS<E>>) -> io::Result<Self> {
        let circuit_verifying_key = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
        let circuit = CanonicalDeserialize::deserialize_compressed(&mut reader)?;
        let committer_key = Arc::new(sonic_pc::CommitterKey::read_le_sharing(&mut reader, srs)?);

        Ok(Self { circuit_verifying_key, circuit, committer_key })
    }
}

impl<E: PairingEngine, SM: SNARKMode> PartialEq for CircuitProvingKey<E, SM> {
    fn eq(&self, other: &Self) -> bool {
        self.circuit.id == other.circuit.id
    }
}

impl<E: PairingEngine, SM: SNARKMode> Eq for CircuitProvingKey<E, SM> {}

impl<E: PairingEngine, SM: SNARKMode> Ord for CircuitProvingKey<E, SM> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.circuit.id.cmp(&other.circuit.id)
    }
}

impl<E: PairingEngine, SM: SNARKMode> PartialOrd for CircuitProvingKey<E, SM> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
