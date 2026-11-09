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

use crate::polycommit::kzg10;
use snarkvm_curves::{PairingCurve, PairingEngine};

use std::{collections::BTreeMap, sync::Arc};

/// `UniversalVerifier` is used to check evaluation proofs for a given
/// commitment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UniversalVerifier<E: PairingEngine> {
    /// The verification key for the underlying KZG10 scheme.
    pub vk: kzg10::VerifierKey<E>,
    /// Information required to enforce degree bounds. Each pair is of the form
    /// `(degree_bound, shifting_advice)`. Each pair is in the form
    /// `(d, \beta^{-(max_degree - d)} H)`, where `H` is the generator of G2,
    /// and the degree bound `d` is of the form `2^k - 2`.
    pub prepared_negative_powers_of_beta_h: Arc<BTreeMap<usize, <E::G2Affine as PairingCurve>::Prepared>>,
}
