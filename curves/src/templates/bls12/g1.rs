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
    templates::{
        bls12::Bls12Parameters,
        short_weierstrass_jacobian::{Affine, Projective},
    },
    traits::AffineCurve,
};
use snarkvm_fields::Zero;
use snarkvm_utilities::{ToBytes, serialize::*};

use std::io::{Result as IoResult, Write};

pub type G1Affine<P> = Affine<<P as Bls12Parameters>::G1Parameters>;
pub type G1Projective<P> = Projective<<P as Bls12Parameters>::G1Parameters>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct G1Prepared<P: Bls12Parameters>(pub G1Affine<P>);

impl<P: Bls12Parameters> G1Prepared<P> {
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn from_affine(p: G1Affine<P>) -> Self {
        G1Prepared(p)
    }
}

impl<P: Bls12Parameters> Default for G1Prepared<P> {
    fn default() -> Self {
        G1Prepared(G1Affine::<P>::prime_subgroup_generator())
    }
}

impl<P: Bls12Parameters> ToBytes for G1Prepared<P> {
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.0.write_le(writer)
    }
}
