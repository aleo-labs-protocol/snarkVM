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

/// The error type for `PolynomialCommitment`.
#[derive(Debug, Error)]
pub enum PCError {
    #[error(transparent)]
    AnyhowError(#[from] anyhow::Error),

    #[error("QuerySet` refers to polynomial \"{label}\", but it was not provided.")]
    MissingPolynomial {
        /// The label of the missing polynomial
        label: String,
    },

    #[error("`QuerySet` refers to polynomial \"{label}\", but `Evaluations` does not contain an evaluation for it.")]
    MissingEvaluation {
        /// The label of the missing polynomial.
        label: String,
    },

    #[error("The provided polynomial was meant to be hiding, but `rng` was `None`.")]
    MissingRng,

    #[error("The degree provided in setup was too small; degree 0 polynomials are not supported.")]
    DegreeIsZero,

    #[error(
        "the number of coefficients in the polynomial ({num_coefficients:?}) is greater than \
             the maximum number of powers in `Powers` ({num_powers:?})"
    )]
    TooManyCoefficients {
        /// The number of coefficients in the polynomial.
        num_coefficients: usize,
        /// The maximum number of powers provided in `Powers`.
        num_powers: usize,
    },

    #[error("The hiding bound was not `None`, but the hiding bound was zero.")]
    HidingBoundIsZero,

    #[error(
        "the degree of the hiding poly ({hiding_poly_degree:?}) is not less than the maximum number of powers in `Powers` ({num_powers:?})"
    )]
    HidingBoundToolarge {
        /// The hiding bound
        hiding_poly_degree: usize,
        /// The number of powers.
        num_powers: usize,
    },

    #[error("The lagrange basis is not a power of two.")]
    LagrangeBasisSizeIsNotPowerOfTwo,

    #[error("The lagrange basis is larger than the supported degree.")]
    LagrangeBasisSizeIsTooLarge,

    #[error("The degree provided to `trim` was too large.")]
    TrimmingDegreeTooLarge,

    #[error("the equation \"{0}\" contained degree-bounded polynomials")]
    EquationHasDegreeBounds(String),

    #[error("the degree bound ({0}) is not supported by the parameters")]
    UnsupportedDegreeBound(usize),

    #[error("the Lagrange basis size ({0}) is not supported by the parameters")]
    UnsupportedLagrangeBasisSize(usize),

    #[error(
        "the degree bound ({degree_bound}) for the polynomial {label} \
        (having degree {poly_degree}) is greater than the maximum degree ({max_degree})"
    )]
    IncorrectDegreeBound {
        /// Degree of the polynomial.
        poly_degree: usize,
        /// Degree bound.
        degree_bound: usize,
        /// Maximum degree.
        max_degree: usize,
        /// Index of the offending polynomial.
        label: String,
    },
}
