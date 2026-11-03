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

use crate::fft::{DensePolynomial, domain::*};
use rand::RngExt;
use snarkvm_curves::bls12_377::{Fr, G1Projective};
use snarkvm_fields::{FftField, Field, One, Zero};
use snarkvm_utilities::rand::{TestRng, Uniform};

#[test]
fn vanishing_polynomial_evaluation() {
    let rng = &mut TestRng::default();

    for coeffs in 0..10 {
        let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
        let z = domain.vanishing_polynomial();
        for _ in 0..100 {
            let point: Fr = rng.random();
            assert_eq!(z.evaluate(point), domain.evaluate_vanishing_polynomial(point))
        }
    }
}

#[test]
fn vanishing_polynomial_vanishes_on_domain() {
    for coeffs in 0..1000 {
        let domain = EvaluationDomain::<Fr>::new(coeffs).unwrap();
        let z = domain.vanishing_polynomial();
        for point in domain.elements() {
            assert!(z.evaluate(point).is_zero())
        }
    }
}

#[test]
fn size_of_elements() {
    for coeffs in 1..10 {
        let size = 1 << coeffs;
        let domain = EvaluationDomain::<Fr>::new(size).unwrap();
        let domain_size = domain.size();
        assert_eq!(domain_size, domain.elements().count());
    }
}

#[test]
fn elements_contents() {
    for coeffs in 1..10 {
        let size = 1 << coeffs;
        let domain = EvaluationDomain::<Fr>::new(size).unwrap();
        for (i, element) in domain.elements().enumerate() {
            assert_eq!(element, domain.group_gen.pow([i as u64]));
        }
    }
}

/// Test that lagrange interpolation for a random polynomial at a random
/// point works.
#[test]
fn non_systematic_lagrange_coefficients_test() {
    let mut rng = TestRng::default();

    for domain_dim in 1..10 {
        let domain_size = 1 << domain_dim;
        let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        // Get random pt + lagrange coefficients
        let rand_pt = Fr::rand(&mut rng);
        let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(rand_pt);

        // Sample the random polynomial, evaluate it over the domain and the random
        // point.
        let rand_poly = DensePolynomial::<Fr>::rand(domain_size - 1, &mut rng);
        let poly_evals = domain.fft(rand_poly.coeffs());
        let actual_eval = rand_poly.evaluate(rand_pt);

        // Do lagrange interpolation, and compare against the actual evaluation
        let mut interpolated_eval = Fr::zero();
        for i in 0..domain_size {
            interpolated_eval += lagrange_coeffs[i] * poly_evals[i];
        }
        assert_eq!(actual_eval, interpolated_eval);
    }
}

/// Test that lagrange coefficients for a point in the domain is correct
#[test]
fn systematic_lagrange_coefficients_test() {
    // This runs in time O(N^2) in the domain size, so keep the domain dimension
    // low. We generate lagrange coefficients for each element in the domain.
    for domain_dim in 1..5 {
        let domain_size = 1 << domain_dim;
        let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        let all_domain_elements: Vec<Fr> = domain.elements().collect();
        for (i, element) in all_domain_elements.iter().enumerate().take(domain_size) {
            let lagrange_coeffs = domain.evaluate_all_lagrange_coefficients(*element);
            for (j, &coeff) in lagrange_coeffs.iter().enumerate().take(domain_size) {
                // Lagrange coefficient for the evaluation point, which should be 1
                if i == j {
                    assert_eq!(coeff, Fr::one());
                } else {
                    assert_eq!(coeff, Fr::zero());
                }
            }
        }
    }
}

#[test]
fn test_fft_correctness() {
    // Tests that the ffts output the correct result.
    // This assumes a correct polynomial evaluation at point procedure.
    // It tests consistency of FFT/IFFT, and coset_fft/coset_ifft,
    // along with testing that each individual evaluation is correct.

    // Runs in time O(degree^2)
    let log_degree = 5;
    let degree = 1 << log_degree;
    let rand_poly = DensePolynomial::<Fr>::rand(degree - 1, &mut TestRng::default());

    for log_domain_size in log_degree..(log_degree + 2) {
        let domain_size = 1 << log_domain_size;
        let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        let poly_evals = domain.fft(&rand_poly.coeffs);
        let poly_coset_evals = domain.coset_fft(&rand_poly.coeffs);
        for (i, x) in domain.elements().enumerate() {
            let coset_x = Fr::multiplicative_generator() * x;

            assert_eq!(poly_evals[i], rand_poly.evaluate(x));
            assert_eq!(poly_coset_evals[i], rand_poly.evaluate(coset_x));
        }

        let rand_poly_from_subgroup = DensePolynomial::from_coefficients_vec(domain.ifft(&poly_evals));
        let rand_poly_from_coset = DensePolynomial::from_coefficients_vec(domain.coset_ifft(&poly_coset_evals));

        assert_eq!(rand_poly, rand_poly_from_subgroup, "degree = {degree}, domain size = {domain_size}");
        assert_eq!(rand_poly, rand_poly_from_coset, "degree = {degree}, domain size = {domain_size}");
    }
}

#[test]
fn test_roots_of_unity() {
    // Tests that the roots of unity result is the same as domain.elements()
    let max_degree = 10;
    for log_domain_size in 0..max_degree {
        let domain_size = 1 << log_domain_size;
        let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        let actual_roots = domain.roots_of_unity(domain.group_gen);
        for &value in &actual_roots {
            assert!(domain.evaluate_vanishing_polynomial(value).is_zero());
        }
        let expected_roots_elements = domain.elements();
        for (expected, &actual) in expected_roots_elements.zip(&actual_roots) {
            assert_eq!(expected, actual);
        }
        assert_eq!(actual_roots.len(), domain_size / 2);
    }
}

#[test]
#[cfg(not(feature = "serial"))]
fn parallel_fft_consistency() {
    // This implements the Cooley-Turkey FFT, derived from libfqfft
    // The libfqfft implementation uses pseudocode from [CLRS 2n Ed, pp. 864].
    fn serial_radix2_fft(a: &mut [Fr], omega: Fr, log_n: u32) {
        #[inline]
        pub(crate) fn bitreverse(mut n: u32, l: u32) -> u32 {
            let mut r = 0;
            for _ in 0..l {
                r = (r << 1) | (n & 1);
                n >>= 1;
            }
            r
        }
        use core::convert::TryFrom;
        let n = u32::try_from(a.len()).expect("cannot perform FFTs larger on vectors of len > (1 << 32)");
        assert_eq!(n, 1 << log_n);

        // swap coefficients in place
        for k in 0..n {
            let rk = bitreverse(k, log_n);
            if k < rk {
                a.swap(rk as usize, k as usize);
            }
        }

        let mut m = 1;
        for _i in 1..=log_n {
            // w_m is 2^i-th root of unity
            let w_m = omega.pow([(n / (2 * m)) as u64]);

            let mut k = 0;
            while k < n {
                // w = w_m^j at the start of every loop iteration
                let mut w = Fr::one();
                for j in 0..m {
                    let mut t = a[(k + j + m) as usize];
                    t *= w;
                    let mut tmp = a[(k + j) as usize];
                    tmp -= t;
                    a[(k + j + m) as usize] = tmp;
                    a[(k + j) as usize] += t;
                    w *= &w_m;
                }

                k += 2 * m;
            }

            m *= 2;
        }
    }

    fn serial_radix2_ifft(a: &mut [Fr], omega: Fr, log_n: u32) {
        serial_radix2_fft(a, omega.inverse().unwrap(), log_n);
        let domain_size_inv = Fr::from(a.len() as u64).inverse().unwrap();
        for coeff in a.iter_mut() {
            *coeff *= domain_size_inv;
        }
    }

    fn serial_radix2_coset_fft(a: &mut [Fr], omega: Fr, log_n: u32) {
        let coset_shift = Fr::multiplicative_generator();
        let mut cur_pow = Fr::one();
        for coeff in a.iter_mut() {
            *coeff *= cur_pow;
            cur_pow *= coset_shift;
        }
        serial_radix2_fft(a, omega, log_n);
    }

    fn serial_radix2_coset_ifft(a: &mut [Fr], omega: Fr, log_n: u32) {
        serial_radix2_ifft(a, omega, log_n);
        let coset_shift = Fr::multiplicative_generator().inverse().unwrap();
        let mut cur_pow = Fr::one();
        for coeff in a.iter_mut() {
            *coeff *= cur_pow;
            cur_pow *= coset_shift;
        }
    }

    fn test_consistency<R: RngExt>(rng: &mut R, max_coeffs: u32) {
        for _ in 0..5 {
            for log_d in 0..max_coeffs {
                let d = 1 << log_d;

                let expected_poly = (0..d).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                let mut expected_vec = expected_poly.clone();
                let mut actual_vec = expected_vec.clone();

                let domain = EvaluationDomain::new(d).unwrap();

                serial_radix2_fft(&mut expected_vec, domain.group_gen, log_d);
                domain.fft_in_place(&mut actual_vec);
                assert_eq!(expected_vec, actual_vec);

                serial_radix2_ifft(&mut expected_vec, domain.group_gen, log_d);
                domain.ifft_in_place(&mut actual_vec);
                assert_eq!(expected_vec, actual_vec);
                assert_eq!(expected_vec, expected_poly);

                serial_radix2_coset_fft(&mut expected_vec, domain.group_gen, log_d);
                domain.coset_fft_in_place(&mut actual_vec);
                assert_eq!(expected_vec, actual_vec);

                serial_radix2_coset_ifft(&mut expected_vec, domain.group_gen, log_d);
                domain.coset_ifft_in_place(&mut actual_vec);
                assert_eq!(expected_vec, actual_vec);
            }
        }
    }

    let rng = &mut TestRng::default();

    test_consistency(rng, 10);
}

#[test]
fn fft_composition() {
    fn test_fft_composition<F: FftField, T: crate::fft::DomainCoeff<F> + Uniform + core::fmt::Debug + Eq, R: RngExt>(
        rng: &mut R,
        max_coeffs: usize,
    ) {
        for coeffs in 0..max_coeffs {
            let coeffs = 1 << coeffs;

            let domain = EvaluationDomain::new(coeffs).unwrap();

            let mut v = vec![];
            for _ in 0..coeffs {
                v.push(T::rand(rng));
            }
            // Fill up with zeros.
            v.resize(domain.size(), T::zero());
            let mut v2 = v.clone();

            domain.ifft_in_place(&mut v2);
            domain.fft_in_place(&mut v2);
            assert_eq!(v, v2, "ifft(fft(.)) != iden");

            domain.fft_in_place(&mut v2);
            domain.ifft_in_place(&mut v2);
            assert_eq!(v, v2, "fft(ifft(.)) != iden");

            domain.coset_ifft_in_place(&mut v2);
            domain.coset_fft_in_place(&mut v2);
            assert_eq!(v, v2, "coset_fft(coset_ifft(.)) != iden");

            domain.coset_fft_in_place(&mut v2);
            domain.coset_ifft_in_place(&mut v2);
            assert_eq!(v, v2, "coset_ifft(coset_fft(.)) != iden");
        }
    }

    let rng = &mut TestRng::default();

    test_fft_composition::<Fr, Fr, _>(rng, 10);
    test_fft_composition::<Fr, G1Projective, _>(rng, 10);
}

#[test]
fn evaluate_over_domain() {
    let rng = &mut TestRng::default();

    for domain_size in (1..10).map(|i| 2usize.pow(i)) {
        let domain = EvaluationDomain::<Fr>::new(domain_size).unwrap();
        for degree in [domain_size - 2, domain_size - 1, domain_size + 10] {
            let p = DensePolynomial::rand(degree, rng);
            assert_eq!(
                p.evaluate_over_domain_by_ref(domain).evaluations,
                domain.elements().map(|e| p.evaluate(e)).collect::<Vec<_>>()
            );
        }
    }
}
