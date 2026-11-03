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

use std::{borrow::Borrow, collections::BTreeMap};

use crate::fft::domain::{FFTPrecomputation, IFFTPrecomputation};

/// A struct that helps multiply a batch of polynomials
use super::*;
use snarkvm_utilities::{ExecutionPool, cfg_into_iter, cfg_iter, cfg_reduce_with};

#[derive(Default)]
pub struct PolyMultiplier<'a, F: PrimeField> {
    polynomials: Vec<(String, Cow<'a, DensePolynomial<F>>)>,
    evaluations: Vec<(String, Cow<'a, crate::fft::Evaluations<F>>)>,
    fft_precomputation: Option<Cow<'a, FFTPrecomputation<F>>>,
    ifft_precomputation: Option<Cow<'a, IFFTPrecomputation<F>>>,
}

impl<'a, F: PrimeField> PolyMultiplier<'a, F> {
    #[inline]
    pub fn new() -> Self {
        Self { polynomials: Vec::new(), evaluations: Vec::new(), fft_precomputation: None, ifft_precomputation: None }
    }

    #[inline]
    pub fn add_precomputation(&mut self, fft_pc: &'a FFTPrecomputation<F>, ifft_pc: &'a IFFTPrecomputation<F>) {
        self.fft_precomputation = Some(Cow::Borrowed(fft_pc));
        self.ifft_precomputation = Some(Cow::Borrowed(ifft_pc));
    }

    #[inline]
    pub fn add_polynomial(&mut self, poly: DensePolynomial<F>, label: impl ToString) {
        self.polynomials.push((label.to_string(), Cow::Owned(poly)))
    }

    #[inline]
    pub fn add_evaluation(&mut self, evals: Evaluations<F>, label: impl ToString) {
        self.evaluations.push((label.to_string(), Cow::Owned(evals)))
    }

    #[inline]
    pub fn add_polynomial_ref(&mut self, poly: &'a DensePolynomial<F>, label: impl ToString) {
        self.polynomials.push((label.to_string(), Cow::Borrowed(poly)))
    }

    #[inline]
    pub fn add_evaluation_ref(&mut self, evals: &'a Evaluations<F>, label: impl ToString) {
        self.evaluations.push((label.to_string(), Cow::Borrowed(evals)))
    }

    /// Multiplies all polynomials stored in `self`.
    ///
    /// Returns `None` if any of the stored evaluations are over a domain that's
    /// insufficiently large to interpolate the product, or if `F` does not
    /// contain a sufficiently large subgroup for interpolation.
    pub fn multiply(self) -> Option<DensePolynomial<F>> {
        #[cfg(all(feature = "cuda", target_arch = "x86_64"))]
        if crate::fft::is_cuda_field::<F>() {
            if self.polynomials.is_empty() && self.evaluations.is_empty() {
                return Some(DensePolynomial::zero());
            }
            let degree = self.polynomials.iter().map(|(_, p)| p.degree() + 1).sum::<usize>();
            let domain = EvaluationDomain::new(degree)?;
            if self.evaluations.iter().any(|(_, e)| e.domain() != domain) {
                return None;
            }
            // Two or more operands over a one-element domain run on the host.
            if snarkvm_algorithms_cuda::polymul_supports(domain.size(), self.polynomials.len() + self.evaluations.len())
            {
                let poly_slices: Vec<&[F]> = self.polynomials.iter().map(|(_, p)| p.coeffs()).collect();
                let eval_slices: Vec<&[F]> = self.evaluations.iter().map(|(_, e)| e.evaluations()).collect();

                let gpu_result_vec =
                    snarkvm_algorithms_cuda::polymul(domain.size(), &poly_slices, &eval_slices, &F::zero());
                let result = crate::cuda_must_succeed!(gpu_result_vec, "polymul");
                return Some(DensePolynomial::from_coefficients_vec(result));
            }
        }
        self.multiply_on_host()
    }

    /// Multiplies on the host, through the out-of-order transforms, which have
    /// no `cuda` arm. Tests compare the device against it.
    pub(crate) fn multiply_on_host(mut self) -> Option<DensePolynomial<F>> {
        if self.polynomials.is_empty() && self.evaluations.is_empty() {
            Some(DensePolynomial::zero())
        } else {
            let degree = self.polynomials.iter().map(|(_, p)| p.degree() + 1).sum::<usize>();
            let domain = EvaluationDomain::new(degree)?;
            if self.evaluations.iter().any(|(_, e)| e.domain() != domain) {
                None
            } else {
                if self.fft_precomputation.is_none() {
                    self.fft_precomputation = Some(Cow::Owned(domain.precompute_fft()));
                }
                if self.ifft_precomputation.is_none() {
                    self.ifft_precomputation =
                        Some(Cow::Owned(self.fft_precomputation.as_ref().unwrap().to_ifft_precomputation()));
                }
                let fft_pc = &self.fft_precomputation.unwrap();
                let ifft_pc = &self.ifft_precomputation.unwrap();
                let mut pool = ExecutionPool::with_capacity(self.polynomials.len() + self.evaluations.len());
                for (_, p) in self.polynomials {
                    pool.add_job(move || {
                        let mut p = p.into_owned().coeffs;
                        p.resize(domain.size(), F::zero());
                        domain.out_order_fft_in_place_with_pc(&mut p, fft_pc);
                        p
                    })
                }
                for (_, e) in self.evaluations {
                    pool.add_job(move || {
                        let mut e = e.into_owned().evaluations;
                        e.resize(domain.size(), F::zero());
                        crate::fft::domain::derange(&mut e);
                        e
                    })
                }
                let results = pool.execute_all();
                let iter = cfg_into_iter!(results);
                let mut result = cfg_reduce_with!(iter, |mut a, b| {
                    a.iter_mut().zip(b).for_each(|(a, b)| *a *= b);
                    a
                })
                .unwrap();
                domain.out_order_ifft_in_place_with_pc(&mut result, ifft_pc);
                Some(DensePolynomial::from_coefficients_vec(result))
            }
        }
    }

    pub fn element_wise_arithmetic_4_over_domain<T: Borrow<str>>(
        mut self,
        domain: EvaluationDomain<F>,
        labels: [T; 4],
        f: impl Fn(F, F, F, F) -> F + Sync,
    ) -> Option<DensePolynomial<F>> {
        if self.fft_precomputation.is_none() {
            self.fft_precomputation = Some(Cow::Owned(domain.precompute_fft()));
        }
        if self.ifft_precomputation.is_none() {
            self.ifft_precomputation =
                Some(Cow::Owned(self.fft_precomputation.as_ref().unwrap().to_ifft_precomputation()));
        }
        let fft_pc = self.fft_precomputation.as_ref().unwrap();
        let mut pool = ExecutionPool::with_capacity(self.polynomials.len() + self.evaluations.len());
        for (l, p) in self.polynomials {
            pool.add_job(move || {
                let mut p = p.clone().into_owned().coeffs;
                p.resize(domain.size(), F::zero());
                domain.out_order_fft_in_place_with_pc(&mut p, fft_pc);
                (l, p)
            })
        }
        for (l, e) in self.evaluations {
            pool.add_job(move || {
                let mut e = e.clone().into_owned().evaluations;
                e.resize(domain.size(), F::zero());
                crate::fft::domain::derange(&mut e);
                (l, e)
            })
        }
        let p = pool.execute_all().into_iter().collect::<BTreeMap<_, _>>();
        assert_eq!(p.len(), 4);
        let mut result = cfg_iter!(p[labels[0].borrow()])
            .zip(&p[labels[1].borrow()])
            .zip(&p[labels[2].borrow()])
            .zip(&p[labels[3].borrow()])
            .map(|(((a, b), c), d)| f(*a, *b, *c, *d))
            .collect::<Vec<_>>();
        drop(p);
        domain.out_order_ifft_in_place_with_pc(&mut result, &self.ifft_precomputation.unwrap());
        Some(DensePolynomial::from_coefficients_vec(result))
    }
}

/// `polymul` against `multiply_on_host`.
///
/// `Polynomial::Mul` sizes its grid by hand rather than striding, so these
/// cases vary the domain up to the sizes the prover uses.
#[cfg(all(test, feature = "cuda", target_arch = "x86_64"))]
mod gpu_polymul_contract {
    use crate::fft::{DensePolynomial, EvaluationDomain, Evaluations, polynomial::PolyMultiplier};
    use snarkvm_curves::bls12_377::Fr;
    use snarkvm_utilities::rand::{TestRng, Uniform};

    /// A domain of one with two operands goes to the host, and answers.
    ///
    /// `polymul` refuses this shape, because `Polynomial::Mul` would launch
    /// `1 << 31` threads. `degree` sums over polynomials alone, so zero or one
    /// polynomial gives a domain of one however many evaluations come with it.
    #[test]
    fn a_one_element_domain_with_two_operands_answers() {
        let rng = &mut TestRng::default();
        let domain = EvaluationDomain::<Fr>::new(1).expect("a one-element domain");
        assert_eq!(domain.size(), 1);

        let constant = DensePolynomial::from_coefficients_vec(vec![Fr::rand(rng)]);
        let evals = Evaluations::from_vec_and_domain(vec![Fr::rand(rng)], domain);

        let mut multiplier = PolyMultiplier::new();
        multiplier.add_polynomial(constant.clone(), "p");
        multiplier.add_evaluation(evals.clone(), "e");
        let got = multiplier.multiply().expect("the host answers this");

        let mut host = PolyMultiplier::new();
        host.add_polynomial(constant, "p");
        host.add_evaluation(evals, "e");
        let want = host.multiply_on_host().expect("the host answers this");

        assert_eq!(got, want, "the device declines and the host answers");
    }

    /// No polynomials at all: `degree` sums over polynomials alone, so two
    /// evaluations give 0, and `EvaluationDomain::new(0)` is a one-element
    /// domain the evaluations then match.
    #[test]
    fn no_polynomials_and_two_evaluations_answers() {
        let rng = &mut TestRng::default();
        let domain = EvaluationDomain::<Fr>::new(0).expect("a one-element domain");
        assert_eq!(domain.size(), 1);

        let a = Evaluations::from_vec_and_domain(vec![Fr::rand(rng)], domain);
        let b = Evaluations::from_vec_and_domain(vec![Fr::rand(rng)], domain);

        let mut multiplier = PolyMultiplier::new();
        multiplier.add_evaluation(a.clone(), "a");
        multiplier.add_evaluation(b.clone(), "b");
        let got = multiplier.multiply().expect("the host answers this");

        let mut host = PolyMultiplier::new();
        host.add_evaluation(a, "a");
        host.add_evaluation(b, "b");
        let want = host.multiply_on_host().expect("the host answers this");

        assert_eq!(got, want, "the device declines and the host answers");
    }

    /// A degree-0 polynomial and two evaluations: a domain of one with three
    /// operands.
    #[test]
    fn a_polynomial_and_two_evaluations_answers() {
        let rng = &mut TestRng::default();
        let domain = EvaluationDomain::<Fr>::new(1).expect("a one-element domain");

        let constant = DensePolynomial::from_coefficients_vec(vec![Fr::rand(rng)]);
        let a = Evaluations::from_vec_and_domain(vec![Fr::rand(rng)], domain);
        let b = Evaluations::from_vec_and_domain(vec![Fr::rand(rng)], domain);

        let mut multiplier = PolyMultiplier::new();
        multiplier.add_polynomial(constant.clone(), "p");
        multiplier.add_evaluation(a.clone(), "a");
        multiplier.add_evaluation(b.clone(), "b");
        let got = multiplier.multiply().expect("the host answers this");

        let mut host = PolyMultiplier::new();
        host.add_polynomial(constant, "p");
        host.add_evaluation(a, "a");
        host.add_evaluation(b, "b");
        let want = host.multiply_on_host().expect("the host answers this");

        assert_eq!(got, want, "the device declines and the host answers");
    }

    #[test]
    fn polymul_matches_the_host_multiply() {
        let rng = &mut TestRng::default();
        let mut bad: Vec<String> = Vec::new();

        // Degree pairs whose product domains are 2^11, 2^16, 2^17, 2^18 and
        // 2^19. A 2^18 constraint domain multiplied pairwise gives the last.
        for (a_deg, b_deg) in [
            (1023usize, 1023usize),
            ((1 << 15) - 1, (1 << 15) - 1),
            ((1 << 16) - 1, (1 << 15) - 1),
            ((1 << 17) - 1, (1 << 17) - 1),
            ((1 << 18) - 1, (1 << 18) - 1),
        ] {
            let a = DensePolynomial::<Fr>::rand(a_deg, rng);
            let b = DensePolynomial::<Fr>::rand(b_deg, rng);

            let mut device = PolyMultiplier::new();
            device.add_polynomial_ref(&a, "a");
            device.add_polynomial_ref(&b, "b");
            let mut host = PolyMultiplier::new();
            host.add_polynomial_ref(&a, "a");
            host.add_polynomial_ref(&b, "b");

            match (device.multiply(), host.multiply_on_host()) {
                (Some(got), Some(want)) => {
                    if got != want {
                        bad.push(format!("degrees {a_deg} x {b_deg}: differs"));
                    }
                    if got.degree() != a_deg + b_deg {
                        bad.push(format!("degrees {a_deg} x {b_deg}: product degree {}", got.degree()));
                    }
                }
                (None, None) => bad.push(format!("degrees {a_deg} x {b_deg}: both refused")),
                (g, _) => bad.push(format!(
                    "degrees {a_deg} x {b_deg}: {} refused it",
                    if g.is_none() { "the device" } else { "the host" }
                )),
            }
        }

        // One polynomial and one evaluation, which `PolyMul` stages differently.
        // The evaluation must be over the product domain.
        for lg in [10u32, 16] {
            let domain_size = 1usize << lg;
            let domain = EvaluationDomain::<Fr>::new(domain_size).expect("a power-of-two domain");
            let a = DensePolynomial::<Fr>::rand(domain_size - 1, rng);
            let e = Evaluations::from_vec_and_domain((0..domain_size).map(|_| Fr::rand(rng)).collect(), domain);

            let mut device = PolyMultiplier::new();
            device.add_polynomial_ref(&a, "a");
            device.add_evaluation_ref(&e, "e");
            let mut host = PolyMultiplier::new();
            host.add_polynomial_ref(&a, "a");
            host.add_evaluation_ref(&e, "e");

            match (device.multiply(), host.multiply_on_host()) {
                (Some(got), Some(want)) if got == want => {}
                (Some(_), Some(_)) => bad.push(format!("lg {lg} poly+eval: differs")),
                (g, w) => bad.push(format!("lg {lg} poly+eval: {:?} against {:?}", g.is_some(), w.is_some())),
            }
        }

        // A single operand, which `PolyMul` copies rather than transforms.
        let degree = 4095usize;
        let a = DensePolynomial::<Fr>::rand(degree, rng);
        let mut device = PolyMultiplier::new();
        device.add_polynomial_ref(&a, "a");
        let mut host = PolyMultiplier::new();
        host.add_polynomial_ref(&a, "a");
        match (device.multiply(), host.multiply_on_host()) {
            (Some(got), Some(want)) if got == want && got == a => {}
            (Some(got), Some(want)) if got != want => bad.push(format!("single degree {degree}: the two paths differ")),
            (Some(_), Some(_)) => bad.push(format!("single degree {degree}: not the operand")),
            (g, _) => bad.push(format!(
                "single degree {degree}: {} refused it",
                if g.is_none() { "the device" } else { "the host" }
            )),
        }

        assert!(bad.is_empty(), "{}", bad.join("; "));
    }
}
