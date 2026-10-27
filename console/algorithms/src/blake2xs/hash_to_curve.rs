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
use snarkvm_console_types::prelude::AffineCurve;

impl Blake2Xs {
    /// Runs hash-to-curve and returns the generator, message, and counter on success.
    #[inline]
    pub fn hash_to_curve<G: AffineCurve>(input: &str) -> (G, String, usize) {
        // Attempt to increment counter `k` at most `8 * G::SERIALIZED_SIZE` times.
        for k in 0..128 {
            // Construct a new message.
            let message = format!("{input} in {k}");

            // Output the generator if a valid generator was found.
            if let Some(g) = Self::try_hash_to_curve::<G>(&message) {
                return (g, message, k);
            }
        }

        // Panic with probability 2^-128.
        panic!("Unable to hash to curve on {input}")
    }

    /// Evaluates **one** round of hash-to-curve and returns a generator on success.
    #[inline]
    fn try_hash_to_curve<G: AffineCurve>(input: &str) -> Option<G> {
        let serialized_size = G::prime_subgroup_generator().compressed_size();

        // Compute the digest for sampling the generator.
        let digest = Self::evaluate(input.as_bytes(), u16::try_from(serialized_size).unwrap(), "AleoHtC0".as_bytes());
        debug_assert!(digest.len() == serialized_size); // Attempt to use the digest to derive a generator.
        G::from_random_bytes(&digest).and_then(|g| {
            debug_assert!(g.is_on_curve());

            let g = g.mul_by_cofactor();
            debug_assert!(g.is_on_curve());
            debug_assert!(g.is_in_correct_subgroup_assuming_on_curve());

            // Cofactor clearing can produce the identity. Try the next counter when it does.
            (!g.is_zero()).then_some(g)
        })
    }
}

#[cfg(test)]
mod bls12_377_g1 {
    use super::*;
    use snarkvm_curves::bls12_377::G1Affine;
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::{BigInteger384, CanonicalSerialize};

    #[test]
    fn hash_bls12_377_g1() {
        let g1 = Blake2Xs::try_hash_to_curve::<G1Affine>("Aleo BLS12-377 G1 in 0").unwrap();
        assert!(g1.is_on_curve());
        assert!(g1.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(g1.compressed_size(), 384 / 8);
        assert_eq!(
            Blake2Xs::hash_to_curve::<G1Affine>("Aleo BLS12-377 G1"),
            (g1, "Aleo BLS12-377 G1 in 0".to_string(), 0)
        );

        // String representation
        assert_eq!(
            g1.x.to_string(),
            "89363714989903307245735717098563574705733591463163614225748337416674727625843187853442697973404985688481508350822",
        );
        assert_eq!(
            g1.y.to_string(),
            "3702177272937190650578065972808860481433820514072818216637796320125658674906330993856598323293086021583822603349",
        );

        // BigInteger representation
        assert_eq!(
            g1.x.to_bigint(),
            BigInteger384::new([
                1089863619676461926,
                2031922408020517912,
                7605803015099675459,
                5499508099818543095,
                11627353473000952893,
                41837199143568307
            ])
        );
        assert_eq!(
            g1.y.to_bigint(),
            BigInteger384::new([
                8946822147630122069,
                11486725844942458959,
                17739430126876114892,
                5672784675232650440,
                942928816728936680,
                1733239579958889
            ])
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g1.x.0,
            BigInteger384::new([
                1171681672315280277,
                6528257384425852712,
                7514971432460253787,
                2032708395764262463,
                12876543207309632302,
                107509843840671767
            ])
        );
        assert_eq!(
            g1.y.0,
            BigInteger384::new([
                13572190014569192121,
                15344828677741220784,
                17067903700058808083,
                10342263224753415805,
                1083990386877464092,
                21335464879237822
            ])
        );

        // Check that G1Affine matches.
        assert_eq!(G1Affine::prime_subgroup_generator(), g1);
    }
}

#[cfg(test)]
mod bls12_377_g2 {
    use super::*;
    use snarkvm_curves::bls12_377::G2Affine;
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::{BigInteger384, CanonicalSerialize};

    #[test]
    fn hash_bls12_377_g2() {
        let g2 = Blake2Xs::try_hash_to_curve::<G2Affine>("Aleo BLS12-377 G2 in 6").unwrap();
        assert!(g2.is_on_curve());
        assert!(g2.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(g2.compressed_size(), 2 * 384 / 8);
        assert_eq!(
            Blake2Xs::hash_to_curve::<G2Affine>("Aleo BLS12-377 G2"),
            (g2, "Aleo BLS12-377 G2 in 6".to_string(), 6),
        );

        // String representation
        assert_eq!(
            g2.x.to_string(),
            "Fp2(170590608266080109581922461902299092015242589883741236963254737235977648828052995125541529645051927918098146183295 + 83407003718128594709087171351153471074446327721872642659202721143408712182996929763094113874399921859453255070254 * u)",
        );
        assert_eq!(
            g2.y.to_string(),
            "Fp2(1843833842842620867708835993770650838640642469700861403869757682057607397502738488921663703124647238454792872005 + 33145532013610981697337930729788870077912093258611421158732879580766461459275194744385880708057348608045241477209 * u)",
        );

        // BigInteger representation
        assert_eq!(
            g2.x.c0.to_bigint(),
            BigInteger384::new([
                6285382596397680767,
                15748827462709656851,
                12106939604663586443,
                15333984969116343459,
                5478119782678835813,
                79865001705186672
            ])
        );
        assert_eq!(
            g2.x.c1.to_bigint(),
            BigInteger384::new([
                16087313950742852142,
                593255854261604337,
                1941199260866950545,
                10849744434273544618,
                2633370935305329371,
                39048459712288691
            ])
        );
        assert_eq!(
            g2.y.c0.to_bigint(),
            BigInteger384::new([
                7702421029866889285,
                16004466681641276576,
                106615717155384672,
                763522394023763305,
                16530696304726864408,
                863223330401754
            ])
        );
        assert_eq!(
            g2.y.c1.to_bigint(),
            BigInteger384::new([
                14642269910726223961,
                418400088670236579,
                13367772290999385514,
                12034951455731096578,
                1807164704891090155,
                15517665349181582
            ])
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g2.x.c0.0,
            BigInteger384::new([
                1394603105513884269,
                11069732150289508451,
                4261960060090787184,
                13457254148541472797,
                3177258746859163322,
                82258727112085846
            ])
        );
        assert_eq!(
            g2.x.c1.0,
            BigInteger384::new([
                12672065269715576738,
                3451530808602826578,
                9486610028138952262,
                5031487885431614078,
                9858745210421513581,
                63301617551232910
            ])
        );
        assert_eq!(
            g2.y.c0.0,
            BigInteger384::new([
                1855632670224768760,
                2989378521406112342,
                9748867374972564648,
                3204895972998458874,
                16520689795595505429,
                61918742406142643
            ])
        );
        assert_eq!(
            g2.y.c1.0,
            BigInteger384::new([
                1532128906028652860,
                14539073382194201855,
                10828918286556702479,
                14664598863867299115,
                483199896405477997,
                73741830940675480
            ])
        );

        // Check that G2Affine matches.
        assert_eq!(G2Affine::prime_subgroup_generator(), g2);
    }
}

#[cfg(test)]
mod edwards_bls12 {
    use super::*;
    use snarkvm_curves::edwards_bls12::EdwardsAffine;
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::{BigInteger256, CanonicalSerialize};

    #[test]
    fn hash_edwards_bls12() {
        let group = Blake2Xs::try_hash_to_curve::<EdwardsAffine>("Aleo Edwards BLS12 in 4").unwrap();
        assert!(group.is_on_curve());
        assert!(group.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(group.compressed_size(), 256 / 8);
        assert_eq!(
            Blake2Xs::hash_to_curve::<EdwardsAffine>("Aleo Edwards BLS12"),
            (group, "Aleo Edwards BLS12 in 4".to_string(), 4)
        );

        // String representation
        assert_eq!(group.x.to_string(), "1540945439182663264862696551825005342995406165131907382295858612069623286213",);
        assert_eq!(group.y.to_string(), "8003546896475222703853313610036801932325312921786952001586936882361378122196",);

        // BigInteger representation
        assert_eq!(
            group.x.to_bigint(),
            BigInteger256::new([1404703638504229317, 16672475576000152563, 1635533132911366150, 245486771465834503]),
            "\n\nExpected: {:?}\n\n",
            group.x.to_bigint().0,
        );
        assert_eq!(
            group.y.to_bigint(),
            BigInteger256::new([15352153743387634132, 9180404173643694677, 4017395716581932261, 1275038582114391971]),
            "\n\nExpected: {:?}\n\n",
            group.y.to_bigint().0,
        );

        // Montgomery BigInteger representation
        assert_eq!(
            group.x.0,
            BigInteger256::new([15976313411695170452, 17230178952810798400, 11626259175167078036, 678729006091608048]),
            "\n\nExpected: {:?}\n\n",
            group.x.0,
        );
        assert_eq!(
            group.y.0,
            BigInteger256::new([926786653590077393, 18147000980977651608, 13077459464847727671, 1231472949076376191]),
            "\n\nExpected: {:?}\n\n",
            group.y.0,
        );

        // Check that EdwardsAffine matches.
        assert_eq!(EdwardsAffine::prime_subgroup_generator(), group);
    }
}
