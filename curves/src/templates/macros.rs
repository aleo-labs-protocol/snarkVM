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

// https://github.com/rust-lang/rust/issues/57966 forces us to export these and
// import them via `use crate::` syntax. It'd be nice if we were able to avoid any
// macro_use/macro_export and just import the macro
#[macro_export]
macro_rules! impl_sw_curve_serializer {
    ($params: ident) => {
        // Projective Group point implementations delegate to the Affine version
        impl<P: $params> CanonicalSerialize for Projective<P> {
            #[allow(unused_qualifications)]
            #[inline]
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                writer: W,
                compress: Compress,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                CanonicalSerialize::serialize_with_mode(&Affine::<P>::from(*self), writer, compress)
            }

            #[inline]
            fn serialized_size(&self, compress: Compress) -> usize {
                Affine::<P>::from(*self).serialized_size(compress)
            }

            #[inline]
            fn uncompressed_size(&self) -> usize {
                Affine::<P>::from(*self).uncompressed_size()
            }
        }

        impl<P: $params> Valid for Projective<P> {
            fn check(&self) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                let point = Affine::<P>::from(*self);
                if point.is_on_curve() & point.is_in_correct_subgroup_assuming_on_curve() {
                    Ok(())
                } else {
                    Err(snarkvm_utilities::serialize::SerializationError::InvalidData)
                }
            }
        }

        impl<P: $params> CanonicalDeserialize for Projective<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_mode<R: std::io::Read>(
                reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, snarkvm_utilities::serialize::SerializationError> {
                Affine::<P>::deserialize_with_mode(reader, compress, validate).map(Into::into)
            }
        }

        impl<P: $params> CanonicalSerialize for Affine<P> {
            #[allow(unused_qualifications)]
            #[inline]
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                mut writer: W,
                compress: Compress,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                match compress {
                    Compress::Yes => {
                        if self.is_zero() {
                            let flags = snarkvm_utilities::serialize::SWFlags::infinity();
                            // Serialize 0.
                            P::BaseField::zero().serialize_with_flags(writer, flags)
                        } else {
                            let flags = snarkvm_utilities::serialize::SWFlags::from_y_sign(self.y > -self.y);
                            self.x.serialize_with_flags(writer, flags)
                        }
                    }
                    Compress::No => {
                        let flags = if self.is_zero() {
                            snarkvm_utilities::serialize::SWFlags::infinity()
                        } else {
                            snarkvm_utilities::serialize::SWFlags::default()
                        };
                        self.x.serialize_uncompressed(&mut writer)?;
                        self.y.serialize_with_flags(&mut writer, flags)?;
                        Ok(())
                    }
                }
            }

            #[inline]
            fn serialized_size(&self, compress: Compress) -> usize {
                match compress {
                    Compress::Yes => self.x.serialized_size_with_flags::<SWFlags>(),
                    Compress::No => self.x.serialized_size(compress) + self.y.serialized_size_with_flags::<SWFlags>(),
                }
            }
        }

        impl<P: $params> Valid for Affine<P> {
            fn check(&self) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                if self.is_on_curve() & self.is_in_correct_subgroup_assuming_on_curve() {
                    Ok(())
                } else {
                    Err(snarkvm_utilities::serialize::SerializationError::InvalidData)
                }
            }
        }

        impl<P: $params> CanonicalDeserialize for Affine<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_mode<R: std::io::Read>(
                mut reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, snarkvm_utilities::serialize::SerializationError> {
                use snarkvm_utilities::serialize::SWFlags;
                let point = if let Compress::Yes = compress {
                    let (x, flags) = P::BaseField::deserialize_with_flags::<_, SWFlags>(&mut reader)?;
                    if flags.is_infinity() {
                        // The x-coordinate must be zero when the infinity flag is
                        // set, or the encoding is non-canonical.
                        if !x.is_zero() {
                            return Err(snarkvm_utilities::serialize::SerializationError::InvalidData);
                        }
                        Self::zero()
                    } else {
                        // The infinity flag is clear in this branch, so the sign
                        // is present and this cannot panic.
                        let is_positive = flags.is_positive().unwrap();
                        let point = Affine::<P>::from_x_coordinate(x, is_positive)
                            .ok_or(snarkvm_utilities::serialize::SerializationError::InvalidData)?;
                        // y = 0 is its own negation, so both sign flags select it
                        // and from_x_coordinate cannot tell them apart. The
                        // serializer writes the negative-y flag for such a point,
                        // so the positive-y spelling is a second encoding of it.
                        if point.y.is_zero() && is_positive {
                            return Err(snarkvm_utilities::serialize::SerializationError::InvalidData);
                        }
                        point
                    }
                } else {
                    let x = P::BaseField::deserialize_uncompressed(&mut reader)?;
                    let (y, flags) = P::BaseField::deserialize_with_flags::<_, SWFlags>(&mut reader)?;
                    Affine::<P>::new(x, y, flags.is_infinity())
                };
                if validate == Validate::Yes {
                    point.check()?;
                }
                Ok(point)
            }
        }
    };
}
#[macro_export]
macro_rules! impl_edwards_curve_serializer {
    ($params: ident) => {
        impl<P: $params> CanonicalSerialize for Projective<P> {
            #[allow(unused_qualifications)]
            #[inline]
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                writer: W,
                compress: Compress,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                Affine::<P>::from(*self).serialize_with_mode(writer, compress)
            }

            #[inline]
            fn serialized_size(&self, compress: Compress) -> usize {
                Affine::<P>::from(*self).serialized_size(compress)
            }
        }

        impl<P: $params> Valid for Projective<P> {
            fn check(&self) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                let point = Affine::<P>::from(*self);
                if point.is_on_curve() & point.is_in_correct_subgroup_assuming_on_curve() {
                    Ok(())
                } else {
                    Err(snarkvm_utilities::serialize::SerializationError::InvalidData)
                }
            }
        }

        impl<P: $params> CanonicalDeserialize for Projective<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_mode<R: std::io::Read>(
                reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, snarkvm_utilities::serialize::SerializationError> {
                Affine::<P>::deserialize_with_mode(reader, compress, validate).map(Into::into)
            }
        }

        impl<P: $params> CanonicalSerialize for Affine<P> {
            #[allow(unused_qualifications)]
            #[inline]
            fn serialize_with_mode<W: std::io::Write>(
                &self,
                mut writer: W,
                compress: Compress,
            ) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                if let Compress::Yes = compress {
                    if self.is_zero() {
                        let flags = snarkvm_utilities::serialize::EdwardsFlags::default();
                        // Serialize 0.
                        P::BaseField::zero().serialize_with_flags(&mut writer, flags)
                    } else {
                        let flags = snarkvm_utilities::serialize::EdwardsFlags::from_y_sign(self.y > -self.y);
                        self.x.serialize_with_flags(writer, flags)
                    }
                } else {
                    self.x.serialize_uncompressed(&mut writer)?;
                    self.y.serialize_uncompressed(&mut writer)?;
                    Ok(())
                }
            }

            #[inline]
            fn serialized_size(&self, compress: Compress) -> usize {
                if let Compress::Yes = compress {
                    use snarkvm_utilities::serialize::EdwardsFlags;
                    self.x.serialized_size_with_flags::<EdwardsFlags>()
                } else {
                    self.x.uncompressed_size() + self.y.uncompressed_size()
                }
            }
        }

        impl<P: $params> Valid for Affine<P> {
            #[allow(unused_qualifications)]
            fn check(&self) -> Result<(), snarkvm_utilities::serialize::SerializationError> {
                if self.is_on_curve() & self.is_in_correct_subgroup_assuming_on_curve() {
                    Ok(())
                } else {
                    Err(snarkvm_utilities::serialize::SerializationError::InvalidData)
                }
            }
        }

        impl<P: $params> CanonicalDeserialize for Affine<P> {
            #[allow(unused_qualifications)]
            fn deserialize_with_mode<R: std::io::Read>(
                mut reader: R,
                compress: Compress,
                validate: Validate,
            ) -> Result<Self, snarkvm_utilities::serialize::SerializationError> {
                use snarkvm_utilities::serialize::{EdwardsFlags, SerializationError};
                let point = if let Compress::Yes = compress {
                    let (x, flags): (P::BaseField, EdwardsFlags) = P::BaseField::deserialize_with_flags(&mut reader)?;

                    // The flag names the sign of y, and it is consulted at every
                    // x. At x = 0 it is the only thing separating the identity
                    // (0, 1) from the order-two point (0, -1); reading the
                    // identity out of x = 0 without looking at the flag would
                    // give the identity a second encoding.
                    Affine::<P>::from_x_coordinate(x, flags.is_positive()).ok_or(SerializationError::InvalidData)?
                } else {
                    let x = P::BaseField::deserialize_uncompressed(&mut reader)?;
                    let y = P::BaseField::deserialize_uncompressed(&mut reader)?;
                    Affine::<P>::new(x, y, x * y)
                };

                if let Validate::Yes = validate {
                    Valid::check(&point)?;
                }

                Ok(point)
            }
        }
    };
}
