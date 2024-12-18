use core::{error, fmt};

use generic_array::{typenum::Unsigned, ArrayLength, GenericArray};
use sha3::{
    digest::{
        core_api::CoreProxy,
        crypto_common::{AlgorithmName, BlockSizeUser},
        ExtendableOutput, Update, XofReader,
    },
    CShake128, CShake256,
};
use sha3_utils::{bytepad, encode_string, right_encode, right_encode_bytes};

/// Returned when the key is too small.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InvalidLength;

impl fmt::Display for InvalidLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid length")
    }
}

impl error::Error for InvalidLength {}

macro_rules! impl_kmac {
    ($alg:literal, $name:ident, $cshake:ty, $security:literal) => {
        #[doc = "`"]
        #[doc = $alg]
        #[doc = "`."]
        #[derive(Clone, Debug)]
        pub struct $name {
            cshake: $cshake,
        }

        impl $name {
            /// The minimum allowed size, in bytes, of a key.
            pub const MIN_KEY_SIZE: usize = $security / 8;

            /// Crates a new KMAC instance with the customization
            /// string `s` and key `k`.
            ///
            /// - `k` must be at least
            ///   [`MIN_KEY_SIZE`][Self::MIN_KEY_SIZE].
            /// - `s` can be any length, including the empty
            ///   string.
            pub fn new(k: &[u8], s: &[u8]) -> Result<Self, InvalidLength> {
                if k.len() < Self::MIN_KEY_SIZE {
                    return Err(InvalidLength);
                }

                let mut cshake = <$cshake>::from_core(
                    <$cshake as CoreProxy>::Core::new_with_function_name(b"KMAC", s),
                );

                const RATE: usize = <$cshake as BlockSizeUser>::BlockSize::USIZE;
                for s in &bytepad::<RATE>(encode_string(k)) {
                    cshake.update(s);
                }

                Ok(Self { cshake })
            }

            /// Writes `data` to the running MAC state.
            pub fn update(&mut self, data: &[u8]) {
                self.cshake.update(data);
            }

            /// Returns a fixed-size output.
            pub fn finalize_into(mut self, out: &mut [u8]) {
                self.cshake.update(right_encode_bytes(out.len()).as_bytes());
                self.cshake.finalize_xof().read(out)
            }

            /// Returns a fixed-size MAC.
            pub fn finalize<N: ArrayLength>(self) -> GenericArray<u8, N> {
                let mut out = GenericArray::default();
                self.finalize_into(&mut out);
                out
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $alg)
            }
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.update(data);
            }
        }
    };
}
impl_kmac!("KMAC128", Kmac128, CShake128, 128);
impl_kmac!("KMAC256", Kmac256, CShake256, 256);

macro_rules! impl_kmac_xof {
    ($alg:literal, $name:ident, $cshake:ty, $security:literal) => {
        #[doc = "`"]
        #[doc = $alg]
        #[doc = "`."]
        #[derive(Clone, Debug)]
        pub struct $name {
            cshake: $cshake,
        }

        impl $name {
            /// The minimum allowed size, in bytes, of a key.
            pub const MIN_KEY_SIZE: usize = $security / 8;

            /// Crates a new KMAC instance with the customization
            /// string `s` and key `k`.
            ///
            /// - `k` must be at least
            ///   [`MIN_KEY_SIZE`][Self::MIN_KEY_SIZE].
            /// - `s` can be any length, including the empty
            ///   string.
            pub fn new(k: &[u8], s: &[u8]) -> Result<Self, InvalidLength> {
                if k.len() < Self::MIN_KEY_SIZE {
                    return Err(InvalidLength);
                }

                let mut cshake = <$cshake>::from_core(
                    <$cshake as CoreProxy>::Core::new_with_function_name(b"KMAC", s),
                );

                const RATE: usize = <$cshake as BlockSizeUser>::BlockSize::USIZE;
                for s in &bytepad::<RATE>(encode_string(k)) {
                    cshake.update(s);
                }

                Ok(Self { cshake })
            }

            /// Writes `data` to the running MAC state.
            pub fn update(&mut self, data: &[u8]) {
                self.cshake.update(data);
            }

            /// Returns a fixed-size output.
            pub fn finalize_xof(mut self) -> <$cshake as ExtendableOutput>::Reader {
                self.cshake.update(right_encode(0).as_bytes());
                self.cshake.finalize_xof()
            }
        }

        impl AlgorithmName for $name {
            fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, $alg)
            }
        }

        impl ExtendableOutput for $name {
            type Reader = <$cshake as ExtendableOutput>::Reader;

            fn finalize_xof(self) -> Self::Reader {
                self.finalize_xof()
            }
        }

        impl Update for $name {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.update(data);
            }
        }
    };
}
impl_kmac_xof!("KMACXOF128", KmacXof128, CShake128, 128);
impl_kmac_xof!("KMACXOF256", KmacXof256, CShake256, 256);

#[cfg(test)]
#[allow(clippy::type_complexity, reason = "Tests")]
mod tests {
    use generic_array::typenum::U32;

    use super::*;

    #[test]
    fn test_kmac128() {
        let vectors: &[(&[u8], &[u8], &[u8], &[u8])] = &[
            (
                &[
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                    0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                ],
                &[0x00, 0x01, 0x02, 0x03],
                &[],
                &[
                    0xE5, 0x78, 0x0B, 0x0D, 0x3E, 0xA6, 0xF7, 0xD3, 0xA4, 0x29, 0xC5, 0x70, 0x6A,
                    0xA4, 0x3A, 0x00, 0xFA, 0xDB, 0xD7, 0xD4, 0x96, 0x28, 0x83, 0x9E, 0x31, 0x87,
                    0x24, 0x3F, 0x45, 0x6E, 0xE1, 0x4E,
                ],
            ),
            (
                &[
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                    0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                ],
                &[0x00, 0x01, 0x02, 0x03],
                b"My Tagged Application",
                &[
                    0x3B, 0x1F, 0xBA, 0x96, 0x3C, 0xD8, 0xB0, 0xB5, 0x9E, 0x8C, 0x1A, 0x6D, 0x71,
                    0x88, 0x8B, 0x71, 0x43, 0x65, 0x1A, 0xF8, 0xBA, 0x0A, 0x70, 0x70, 0xC0, 0x97,
                    0x9E, 0x28, 0x11, 0x32, 0x4A, 0xA5,
                ],
            ),
        ];
        for (i, &(k, data, s, want)) in vectors.iter().enumerate() {
            let mut m = Kmac128::new(k, s).unwrap();
            m.update(data);
            let got = m.finalize::<U32>();
            let want = GenericArray::<u8, U32>::from_slice(want);
            assert_eq!(&got, want, "#{i}");
        }
    }

    #[test]
    fn test_kmacxof128() {
        let vectors: &[(&[u8], &[u8], &[u8], &[u8])] = &[
            (
                &[
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                    0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                ],
                &[0x00, 0x01, 0x02, 0x03],
                &[],
                &[
                    0xCD, 0x83, 0x74, 0x0B, 0xBD, 0x92, 0xCC, 0xC8, 0xCF, 0x03, 0x2B, 0x14, 0x81,
                    0xA0, 0xF4, 0x46, 0x0E, 0x7C, 0xA9, 0xDD, 0x12, 0xB0, 0x8A, 0x0C, 0x40, 0x31,
                    0x17, 0x8B, 0xAC, 0xD6, 0xEC, 0x35,
                ],
            ),
            (
                &[
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
                    0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
                    0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
                ],
                &[0x00, 0x01, 0x02, 0x03],
                b"My Tagged Application",
                &[
                    0x31, 0xA4, 0x45, 0x27, 0xB4, 0xED, 0x9F, 0x5C, 0x61, 0x01, 0xD1, 0x1D, 0xE6,
                    0xD2, 0x6F, 0x06, 0x20, 0xAA, 0x5C, 0x34, 0x1D, 0xEF, 0x41, 0x29, 0x96, 0x57,
                    0xFE, 0x9D, 0xF1, 0xA3, 0xB1, 0x6C,
                ],
            ),
        ];
        for (i, &(k, data, s, want)) in vectors.iter().enumerate() {
            let mut m = KmacXof128::new(k, s).unwrap();
            m.update(data);
            let got = m.finalize_xof().read_boxed(32);
            assert_eq!(&*got, want, "#{i}");
        }
    }
}
