use generic_array::{ArrayLength, GenericArray};
#[cfg(feature = "rust-crypto")]
use sha3::{digest::core_api::CoreProxy, CShake128, CShake256};

use super::enc::EncBuf;

/// A extendable output function (XOF).
pub trait Xof: Clone {
    /// Reads output bytes.
    type Reader: XofReader;

    /// Creates a new XOF with the customization string `s`.
    fn new(s: &[u8]) -> Self;

    /// Updates the running hash with `data`.
    fn update(&mut self, data: &[u8]);

    /// Returns the output of the XOF.
    fn finalize_xof(self) -> Self::Reader;

    /// Writes the XOF output to `out`.
    fn finalize_xof_into(self, out: &mut [u8]) {
        self.finalize_xof().read(out);
    }
}

/// Output bytes from an XOF.
pub trait XofReader {
    /// Reads output bytes from the XOF into `out`.
    fn read(&mut self, out: &mut [u8]);

    /// Reads `N` output bytes from the XOF into `out`.
    fn read_n<N: ArrayLength>(&mut self) -> GenericArray<u8, N> {
        let mut out = GenericArray::default();
        self.read(&mut out);
        out
    }
}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<R> XofReader for R
where
    R: sha3::digest::XofReader,
{
    #[inline]
    fn read(&mut self, out: &mut [u8]) {
        sha3::digest::XofReader::read(self, out);
    }
}

/// `TupleHash128`.
///
/// For the XOF variant, see [`TupleHashXof128`].
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub type TupleHash128 = TupleHash<CShake128>;

/// `TupleHash256`.
///
/// For the XOF variant, see [`TupleHashXof256`].
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub type TupleHash256 = TupleHash<CShake256>;

/// A cryptographic hash over a set of strings such that each
/// string is unambiguously encoded.
///
/// For example, the TupleHash of `("abc", "d")` will produce
/// a different hash value than the TupleHash of `("ab", "cd")`.
///
/// For the XOF variant, see [`TupleHashXof`].
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
#[derive(Clone, Debug, Default)]
pub struct TupleHash<X> {
    xof: X,
}

impl<X: Xof> TupleHash<X> {
    /// Creates a `TupleHash` with the customization string `s`.
    pub fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    /// Writes the string `s` to the hash.
    pub fn update(&mut self, s: &[u8]) {
        let mut b = EncBuf::new();
        for x in b.encode_string(s) {
            self.xof.update(x);
        }
    }

    /// Returns a fixed-size output.
    pub fn finalize_into(mut self, out: &mut [u8]) {
        self.xof.update(EncBuf::new().right_encode_bytes(out.len()));
        self.xof.finalize_xof_into(out)
    }

    /// Returns a fixed-size output.
    pub fn finalize<N: ArrayLength>(self) -> GenericArray<u8, N> {
        let mut out = GenericArray::default();
        self.finalize_into(&mut out);
        out
    }
}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<X: Xof> sha3::digest::HashMarker for TupleHash<X> {}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<X: Xof> sha3::digest::Update for TupleHash<X> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }
}

/// `TupleHashXof128`.
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub type TupleHashXof128 = TupleHashXof<CShake128>;

/// `TupleHashXof256`.
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub type TupleHashXof256 = TupleHashXof<CShake256>;

/// A cryptographic hash over a set of strings such that each
/// string is unambiguously encoded.
///
/// For example, the TupleHash of `("abc", "d")` will produce
/// a different hash value than the TupleHash of `("ab", "cd")`.
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
#[derive(Clone, Debug, Default)]
pub struct TupleHashXof<X> {
    xof: X,
}

impl<X: Xof> TupleHashXof<X> {
    /// Creates a `TupleHash` with the customization string `s`.
    pub fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    /// Writes the string `s` to the hash.
    pub fn update(&mut self, s: &[u8]) {
        let mut b = EncBuf::new();
        for x in b.encode_string(s) {
            self.xof.update(x);
        }
    }

    /// Returns a variable-size output.
    pub fn finalize_xof(mut self) -> TupleHashXofReader<X::Reader> {
        self.xof.update(EncBuf::new().right_encode(0));
        TupleHashXofReader(self.xof.finalize_xof())
    }
}

impl<X: Xof> Xof for TupleHashXof<X> {
    type Reader = TupleHashXofReader<X::Reader>;

    #[inline]
    fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    #[inline]
    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<X: Xof> sha3::digest::ExtendableOutput for TupleHashXof<X> {
    type Reader = TupleHashXofReader<X::Reader>;

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<X: Xof> sha3::digest::HashMarker for TupleHashXof<X> {}

#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
impl<X: Xof> sha3::digest::Update for TupleHashXof<X> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }
}

/// An [`XofReader`] for [`TupleHashXof`].
#[derive(Clone, Debug)]
pub struct TupleHashXofReader<R>(R);

#[cfg(not(feature = "rust-crypto"))]
impl<R: XofReader> XofReader for TupleHashXofReader<R> {
    #[inline]
    fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

#[cfg(feature = "rust-crypto")]
impl<R: XofReader> sha3::digest::XofReader for TupleHashXofReader<R> {
    #[inline]
    fn read(&mut self, out: &mut [u8]) {
        self.0.read(out);
    }
}

/// `TupleHash` over a fixed-size set of inputs.
///
/// # Warning
///
/// `TupleHash` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
pub fn tuple_hash<X, I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
where
    X: Xof,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    N: ArrayLength,
{
    let mut h = TupleHash::<X>::new(s);
    for xi in x {
        h.update(xi.as_ref());
    }
    h.finalize()
}

/// `TupleHash128` over a fixed-size set of inputs.
///
/// For the XOF variant, see [`tuple_hash_xof128`].
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub fn tuple_hash128<I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    N: ArrayLength,
{
    tuple_hash::<CShake128, I, N>(s, x)
}

/// `TupleHash256` over a fixed-size set of inputs.
///
/// For the XOF variant, see [`tuple_hash_xof256`].
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub fn tuple_hash256<I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    N: ArrayLength,
{
    tuple_hash::<CShake256, I, N>(s, x)
}

/// `TupleHashXof` over a fixed-size set of inputs.
///
/// # Warning
///
/// `TupleHashXof` is only defined for cSHAKE128 and cSHAKE256.
/// Using this with a different XOF might have worse security
/// properties.
pub fn tuple_hash_xof<X, I>(s: &[u8], x: I) -> impl XofReader
where
    X: Xof,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut h = TupleHashXof::<X>::new(s);
    for xi in x {
        h.update(xi.as_ref());
    }
    h.finalize_xof()
}

/// `TupleHashXof256` over a fixed-size set of inputs.
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub fn tuple_hash_xof128<I>(s: &[u8], x: I) -> impl XofReader
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    tuple_hash_xof::<CShake128, I>(s, x)
}

/// `TupleHashXof128` over a fixed-size set of inputs.
#[cfg(feature = "rust-crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
pub fn tuple_hash_xof256<I>(s: &[u8], x: I) -> impl XofReader
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    tuple_hash_xof::<CShake256, I>(s, x)
}

macro_rules! impl_cshake {
    ($ty:ty) => {
        #[cfg(feature = "rust-crypto")]
        #[cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]
        impl Xof for $ty {
            type Reader = <$ty as sha3::digest::ExtendableOutput>::Reader;

            fn new(s: &[u8]) -> Self {
                let core = <$ty as CoreProxy>::Core::new_with_function_name(b"TupleHash", s);
                <$ty>::from_core(core)
            }

            fn update(&mut self, data: &[u8]) {
                sha3::digest::Update::update(self, data);
            }

            fn finalize_xof(self) -> Self::Reader {
                sha3::digest::ExtendableOutput::finalize_xof(self)
            }
        }
    };
}
impl_cshake!(CShake128);
impl_cshake!(CShake256);

#[cfg(test)]
#[allow(clippy::type_complexity, reason = "Tests")]
mod tests {
    use generic_array::typenum::{U32, U64};

    use super::*;

    #[test]
    fn test_tuple_hash128_basic() {
        let lhs = tuple_hash128::<_, U32>(b"test", ["abc", "d"]);
        let rhs = tuple_hash128::<_, U32>(b"test", ["ab", "cd"]);
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn test_tuple_hash256_basic() {
        let lhs = tuple_hash256::<_, U32>(b"test", ["abc", "d"]);
        let rhs = tuple_hash256::<_, U32>(b"test", ["ab", "cd"]);
        assert_ne!(lhs, rhs);
    }

    // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/tuplehash_samples.pdf
    #[test]
    fn test_tuple_hash128_vectors() {
        let vectors: &[(&[u8], &[&[u8]], [u8; 32])] = &[
            (
                &[],
                &[&[0x0, 0x1, 0x2], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]],
                [
                    0xC5, 0xD8, 0x78, 0x6C, 0x1A, 0xFB, 0x9B, 0x82, 0x11, 0x1A, 0xB3, 0x4B, 0x65,
                    0xB2, 0xC0, 0x04, 0x8F, 0xA6, 0x4E, 0x6D, 0x48, 0xE2, 0x63, 0x26, 0x4C, 0xE1,
                    0x70, 0x7D, 0x3F, 0xFC, 0x8E, 0xD1,
                ],
            ),
            (
                b"My Tuple App",
                &[&[0x0, 0x1, 0x2], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]],
                [
                    0x75, 0xCD, 0xB2, 0x0F, 0xF4, 0xDB, 0x11, 0x54, 0xE8, 0x41, 0xD7, 0x58, 0xE2,
                    0x41, 0x60, 0xC5, 0x4B, 0xAE, 0x86, 0xEB, 0x8C, 0x13, 0xE7, 0xF5, 0xF4, 0x0E,
                    0xB3, 0x55, 0x88, 0xE9, 0x6D, 0xFB,
                ],
            ),
            (
                b"My Tuple App",
                &[
                    &[0x0, 0x1, 0x2],
                    &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
                    &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
                ],
                [
                    0xE6, 0x0F, 0x20, 0x2C, 0x89, 0xA2, 0x63, 0x1E, 0xDA, 0x8D, 0x4C, 0x58, 0x8C,
                    0xA5, 0xFD, 0x07, 0xF3, 0x9E, 0x51, 0x51, 0x99, 0x8D, 0xEC, 0xCF, 0x97, 0x3A,
                    0xDB, 0x38, 0x04, 0xBB, 0x6E, 0x84,
                ],
            ),
        ];
        for (i, (s, x, want)) in vectors.iter().enumerate() {
            let got = tuple_hash128::<&[&[u8]], U32>(s, x);
            let want = GenericArray::from(*want);
            assert_eq!(got, want, "#{i}");
        }
    }

    // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/tuplehash_samples.pdf
    #[test]
    fn test_tuple_hash256_vectors() {
        let vectors: &[(&[u8], &[&[u8]], [u8; 64])] = &[
            (
                &[],
                &[&[0x0, 0x1, 0x2], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]],
                [
                    0xCF, 0xB7, 0x05, 0x8C, 0xAC, 0xA5, 0xE6, 0x68, 0xF8, 0x1A, 0x12, 0xA2, 0x0A,
                    0x21, 0x95, 0xCE, 0x97, 0xA9, 0x25, 0xF1, 0xDB, 0xA3, 0xE7, 0x44, 0x9A, 0x56,
                    0xF8, 0x22, 0x01, 0xEC, 0x60, 0x73, 0x11, 0xAC, 0x26, 0x96, 0xB1, 0xAB, 0x5E,
                    0xA2, 0x35, 0x2D, 0xF1, 0x42, 0x3B, 0xDE, 0x7B, 0xD4, 0xBB, 0x78, 0xC9, 0xAE,
                    0xD1, 0xA8, 0x53, 0xC7, 0x86, 0x72, 0xF9, 0xEB, 0x23, 0xBB, 0xE1, 0x94,
                ],
            ),
            (
                b"My Tuple App",
                &[&[0x0, 0x1, 0x2], &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]],
                [
                    0x14, 0x7C, 0x21, 0x91, 0xD5, 0xED, 0x7E, 0xFD, 0x98, 0xDB, 0xD9, 0x6D, 0x7A,
                    0xB5, 0xA1, 0x16, 0x92, 0x57, 0x6F, 0x5F, 0xE2, 0xA5, 0x06, 0x5F, 0x3E, 0x33,
                    0xDE, 0x6B, 0xBA, 0x9F, 0x3A, 0xA1, 0xC4, 0xE9, 0xA0, 0x68, 0xA2, 0x89, 0xC6,
                    0x1C, 0x95, 0xAA, 0xB3, 0x0A, 0xEE, 0x1E, 0x41, 0x0B, 0x0B, 0x60, 0x7D, 0xE3,
                    0x62, 0x0E, 0x24, 0xA4, 0xE3, 0xBF, 0x98, 0x52, 0xA1, 0xD4, 0x36, 0x7E,
                ],
            ),
            (
                b"My Tuple App",
                &[
                    &[0x0, 0x1, 0x2],
                    &[0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
                    &[0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28],
                ],
                [
                    0x45, 0x00, 0x0B, 0xE6, 0x3F, 0x9B, 0x6B, 0xFD, 0x89, 0xF5, 0x47, 0x17, 0x67,
                    0x0F, 0x69, 0xA9, 0xBC, 0x76, 0x35, 0x91, 0xA4, 0xF0, 0x5C, 0x50, 0xD6, 0x88,
                    0x91, 0xA7, 0x44, 0xBC, 0xC6, 0xE7, 0xD6, 0xD5, 0xB5, 0xE8, 0x2C, 0x01, 0x8D,
                    0xA9, 0x99, 0xED, 0x35, 0xB0, 0xBB, 0x49, 0xC9, 0x67, 0x8E, 0x52, 0x6A, 0xBD,
                    0x8E, 0x85, 0xC1, 0x3E, 0xD2, 0x54, 0x02, 0x1D, 0xB9, 0xE7, 0x90, 0xCE,
                ],
            ),
        ];
        for (i, (s, x, want)) in vectors.iter().enumerate() {
            let got = tuple_hash256::<&[&[u8]], U64>(s, x);
            let want = GenericArray::from(*want);
            assert_eq!(got, want, "#{i}");
        }
    }
}
