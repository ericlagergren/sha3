use generic_array::{ArrayLength, GenericArray};
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

impl<R> XofReader for R
where
    R: sha3::digest::XofReader,
{
    fn read(&mut self, out: &mut [u8]) {
        sha3::digest::XofReader::read(self, out);
    }
}

/// `TupleHash128`.
///
/// For the XOF variant, see [`TupleHashXof128`].
pub type TupleHash128 = TupleHash<CShake128>;

/// `TupleHash256`.
///
/// For the XOF variant, see [`TupleHashXof256`].
pub type TupleHash256 = TupleHash<CShake256>;

/// `TupleHashXof128`.
pub type TupleHashXof128 = TupleHashXof<CShake128>;

/// `TupleHashXof256`.
pub type TupleHashXof256 = TupleHashXof<CShake256>;

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
#[derive(Clone, Debug)]
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
#[derive(Clone, Debug)]
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
    pub fn finalize_xof(mut self) -> X::Reader {
        self.xof.update(EncBuf::new().right_encode(0));
        self.xof.finalize_xof()
    }
}

impl<X: Xof> Xof for TupleHashXof<X> {
    type Reader = X::Reader;

    fn new(s: &[u8]) -> Self {
        Self { xof: X::new(s) }
    }

    fn update(&mut self, data: &[u8]) {
        self.update(data);
    }

    fn finalize_xof(self) -> Self::Reader {
        self.finalize_xof()
    }
}

fn tuple_hash<X, I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
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
pub fn tuple_hash256<I, N>(s: &[u8], x: I) -> GenericArray<u8, N>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    N: ArrayLength,
{
    tuple_hash::<CShake256, I, N>(s, x)
}

fn tuple_hash_xof<X, I>(s: &[u8], x: I) -> impl XofReader
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
pub fn tuple_hash_xof128<I>(s: &[u8], x: I) -> impl XofReader
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    tuple_hash_xof::<CShake128, I>(s, x)
}

/// `TupleHashXof128` over a fixed-size set of inputs.
pub fn tuple_hash_xof256<I>(s: &[u8], x: I) -> impl XofReader
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    tuple_hash_xof::<CShake256, I>(s, x)
}

macro_rules! impl_cshake {
    ($ty:ty) => {
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
mod tests {
    use generic_array::typenum::U32;

    use super::*;

    #[test]
    fn test_tuple_hash128() {
        let lhs = tuple_hash128::<_, U32>(b"test", ["abc", "d"]);
        let rhs = tuple_hash128::<_, U32>(b"test", ["ab", "cd"]);
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn test_tuple_hash256() {
        let lhs = tuple_hash256::<_, U32>(b"test", ["abc", "d"]);
        let rhs = tuple_hash256::<_, U32>(b"test", ["ab", "cd"]);
        assert_ne!(lhs, rhs);
    }
}
