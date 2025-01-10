#![allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove that the indices are in bounds"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "All arithmetic is in bounds"
)]

use core::{
    array, cmp, fmt, hint,
    iter::{ExactSizeIterator, FusedIterator},
    ops::{Add, AddAssign, Mul, Sub},
};

use hybrid_array::{Array, ArrayN, ArraySize, AssocArraySize};
#[cfg(feature = "no-panic")]
use no_panic::no_panic;
use typenum::{
    generic_const_mappings::{Const, ToUInt, U},
    Add1, IsGreaterOrEqual, NonZero, Prod, Sum, U1, U2,
};

use super::util::as_chunks;

/// The size in bytes of [`usize`].
const USIZE_BYTES: usize = ((usize::BITS + 7) / 8) as usize;

// This is silly, but it ensures that we're always in
//    [0, ((2^2040)-1)/8]
// which is required by SP 800-185, which requires that
// `left_encode`, `right_encode`, etc. accept integers up to
// (2^2040)-1.
//
// Divide by 8 because of the `*_bytes` routines.
const _: () = assert!(USIZE_BYTES <= 255);

/// Encodes `x` as a byte string in a way that can be
/// unambiguously parsed from the beginning.
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn left_encode(mut x: usize) -> LeftEncode {
    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = (x | 1).leading_zeros() / 8;
    // Shift into the leading zeros so that we write everything
    // at the start of the buffer. This lets us use constants for
    // writing, as well as lets us use fixed-size writes (see
    // `bytepad_blocks`, etc.).
    x <<= n * 8;

    let mut buf = [0; 1 + USIZE_BYTES];
    buf[0] = (USIZE_BYTES - n as usize) as u8;
    buf[1..].copy_from_slice(&x.to_be_bytes());

    LeftEncode { buf }
}

/// The result of [`left_encode`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeftEncode {
    // Invariant: `buf[0]` is in [0, buf.len()-1).
    buf: [u8; 1 + USIZE_BYTES],
}

impl LeftEncode {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        (self.buf[0] + 1) as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { self.buf.get_unchecked(..self.len()) }
    }
}

impl AsRef<[u8]> for LeftEncode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Encodes `x*8` as a byte string in a way that can be
/// unambiguously parsed from the beginning.
///
/// # Rationale
///
/// [`left_encode`] is typically used to encode a length in
/// *bits*. In practice, we usually have a length in *bytes*. The
/// conversion from bytes to bits might overflow if the number of
/// bytes is large. This method avoids overflowing.
///
/// # Example
///
/// ```rust
/// use sha3_utils::{left_encode, left_encode_bytes};
///
/// assert_eq!(
///     left_encode(8192 * 8).as_bytes(),
///     left_encode_bytes(8192).as_bytes(),
/// );
///
/// // usize::MAX*8 overflows, causing an incorrect result.
/// assert_ne!(
///     left_encode(usize::MAX.wrapping_mul(8)).as_bytes(),
///     left_encode_bytes(usize::MAX).as_bytes(),
/// );
/// ```
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn left_encode_bytes(x: usize) -> LeftEncodeBytes {
    // Break `x*8` into double word arithmetic.
    let mut hi = (x >> (usize::BITS - 3)) as u8;
    let mut lo = x << 3;

    let n = if hi == 0 {
        // `lo|1` ensures that `n < USIZE_BYTES`. It's cheaper
        // than a conditional.
        let n = (lo | 1).leading_zeros() / 8;
        lo <<= n * 8;
        hi = (lo >> (usize::BITS - 8)) as u8;
        lo <<= 8;
        (n + 1) as usize
    } else {
        0
    };

    // This might be a smidge better than assigning to `buf[0]`
    // and `buf[1]` directly.
    let v = ((1 + USIZE_BYTES - n) as u16) | ((u16::from(hi)) << 8);

    let mut buf = [0; 2 + USIZE_BYTES];
    buf[..2].copy_from_slice(&v.to_le_bytes());
    buf[2..].copy_from_slice(&lo.to_be_bytes());

    LeftEncodeBytes { buf }
}

/// The result of [`left_encode_bytes`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeftEncodeBytes {
    // Invariant: `buf[0]` is in [0, buf.len()-1).
    buf: [u8; 2 + USIZE_BYTES],
}

impl LeftEncodeBytes {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        (self.buf[0] + 1) as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { self.buf.get_unchecked(..self.len()) }
    }
}

impl AsRef<[u8]> for LeftEncodeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Encodes `x` as a byte string in a way that can be
/// unambiguously parsed from the end.
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn right_encode(x: usize) -> RightEncode {
    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = (x | 1).leading_zeros() / 8;

    let mut buf = [0; USIZE_BYTES + 1];
    buf[..USIZE_BYTES].copy_from_slice(&x.to_be_bytes());
    buf[buf.len() - 1] = (USIZE_BYTES - n as usize) as u8;

    RightEncode { buf }
}

/// The result of [`right_encode`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RightEncode {
    // Invariant: `buf[buf.len()-1]` is in [1, buf.len()).
    buf: [u8; USIZE_BYTES + 1],
}

impl RightEncode {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        let n = self.buf[self.buf.len() - 1];
        self.buf.len() - 1 - n as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { self.buf.get_unchecked(self.len()..) }
    }
}

impl AsRef<[u8]> for RightEncode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Encodes `x*8` as a byte string in a way that can be
/// unambiguously parsed from the beginning.
///
/// # Rationale
///
/// [`right_encode`] is typically used to encode a length in
/// *bits*. In practice, we usually have a length in *bytes*. The
/// conversion from bytes to bits might overflow if the number of
/// bytes is large. This method avoids overflowing.
///
/// # Example
///
/// ```rust
/// use sha3_utils::{right_encode, right_encode_bytes};
///
/// assert_eq!(
///     right_encode(8192 * 8).as_bytes(),
///     right_encode_bytes(8192).as_bytes(),
/// );
///
/// // usize::MAX*8 overflows, causing an incorrect result.
/// assert_ne!(
///     right_encode(usize::MAX.wrapping_mul(8)).as_bytes(),
///     right_encode_bytes(usize::MAX).as_bytes(),
/// );
/// ```
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn right_encode_bytes(mut x: usize) -> RightEncodeBytes {
    // Break `x*8` into double word arithmetic.
    let hi = (x >> (usize::BITS - 3)) & 0x7;
    x <<= 3;

    // `x|1` ensures that `n < 8`. It's cheaper than the
    // obvious `if n == 8 { n = 7; }`.
    let n = if hi == 0 {
        1 + ((x | 1).leading_zeros() / 8)
    } else {
        0
    };

    let mut buf = [0; 1 + USIZE_BYTES + 1];
    buf[0] = hi as u8;
    buf[1..1 + USIZE_BYTES].copy_from_slice(&x.to_be_bytes());
    buf[1 + USIZE_BYTES] = (1 + USIZE_BYTES - n as usize) as u8;

    RightEncodeBytes { buf }
}

/// The result of [`right_encode_bytes`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RightEncodeBytes {
    // Invariant: `buf[buf.len()-1]` is in [1, buf.len()).
    buf: [u8; 1 + USIZE_BYTES + 1],
}

impl RightEncodeBytes {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        let n = self.buf[self.buf.len() - 1];
        self.buf.len() - 1 - n as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { self.buf.get_unchecked(self.len()..) }
    }
}

impl AsRef<[u8]> for RightEncodeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Encodes `s` such that it can be unambiguously encoded from
/// the beginning.
///
/// # Example
///
/// ```rust
/// use sha3_utils::encode_string;
///
/// let s = encode_string(b"hello, world!");
/// assert_eq!(
///     s.iter().flatten().copied().collect::<Vec<_>>(),
///     &[
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///     ],
/// );
/// ```
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn encode_string(s: &[u8]) -> EncodedString<'_> {
    let prefix = left_encode_bytes(s.len());
    EncodedString { prefix, s }
}

/// The result of [`encode_string`].
#[derive(Copy, Clone, Debug)]
pub struct EncodedString<'a> {
    prefix: LeftEncodeBytes,
    s: &'a [u8],
}

impl EncodedString<'_> {
    /// Returns an iterator over the encoded string.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn iter(&self) -> EncodedStringIter<'_> {
        EncodedStringIter {
            iter: [self.prefix.as_bytes(), self.s].into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a EncodedString<'a> {
    type Item = &'a [u8];
    type IntoIter = EncodedStringIter<'a>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over [`EncodedString`].
#[derive(Clone, Debug)]
pub struct EncodedStringIter<'a> {
    iter: array::IntoIter<&'a [u8], 2>,
}

impl<'a> Iterator for EncodedStringIter<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }

    #[inline]
    fn fold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.iter.fold(acc, f)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.iter.last()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for EncodedStringIter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl FusedIterator for EncodedStringIter<'_> {}

/// The minimum size, in bytes, allowed by [`bytepad_blocks`].
///
/// `USIZE_BYTES` is the size in bytes of [`usize`].
pub type MinBlockSize = Prod<Add1<U<{ USIZE_BYTES }>>, U2>;

/// Same as [`bytepad`], but returns the data as blocks.
///
/// In practice, this has helped avoid needless calls to `memcpy`
/// and has helped remove panicking branches.
pub fn bytepad_blocks<const W: usize>(
    s: EncodedString<'_>,
) -> ([u8; W], &[[u8; W]], Option<[u8; W]>)
where
    Const<W>: ToUInt,
    U<W>: IsGreaterOrEqual<MinBlockSize>,
{
    // `first` is left_encode(w) || left_encode(s) || s[..n].
    let (first, n) = {
        let mut first = [0u8; W];
        let mut i = 0;

        let w = left_encode(W);
        first[..w.buf.len()].copy_from_slice(&w.buf);
        i += w.len();

        first[i..i + s.prefix.buf.len()].copy_from_slice(&s.prefix.buf);
        i += s.prefix.len();

        // Help the compiler out to avoid a bounds check.
        //
        // SAFETY:
        //
        // - `W` must be at least twice as large as
        //   `1+USIZE_BYTES`.
        // - `LeftEncode.buf` is `1+USIZE_BYTES` long.
        // - `LeftEncode.n` is always in [1, buf.len()) (i.e.,
        //   a valid index into `LeftEncode.buf`).
        //
        // Therefore, `i < first.len()`.
        //
        // TODO(eric): Figure out how to express this without
        // unsafe.
        unsafe { hint::assert_unchecked(i < first.len()) }

        let n = cmp::min(first[i..].len(), s.s.len());
        first[i..i + n].copy_from_slice(&s.s[..n]);
        (first, n)
    };

    // `mid` is s[n..m].
    let (mid, rest) = as_chunks(&s.s[n..]);

    // `last` is s[..m].
    let last = if !rest.is_empty() {
        let mut block = [0u8; W];
        block[..rest.len()].copy_from_slice(rest);
        Some(block)
    } else {
        None
    };

    (first, mid, last)
}

/// Prepends the integer encoding of `W` to `s`, then pads the
/// result to a multiple of `W` for a non-zero `W`.
///
/// # Example
///
/// ```rust
/// use sha3_utils::{bytepad, encode_string};
///
/// // Accepts `EncodedString`s.
/// let v = bytepad::<32, _>(encode_string(b"hello, world!"));
/// assert_eq!(
///     v.iter().flatten().copied().collect::<Vec<_>>(),
///     &[
///         1, 32,
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     ],
/// );
///
/// // Accepts arrays of `EncodedString`s.
/// let v = bytepad::<32, _>([encode_string(b"hello, world!")]);
/// assert_eq!(
///     v.iter().flatten().copied().collect::<Vec<_>>(),
///     &[
///         1, 32,
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     ],
/// );
///
/// let v = bytepad::<32, _>([
///     encode_string(b"hello, world!"),
///     encode_string(b"hello, world!"),
/// ]);
/// assert_eq!(
///     v.iter().flatten().copied().collect::<Vec<_>>(),
///     &[
///         1, 32,
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///     ],
/// );
/// ```
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn bytepad<'a, const W: usize, N>(s: impl IntoArray<EncodedString<'a>, N>) -> BytePad<'a, W, N>
where
    N: ArraySize + NonZero,
{
    const { assert!(W > 0) }

    BytePad {
        w: left_encode(W),
        s: s.into_array(),
        pad: [0u8; W],
    }
}

/// The result of [`bytepad`].
pub struct BytePad<'a, const W: usize, N>
where
    N: ArraySize,
{
    w: LeftEncode,
    s: Array<EncodedString<'a>, N>,
    pad: [u8; W],
}

impl<const W: usize, N> BytePad<'_, W, N>
where
    N: ArraySize + Mul<U2>,
    Prod<N, U2>: Add<U2>,
    Sum<Prod<N, U2>, U2>: ArraySize,
{
    /// Returns an iterator over the byte-padded string.
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn iter(&self) -> BytePadIter<ArrayIter<&[u8], PaddedSize<N>>> {
        let mut n = Wrapping::<W>::new(self.w.len());

        let mut v = Array::<_, PaddedSize<N>>::default();
        v[0] = self.w.as_bytes();
        for (v, s) in v[1..].chunks_exact_mut(2).zip(self.s.iter()) {
            v[0] = s.prefix.as_bytes();
            v[1] = s.s;
            n += v[0].len();
            n += v[1].len();
        }
        let i = v.len() - 1;
        v[i] = &self.pad[..n.remainder()];

        BytePadIter {
            iter: v.into_iter(),
        }
    }
}

impl<'a, const W: usize, N> Copy for BytePad<'a, W, N>
where
    N: ArraySize,
    N::ArrayType<EncodedString<'a>>: Copy,
{
}

impl<const W: usize, N> Clone for BytePad<'_, W, N>
where
    N: ArraySize,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            w: self.w,
            s: self.s.clone(),
            pad: self.pad,
        }
    }
}

impl<const W: usize, N> fmt::Debug for BytePad<'_, W, N>
where
    N: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BytePad")
            .field("w", &self.w)
            .field("s", &self.s)
            .finish_non_exhaustive()
    }
}

impl<'a, const W: usize, N> IntoIterator for &'a BytePad<'a, W, N>
where
    N: ArraySize + Mul<U2>,
    Prod<N, U2>: Add<U2>,
    Sum<Prod<N, U2>, U2>: ArraySize,
{
    type Item = &'a [u8];
    type IntoIter = BytePadIter<ArrayIter<&'a [u8], PaddedSize<N>>>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over [`BytePad`].
#[derive(Clone, Debug)]
pub struct BytePadIter<I> {
    iter: I,
}

impl<I: Iterator> Iterator for BytePadIter<I> {
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }

    #[inline]
    fn count(self) -> usize {
        self.iter.count()
    }

    #[inline]
    fn fold<Acc, F>(self, acc: Acc, f: F) -> Acc
    where
        F: FnMut(Acc, Self::Item) -> Acc,
    {
        self.iter.fold(acc, f)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        self.iter.last()
    }

    #[inline]
    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.iter.nth(n)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<I: ExactSizeIterator> ExactSizeIterator for BytePadIter<I> {
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl<I: FusedIterator> FusedIterator for BytePadIter<I> {}

/// Helper trait for [`bytepad`].
pub trait IntoArray<T, N: ArraySize> {
    /// Converts `self` to an array of `T`.
    fn into_array(self) -> Array<T, N>;
}

impl<T> IntoArray<T, U1> for T {
    #[inline]
    fn into_array(self) -> Array<T, U1> {
        Array([self])
    }
}

impl<T, const N: usize> IntoArray<T, <[T; N] as AssocArraySize>::Size> for [T; N]
where
    [T; N]: AssocArraySize + Into<ArrayN<T, N>>,
{
    #[inline]
    fn into_array(self) -> ArrayN<T, { N }> {
        self.into()
    }
}

impl<T, U> IntoArray<T, U> for Array<T, U>
where
    U: ArraySize,
{
    #[inline]
    fn into_array(self) -> Array<T, U> {
        self
    }
}

type PaddedSize<N> = Sum<Prod<N, U2>, U2>;
type ArrayIter<T, N> = <Array<T, N> as IntoIterator>::IntoIter;

/// A `usize` that wraps modulo `W`.
#[derive(Copy, Clone, Debug)]
struct Wrapping<const W: usize>(usize);

impl<const W: usize> Wrapping<W> {
    const fn new(n: usize) -> Self {
        Self(n % W)
    }

    const fn remainder(self) -> usize {
        if self.0 != 0 {
            W - self.0
        } else {
            0
        }
    }
}

impl<const W: usize> Add for Wrapping<W> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        Self((a + b) % W)
    }
}
impl<const W: usize> Add<usize> for Wrapping<W> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: usize) -> Self::Output {
        let a = self.0;
        let b = rhs % W;
        Self((a + b) % W)
    }
}
impl<const W: usize> AddAssign<usize> for Wrapping<W> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs % W;
        self.0 %= W;
    }
}
impl<const W: usize> Sub<Wrapping<W>> for usize {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Wrapping<W>) -> Self::Output {
        self - rhs.0
    }
}
impl<const W: usize> PartialEq<usize> for Wrapping<W> {
    #[inline(always)]
    fn eq(&self, other: &usize) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_left_encode() {
        assert_eq!(left_encode(0).as_bytes(), &[1, 0], "#0");
        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = vec![0; 1];
            want.extend(x.to_be_bytes().iter().skip_while(|&&v| v == 0));
            want[0] = (want.len() - 1) as u8;
            assert_eq!(left_encode(x).as_bytes(), want, "#{x}");
        }
    }

    #[test]
    fn test_left_encode_bytes() {
        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = vec![0; 1];
            want.extend(
                (8 * x as u128)
                    .to_be_bytes()
                    .iter()
                    .skip_while(|&&v| v == 0),
            );
            want[0] = (want.len() - 1) as u8;
            assert_eq!(left_encode_bytes(x).as_bytes(), want, "#{x}");
        }
    }

    #[test]
    fn test_right_encode() {
        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = Vec::from_iter(x.to_be_bytes().iter().copied().skip_while(|&v| v == 0));
            want.push(want.len() as u8);
            assert_eq!(right_encode(x).as_bytes(), want, "#{x}");
        }
    }

    #[test]
    fn test_right_encode_bytes() {
        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = Vec::from_iter(
                (8 * x as u128)
                    .to_be_bytes()
                    .iter()
                    .copied()
                    .skip_while(|&v| v == 0),
            );
            want.push(want.len() as u8);
            assert_eq!(right_encode_bytes(x).as_bytes(), want, "#{x}");
        }
    }

    #[test]
    fn test_bytepad() {
        #[rustfmt::skip]
        let want = &[
            1, 32, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        ];
        let v = bytepad::<32, _>(encode_string(b"hello, world!"));
        assert_eq!(v.iter().flatten().copied().collect::<Vec<_>>(), want);
        let v = bytepad::<32, _>([encode_string(b"hello, world!")]);
        assert_eq!(v.iter().flatten().copied().collect::<Vec<_>>(), want);

        #[rustfmt::skip]
        let want = &[
            1, 32, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
        ];
        let v = bytepad::<32, _>([
            encode_string(b"hello, world!"),
            encode_string(b"hello, world!"),
        ]);
        assert_eq!(v.iter().flatten().copied().collect::<Vec<_>>(), want);
    }
}
