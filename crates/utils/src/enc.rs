#![allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove that the indices are in bounds"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "All arithmetic is in bounds"
)]

use core::{
    array, cmp, hint,
    iter::{ExactSizeIterator, FusedIterator},
    mem::MaybeUninit,
};

#[cfg(feature = "no-panic")]
use no_panic::no_panic;
use typenum::{
    generic_const_mappings::{Const, ToUInt, U},
    operator_aliases::{Add1, Prod},
    type_operators::IsGreaterOrEqual,
    U2,
};

use super::util::{as_chunks, copy_from_slice, slice_assume_init_ref};

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
    let mut buf = [0; 1 + USIZE_BYTES];

    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = ((x | 1).leading_zeros() / 8) as usize;
    x <<= n * 8;

    buf[0] = (USIZE_BYTES - n) as u8;
    buf[1..].copy_from_slice(&x.to_be_bytes());

    LeftEncode { buf }
}

/// The result of [`left_encode`].
#[derive(Copy, Clone, Debug)]
pub struct LeftEncode {
    // Invariant: `buf[0]` is in [0, buf.len()-1).
    buf: [u8; 1 + USIZE_BYTES],
}

impl LeftEncode {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless")]
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

impl Eq for LeftEncode {}
impl PartialEq for LeftEncode {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
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
    let mut buf = [0; 1 + USIZE_BYTES + 1];

    let mut hi = (x >> (usize::BITS - 3)) as u8;
    let mut lo = x << 3;

    let n = if hi == 0 {
        // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper
        // than a conditional.
        let n = (lo | 1).leading_zeros() / 8;
        lo <<= n * 8;
        hi = (lo >> (usize::BITS - 8)) as u8;
        lo <<= 8;
        (n + 1) as usize
    } else {
        0
    };

    buf[0] = (1 + USIZE_BYTES - n) as u8;
    buf[1] = hi;
    buf[2..2 + USIZE_BYTES].copy_from_slice(&lo.to_be_bytes());

    LeftEncodeBytes { buf }
}

/// The result of [`left_encode_bytes`].
#[derive(Copy, Clone, Debug)]
pub struct LeftEncodeBytes {
    // Invariant: `buf[0]` is in [0, buf.len()-1).
    buf: [u8; 2 + USIZE_BYTES],
}

impl LeftEncodeBytes {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless")]
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

impl Eq for LeftEncodeBytes {}
impl PartialEq for LeftEncodeBytes {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
    }
}

/// Encodes `x` as a byte string in a way that can be
/// unambiguously parsed from the end.
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn right_encode(x: usize) -> RightEncode {
    let mut buf = [MaybeUninit::uninit(); USIZE_BYTES + 1];

    copy_from_slice(&mut buf[..USIZE_BYTES], &x.to_be_bytes());

    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = (x | 1).leading_zeros() / 8;
    buf[buf.len() - 1].write((USIZE_BYTES - n as usize) as u8);
    RightEncode { buf }
}

/// The result of [`right_encode`].
#[derive(Copy, Clone, Debug)]
pub struct RightEncode {
    // Invariant: `buf[buf.len()-1]` is in [1, buf.len()).
    // Invariant: `buf[n..]` has been initialized where `n` is
    // `buf.len() - 1 - buf[buf.len()-1]`.
    buf: [MaybeUninit<u8>; USIZE_BYTES + 1],
}

impl RightEncode {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless")]
    pub const fn len(&self) -> usize {
        // SAFETY: `buf[buf.len()-1..]` has been initialized.
        let n = unsafe { self.buf[self.buf.len() - 1].assume_init() };
        self.buf.len() - 1 - n as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        let src = unsafe { self.buf.get_unchecked(self.len()..) };
        // SAFETY: We initialized `src`.
        unsafe { slice_assume_init_ref(src) }
    }
}

impl AsRef<[u8]> for RightEncode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Eq for RightEncode {}
impl PartialEq for RightEncode {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
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
    let mut buf = [MaybeUninit::uninit(); 1 + USIZE_BYTES + 1];

    let hi = (x >> (usize::BITS - 3)) & 0x7;
    buf[0].write(hi as u8);
    x <<= 3;
    copy_from_slice(&mut buf[1..1 + USIZE_BYTES], &x.to_be_bytes());

    // `x|1` ensures that `n < 8`. It's cheaper than the
    // obvious `if n == 8 { n = 7; }`.
    let n = if hi == 0 {
        1 + ((x | 1).leading_zeros() / 8) as usize
    } else {
        0
    };
    buf[buf.len() - 1].write((1 + USIZE_BYTES - n) as u8);
    RightEncodeBytes { buf }
}

/// The result of [`right_encode_bytes`].
#[derive(Copy, Clone, Debug)]
pub struct RightEncodeBytes {
    // Invariant: `buf[buf.len()-1]` is in [1, buf.len()).
    // Invariant: `buf[n..]` has been initialized where `n` is
    // `buf.len() - 1 - buf[buf.len()-1]`.
    buf: [MaybeUninit<u8>; 1 + USIZE_BYTES + 1],
}

impl RightEncodeBytes {
    /// Returns the number of encoded bytes.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless")]
    pub const fn len(&self) -> usize {
        // SAFETY: `buf[buf.len()-1..]` has been initialized.
        let n = unsafe { self.buf[self.buf.len() - 1].assume_init() };
        self.buf.len() - 1 - n as usize
    }

    /// Returns the encoded bytes.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, self.buf.len()).
        let src = unsafe { self.buf.get_unchecked(self.len()..) };
        // SAFETY: We initialized `src`.
        unsafe { slice_assume_init_ref(src) }
    }
}

impl AsRef<[u8]> for RightEncodeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Eq for RightEncodeBytes {}
impl PartialEq for RightEncodeBytes {
    #[inline]
    fn eq(&self, rhs: &Self) -> bool {
        self.as_bytes() == rhs.as_bytes()
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
/// result to a multiple of `W`.
///
/// # Preconditions
///
/// - `W` must be non-zero.
///
/// # Example
///
/// ```rust
/// use sha3_utils::{bytepad, encode_string};
///
/// let v = bytepad::<32>(encode_string(b"hello, world!"));
/// assert_eq!(
///     v.iter().flatten().copied().collect::<Vec<_>>(),
///     &[
///         1, 32,
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///     ],
/// );
/// ```
#[inline]
#[cfg_attr(feature = "no-panic", no_panic)]
pub fn bytepad<const W: usize>(s: EncodedString<'_>) -> BytePad<'_, W> {
    const { assert!(W > 0) }

    BytePad {
        w: left_encode(W),
        s,
        pad: [0u8; W],
    }
}

/// The result of [`bytepad`].
#[derive(Copy, Clone, Debug)]
pub struct BytePad<'a, const W: usize> {
    w: LeftEncode,
    s: EncodedString<'a>,
    pad: [u8; W],
}

impl<const W: usize> BytePad<'_, W> {
    /// Returns an iterator over the byte-padded string.
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn iter(&self) -> BytePadIter<'_> {
        let w = self.w.as_bytes();
        let prefix = self.s.prefix.as_bytes();
        let s = self.s.s;
        // TODO(eric): What if this overflows?
        let n = w.len() + prefix.len() + s.len();
        let m = if n % W != 0 { W - (n % W) } else { 0 };
        let pad = &self.pad[..m];
        BytePadIter {
            iter: [w, prefix, s, pad].into_iter(),
        }
    }
}

impl<'a, const W: usize> IntoIterator for &'a BytePad<'a, W> {
    type Item = &'a [u8];
    type IntoIter = BytePadIter<'a>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over [`BytePad`].
#[derive(Clone, Debug)]
pub struct BytePadIter<'a> {
    iter: array::IntoIter<&'a [u8], 4>,
}

impl<'a> Iterator for BytePadIter<'a> {
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

impl ExactSizeIterator for BytePadIter<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl FusedIterator for BytePadIter<'_> {}

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
}
