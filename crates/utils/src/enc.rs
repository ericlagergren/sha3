#![allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove that the indices are in bounds"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "All arithmetic is in bounds"
)]

use core::{
    array, fmt,
    hash::Hash,
    hint,
    iter::{ExactSizeIterator, FusedIterator},
    slice,
};

#[cfg(feature = "no-panic")]
use no_panic::no_panic;
use zerocopy::{ByteEq, ByteHash, Immutable, IntoBytes, KnownLayout, Unaligned};

/// The size in bytes of [`usize`].
pub(crate) const USIZE_BYTES: usize = size_of::<usize>();

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
pub const fn left_encode(mut x: usize) -> LeftEncode {
    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = (x | 1).leading_zeros() / 8;
    // Shift into the leading zeros so that we write everything
    // at the start of the buffer. This lets us use constants for
    // writing, as well as lets us use fixed-size writes (see
    // `bytepad_blocks`, etc.).
    x <<= n * 8;

    LeftEncode(LeftEncodeRepr {
        n: (USIZE_BYTES - n as usize) as u8,
        w: x.to_be(),
    })
}

/// The result of [`left_encode`].
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct LeftEncode(LeftEncodeRepr);

impl LeftEncode {
    /// Returns the number of encoded bytes.
    ///
    /// The result is always non-zero.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        // SAFETY: See the invariant for `n` in `LeftEncodeRepr`.
        unsafe { hint::assert_unchecked(self.0.n <= USIZE_BYTES as u8) }

        (self.0.n + 1) as usize
    }

    /// Returns the encoded bytes.
    ///
    /// The result always has a non-zero length.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, USIZE_BYTES + 1].
        unsafe { slice::from_raw_parts(self.as_fixed_bytes().as_ptr(), self.len()) }
    }

    pub(crate) const fn as_fixed_bytes(&self) -> &[u8; size_of::<Self>()] {
        zerocopy::transmute_ref!(&self.0)
    }
}

impl AsRef<[u8]> for LeftEncode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for LeftEncode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LeftEncode").field(&self.as_bytes()).finish()
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, ByteEq, ByteHash)]
struct LeftEncodeRepr {
    /// Invariant: `n` is in [0, USIZE_BYTES]
    n: u8,
    w: usize,
}
const _: () = {
    assert!(size_of::<LeftEncodeRepr>() == 1 + USIZE_BYTES);
};

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
pub const fn left_encode_bytes(x: usize) -> LeftEncodeBytes {
    // Break `x*8` into double word arithmetic.
    let mut hi = (x >> (usize::BITS - 3)) as u8;
    let mut lo = x << 3;

    let n = if hi == 0 {
        // `lo|1` ensures that `n < USIZE_BYTES`. It's cheaper
        // than using a conditional.
        let n = (lo | 1).leading_zeros() / 8;
        lo <<= n * 8;
        // `hi == 0`, so we have one more leading byte to shift
        // off.
        hi = (lo >> (usize::BITS - 8)) as u8;
        lo <<= 8;
        (n + 1) as usize
    } else {
        0
    };

    LeftEncodeBytes(LeftEncodeBytesRepr {
        n: (1 + USIZE_BYTES - n) as u8,
        hi,
        lo: lo.to_be(),
    })
}

/// The result of [`left_encode_bytes`].
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct LeftEncodeBytes(LeftEncodeBytesRepr);

impl LeftEncodeBytes {
    /// Returns the number of encoded bytes.
    ///
    /// The result is always non-zero.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        // SAFETY: See the invariant for `n` in
        // `LeftEncodeBytesRepr`.
        unsafe { hint::assert_unchecked(self.0.n <= (USIZE_BYTES + 1) as u8) }

        (self.0.n + 1) as usize
    }

    /// Returns the encoded bytes.
    ///
    /// The result always has a non-zero length.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY: `self.len()` is in [1, USIZE_BYTES + 2].
        unsafe { slice::from_raw_parts(self.as_fixed_bytes().as_ptr(), self.len()) }
    }

    pub(crate) const fn as_fixed_bytes(&self) -> &[u8; size_of::<Self>()] {
        zerocopy::transmute_ref!(&self.0)
    }
}

impl AsRef<[u8]> for LeftEncodeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for LeftEncodeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LeftEncodeBytes")
            .field(&self.as_bytes())
            .finish()
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, ByteEq, ByteHash)]
struct LeftEncodeBytesRepr {
    /// Invariant: `n` is in [0, USIZE_BYTES+1]
    n: u8,
    hi: u8,
    lo: usize,
}
const _: () = {
    assert!(size_of::<LeftEncodeBytesRepr>() == 2 + USIZE_BYTES);
};

/// Encodes `x` as a byte string in a way that can be
/// unambiguously parsed from the end.
#[inline]
pub const fn right_encode(x: usize) -> RightEncode {
    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = (x | 1).leading_zeros() / 8;

    RightEncode(RightEncodeRepr {
        w: x.to_be(),
        n: (USIZE_BYTES - n as usize) as u8,
    })
}

/// The result of [`right_encode`].
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct RightEncode(RightEncodeRepr);

impl RightEncode {
    /// Returns the number of encoded bytes.
    ///
    /// The result is always non-zero.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        let n = self.0.n as usize;
        self.as_fixed_bytes().len() - 1 - n
    }

    /// Returns the encoded bytes.
    ///
    /// The result always has a non-zero length.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        let buf = self.as_fixed_bytes();
        let off = self.len();
        let len = buf.len() - off;

        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { slice::from_raw_parts(buf.as_ptr().add(off), len) }
    }

    const fn as_fixed_bytes(&self) -> &[u8; size_of::<Self>()] {
        zerocopy::transmute_ref!(&self.0)
    }
}

impl AsRef<[u8]> for RightEncode {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for RightEncode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RightEncode")
            .field(&self.as_bytes())
            .finish()
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, ByteEq, ByteHash)]
struct RightEncodeRepr {
    w: usize,
    /// Invariant: `n` is in [0, USIZE_BYTES]
    n: u8,
}
const _: () = {
    assert!(size_of::<RightEncodeRepr>() == USIZE_BYTES + 1);
};

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
pub const fn right_encode_bytes(mut x: usize) -> RightEncodeBytes {
    // Break `x*8` into double word arithmetic.
    let hi = (x >> (usize::BITS - 3)) & 0x7;
    x <<= 3;

    // `x|1` ensures that `n < USIZE_BYTES`. It's cheaper than
    // using a conditional.
    let n = if hi == 0 {
        1 + ((x | 1).leading_zeros() / 8)
    } else {
        0
    };

    RightEncodeBytes(RightEncodeBytesRepr {
        hi: hi as u8,
        lo: x.to_be(),
        n: (1 + USIZE_BYTES - n as usize) as u8,
    })
}

/// The result of [`right_encode_bytes`].
#[derive(Copy, Clone, Hash, Eq, PartialEq)]
pub struct RightEncodeBytes(RightEncodeBytesRepr);

impl RightEncodeBytes {
    /// Returns the number of encoded bytes.
    ///
    /// The result is always non-zero.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        let n = self.0.n as usize;
        self.as_fixed_bytes().len() - 1 - n
    }

    /// Returns the encoded bytes.
    ///
    /// The result always has a non-zero length.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        let buf = self.as_fixed_bytes();
        let off = self.len();
        let len = buf.len() - off;

        // SAFETY: `self.len()` is in [1, self.buf.len()).
        unsafe { slice::from_raw_parts(buf.as_ptr().add(off), len) }
    }

    const fn as_fixed_bytes(&self) -> &[u8; size_of::<Self>()] {
        zerocopy::transmute_ref!(&self.0)
    }
}

impl AsRef<[u8]> for RightEncodeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for RightEncodeBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RightEncodeBytes")
            .field(&self.as_bytes())
            .finish()
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone, KnownLayout, Immutable, Unaligned, IntoBytes, ByteEq, ByteHash)]
struct RightEncodeBytesRepr {
    hi: u8,
    lo: usize,
    /// Invariant: `n` is in [0, USIZE_BYTES+1]
    n: u8,
}
const _: () = {
    assert!(size_of::<RightEncodeBytesRepr>() == 1 + USIZE_BYTES + 1);
};

/// Encodes `s` such that it can be unambiguously encoded from
/// the beginning.
///
/// This is the same thing as [`encode_string`], but evaluates to
/// a constant `&[u8]`.
///
/// # Example
///
/// ```rust
/// use sha3_utils::encode_string;
///
/// let s = encode_string!(b"hello, world!");
/// assert_eq!(
///     s,
///     &[
///         1, 104,
///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
///     ],
/// );
/// ```
#[macro_export]
macro_rules! encode_string {
    ($s:expr) => {{
        const S: &[u8] = $s;
        const PREFIX: &[u8] = $crate::left_encode_bytes(S.len()).as_bytes();
        const LENGTH: usize = PREFIX.len() + S.len();
        const OUTPUT: [u8; LENGTH] = {
            let mut buf = [0u8; PREFIX.len() + S.len()];
            let mut i = 0;
            let mut j = 0;
            while j < PREFIX.len() {
                buf[i] = PREFIX[j];
                i += 1;
                j += 1;
            }
            let mut j = 0;
            while j < S.len() {
                buf[i] = S[j];
                i += 1;
                j += 1;
            }
            buf
        };
        OUTPUT.as_slice()
    }};
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
pub const fn encode_string(s: &[u8]) -> EncodedString<'_> {
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
    /// Returns the length of the encoded string.
    ///
    /// The result is always non-zero.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "Meaningless for this type")]
    pub const fn len(&self) -> usize {
        self.prefix.len() + self.s.len()
    }

    /// Returns an iterator over the encoded string.
    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    pub fn iter(&self) -> EncodedStringIter<'_> {
        EncodedStringIter {
            iter: [self.prefix.as_bytes(), self.s].into_iter(),
        }
    }

    /// Returns the two parts of the encoded string.
    #[inline]
    pub const fn as_parts(&self) -> (&LeftEncodeBytes, &[u8]) {
        (&self.prefix, self.s)
    }
}

impl<'a> EncodedString<'a> {
    /// Returns the two parts of the encoded string.
    #[inline]
    pub const fn to_parts(self) -> (LeftEncodeBytes, &'a [u8]) {
        (self.prefix, self.s)
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
    fn test_encode_string() {
        let want = encode_string(b"hello, world!")
            .into_iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        let got = encode_string!(b"hello, world!");
        assert_eq!(got, want);
    }
}
