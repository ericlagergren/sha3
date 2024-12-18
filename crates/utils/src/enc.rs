#![allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove that the indices are in bounds"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "All arithmetic is in bounds"
)]

use core::{
    array,
    iter::{ExactSizeIterator, FusedIterator},
    mem::MaybeUninit,
};

use super::util::{copy_from_slice, slice_assume_init_ref};

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
pub fn left_encode(x: usize) -> LeftEncode {
    let mut buf = [MaybeUninit::uninit(); 1 + USIZE_BYTES];

    copy_from_slice(&mut buf[1..], &x.to_be_bytes());

    // `x|1` ensures that `n < 8`. It's cheaper than the
    // obvious `if n == 8 { n = 7; }`.
    let n = ((x | 1).leading_zeros() / 8) as usize;
    buf[n].write((USIZE_BYTES - n) as u8);
    LeftEncode { buf, n: n as u8 }
}

/// The result of [`left_encode`].
#[derive(Copy, Clone, Debug)]
pub struct LeftEncode {
    buf: [MaybeUninit<u8>; 1 + USIZE_BYTES],
    // Invariant: `buf[n..]` has been initialized.
    n: u8,
}

impl LeftEncode {
    /// Returns the encoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: We wrote to every element in
        // `self.buf[self.n..]`.
        let src = unsafe { self.buf.get_unchecked(self.n as usize..) };
        // SAFETY: We wrote to every element in `src`.
        unsafe { slice_assume_init_ref(src) }
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
pub fn left_encode_bytes(mut x: usize) -> LeftEncodeBytes {
    let mut buf = [MaybeUninit::uninit(); 2 + USIZE_BYTES];

    let hi = (x >> (usize::BITS - 3)) & 0x7;
    buf[1].write(hi as u8);
    x <<= 3;
    copy_from_slice(&mut buf[2..], &x.to_be_bytes());

    // `x|1` ensures that `n < 8`. It's cheaper than the
    // obvious `if n == 8 { n = 7; }`.
    let n = if hi == 0 {
        1 + ((x | 1).leading_zeros() / 8) as usize
    } else {
        0
    };
    buf[n].write((1 + USIZE_BYTES - n) as u8);
    LeftEncodeBytes { buf, n: n as u8 }
}

/// The result of [`left_encode_bytes`].
#[derive(Copy, Clone, Debug)]
pub struct LeftEncodeBytes {
    buf: [MaybeUninit<u8>; 2 + USIZE_BYTES],
    // Invariant: `buf[n..]` has been initialized.
    n: u8,
}

impl LeftEncodeBytes {
    /// Returns the encoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: We wrote to every element in
        // `self.buf[self.n..BYTES_SIZE+1]`.
        let src = unsafe { self.buf.get_unchecked(self.n as usize..) };
        // SAFETY: We wrote to every element in `src`.
        unsafe { slice_assume_init_ref(src) }
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
pub fn right_encode(x: usize) -> RightEncode {
    let mut buf = [MaybeUninit::uninit(); USIZE_BYTES + 1];

    copy_from_slice(&mut buf[..USIZE_BYTES], &x.to_be_bytes());

    // `x|1` ensures that `n < 8`. It's cheaper than the
    // obvious `if n == 8 { n = 7; }`.
    let n = ((x | 1).leading_zeros() / 8) as usize;
    buf[buf.len() - 1].write((USIZE_BYTES - n) as u8);
    RightEncode { buf, n: n as u8 }
}

/// The result of [`right_encode`].
#[derive(Copy, Clone, Debug)]
pub struct RightEncode {
    buf: [MaybeUninit<u8>; USIZE_BYTES + 1],
    // Invariant: `buf[n..]` has been initialized.
    n: u8,
}

impl RightEncode {
    /// Returns the encoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: We wrote to every element in
        // `self.buf[self.n..]`.
        let src = unsafe { self.buf.get_unchecked(self.n as usize..) };
        // SAFETY: We wrote to every element in `src`.
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
    RightEncodeBytes { buf, n: n as u8 }
}

/// The result of [`right_encode_bytes`].
#[derive(Copy, Clone, Debug)]
pub struct RightEncodeBytes {
    buf: [MaybeUninit<u8>; 1 + USIZE_BYTES + 1],
    // Invariant: `buf[n..]` has been initialized.
    n: u8,
}

impl RightEncodeBytes {
    /// Returns the encoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: We wrote to every element in
        // `self.buf[self.n..BYTES_SIZE+1]`.
        let src = unsafe { self.buf.get_unchecked(self.n as usize..) };
        // SAFETY: We wrote to every element in `src`.
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
    pub fn iter(&self) -> EncodedStringIter<'_> {
        EncodedStringIter {
            iter: [self.prefix.as_bytes(), self.s].into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a EncodedString<'a> {
    type Item = &'a [u8];
    type IntoIter = EncodedStringIter<'a>;

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
