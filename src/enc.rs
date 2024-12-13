use core::{
    iter::{ExactSizeIterator, FusedIterator},
    mem::MaybeUninit,
};

use super::util::{copy_from_slice, slice_assume_init_ref};

const USIZE_BYTES: usize = ((usize::BITS + 7) / 8) as usize;
const BITS_SIZE: usize = USIZE_BYTES;
const BYTES_SIZE: usize = BITS_SIZE + 1;
const ENC_BUF_SIZE: usize = BYTES_SIZE + 1;

/// Implements `right_encode` and `left_encode`.
#[derive(Debug)]
pub struct EncBuf {
    buf: [MaybeUninit<u8>; ENC_BUF_SIZE],
}

impl EncBuf {
    /// Creates a new `EncBuf`.
    #[inline]
    pub const fn new() -> Self {
        Self {
            buf: [MaybeUninit::uninit(); ENC_BUF_SIZE],
        }
    }

    /// Encodes `s` such that it can be unambiguously encoded
    /// from the beginning.
    ///
    /// ```
    /// use tuple_hash::EncBuf;
    ///
    /// let mut b = EncBuf::new();
    /// let s = b.encode_string(b"hello, world!");
    /// assert_eq!(
    ///     s.flatten().copied().collect::<Vec<_>>(),
    ///     &[
    ///         1, 104,
    ///         104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33,
    ///     ],
    /// );
    /// ```
    pub fn encode_string<'a, 'b>(&'a mut self, s: &'b [u8]) -> EncodedString<'a>
    where
        'b: 'a,
    {
        const { assert!(usize::BITS < 2040 - 3) }

        let prefix = self.left_encode_bytes(s.len());
        EncodedString {
            iter: [prefix, s].into_iter(),
        }
    }

    /// Encodes `x` as a byte string in a way that can be
    /// unambiguously parsed from the beginning.
    pub fn left_encode(&mut self, x: usize) -> &[u8] {
        const { assert!(usize::BITS < 2040 - 3) }

        let dst = &mut self.buf[..1 + BITS_SIZE];

        copy_from_slice(&mut dst[1..], &x.to_be_bytes());

        // `x|1` ensures that `n < 8`. It's cheaper than the
        // obvious `if n == 8 { n = 7; }`.
        let n = ((x | 1).leading_zeros() / 8) as usize;
        dst[n].write({
            let mut v = USIZE_BYTES - n;
            if v == 0 {
                v = 1;
            }
            v as u8
        });
        unsafe { slice_assume_init_ref(&dst[n..]) }
    }

    /// Encodes `x*8` as a byte string in a way that can be
    /// unambiguously parsed from the beginning.
    ///
    /// # Rationale
    ///
    /// [`left_encode`][Self::left_encode] is typically used to
    /// encode a length in *bits*. In practice, we usually have
    /// a length in *bytes*. The conversion from bytes to bits
    /// might overflow if the number of bytes is large. This
    /// method avoids overflowing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tuple_hash::EncBuf;
    ///
    /// assert_eq!(
    ///     EncBuf::new().left_encode(8192 * 8),
    ///     EncBuf::new().left_encode_bytes(8192),
    /// );
    ///
    /// // usize::MAX*8 overflows, causing an incorrect result.
    /// assert_ne!(
    ///     EncBuf::new().left_encode(usize::MAX.wrapping_mul(8)),
    ///     EncBuf::new().left_encode_bytes(usize::MAX),
    /// );
    /// ```
    pub fn left_encode_bytes(&mut self, mut x: usize) -> &[u8] {
        const { assert!(usize::BITS < 2040 - 3) }

        let dst = &mut self.buf[..1 + BYTES_SIZE];

        let hi = (x >> (usize::BITS - 3)) & 0x7;
        dst[1].write(hi as u8);
        x <<= 3;
        copy_from_slice(&mut dst[2..], &x.to_be_bytes());

        // `x|1` ensures that `n < 8`. It's cheaper than the
        // obvious `if n == 8 { n = 7; }`.
        let n = if hi == 0 {
            1 + ((x | 1).leading_zeros() / 8) as usize
        } else {
            0
        };
        dst[n].write({
            let mut v = 1 + USIZE_BYTES - n;
            if v == 0 {
                v = 1;
            }
            v as u8
        });
        unsafe { slice_assume_init_ref(&dst[n..]) }
    }

    /// Encodes `x` as a byte string in a way that can be
    /// unambiguously parsed from the end.
    pub fn right_encode(&mut self, x: usize) -> &[u8] {
        const { assert!(usize::BITS < 2040 - 3) }

        let dst = &mut self.buf[..BITS_SIZE + 1];

        copy_from_slice(&mut dst[..USIZE_BYTES], &x.to_be_bytes());

        // `x|1` ensures that `n < 8`. It's cheaper than the
        // obvious `if n == 8 { n = 7; }`.
        let n = ((x | 1).leading_zeros() / 8) as usize;
        dst[dst.len() - 1].write({
            let mut v = USIZE_BYTES - n;
            if v == 0 {
                v = 1;
            }
            v as u8
        });
        unsafe { slice_assume_init_ref(&dst[n..]) }
    }

    /// Encodes `x*8` as a byte string in a way that can be
    /// unambiguously parsed from the beginning.
    ///
    /// # Rationale
    ///
    /// [`right_encode`][Self::right_encode] is typically used to
    /// encode a length in *bits*. In practice, we usually have
    /// a length in *bytes*. The conversion from bytes to bits
    /// might overflow if the number of bytes is large. This
    /// method avoids overflowing.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tuple_hash::EncBuf;
    ///
    /// assert_eq!(
    ///     EncBuf::new().right_encode(8192 * 8),
    ///     EncBuf::new().right_encode_bytes(8192),
    /// );
    ///
    /// // usize::MAX*8 overflows, causing an incorrect result.
    /// assert_ne!(
    ///     EncBuf::new().right_encode(usize::MAX.wrapping_mul(8)),
    ///     EncBuf::new().right_encode_bytes(usize::MAX),
    /// );
    /// ```
    pub fn right_encode_bytes(&mut self, mut x: usize) -> &[u8] {
        const { assert!(usize::BITS < 2040 - 3) }

        let dst = &mut self.buf[..BYTES_SIZE + 1];

        let hi = (x >> (usize::BITS - 3)) & 0x7;
        dst[0].write(hi as u8);
        x <<= 3;
        copy_from_slice(&mut dst[1..1 + USIZE_BYTES], &x.to_be_bytes());

        // `x|1` ensures that `n < 8`. It's cheaper than the
        // obvious `if n == 8 { n = 7; }`.
        let n = if hi == 0 {
            1 + ((x | 1).leading_zeros() / 8) as usize
        } else {
            0
        };
        dst[dst.len() - 1].write({
            let mut v = 1 + USIZE_BYTES - n;
            if v == 0 {
                v = 1;
            }
            v as u8
        });
        unsafe { slice_assume_init_ref(&dst[n..]) }
    }
}

impl Copy for EncBuf {}

impl Clone for EncBuf {
    #[inline]
    #[allow(
        clippy::non_canonical_clone_impl,
        reason = "The internal state is always meaningless \
                  between calls to `*_encode_*`."
    )]
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for EncBuf {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// An iterator over the parts of an encoded string.
///
/// See [`encode_string`][EncBuf::encode_string].
pub struct EncodedString<'a> {
    iter: core::array::IntoIter<&'a [u8], 2>,
}

impl<'a> Iterator for EncodedString<'a> {
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

impl ExactSizeIterator for EncodedString<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.iter.len()
    }
}

impl FusedIterator for EncodedString<'_> {}

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
            assert_eq!(EncBuf::new().left_encode(x), want, "#{x}");
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
            assert_eq!(EncBuf::new().left_encode_bytes(x), want, "#{x}");
        }
    }

    #[test]
    fn test_right_encode() {
        for i in 0..usize::BITS {
            let x: usize = 1 << i;
            let mut want = Vec::from_iter(x.to_be_bytes().iter().copied().skip_while(|&v| v == 0));
            want.push(want.len() as u8);
            assert_eq!(EncBuf::new().right_encode(x), want, "#{x}");
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
            assert_eq!(EncBuf::new().right_encode_bytes(x), want, "#{x}");
        }
    }
}
