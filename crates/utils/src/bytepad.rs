#![allow(
    clippy::indexing_slicing,
    reason = "The compiler can prove that the indices are in bounds"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "All arithmetic is in bounds"
)]

use core::{
    cmp,
    iter::{self, FusedIterator},
    ops::{Add, AddAssign},
};

#[cfg(feature = "no-panic")]
use no_panic::no_panic;

use crate::{
    enc::{left_encode, EncodedString, LeftEncode, LeftEncodeBytes, USIZE_BYTES},
    util::as_chunks,
};

/// The minimum size, in bytes, allowed by [`bytepad_blocks`].
pub const MIN_BLOCK_SIZE: usize = (1 + USIZE_BYTES) * 2;

/// Same as [`bytepad`], but returns the data as blocks of length
/// `W`.
///
/// In practice, this has helped avoid needless calls to `memcpy`
/// and has helped remove panicking branches.
pub fn bytepad_blocks<const W: usize>(
    s: EncodedString<'_>,
) -> ([u8; W], &[[u8; W]], Option<[u8; W]>) {
    const { assert!(W >= MIN_BLOCK_SIZE, "`W` is too small") }

    let (prefix, s) = s.to_parts();

    // `first` is left_encode(w) || left_encode(s) || s[..n].
    let (first, s) = {
        let mut first = [0u8; W];
        let mut i = 0;

        #[inline(always)]
        fn copy(dst: &mut [u8], src: &[u8]) -> usize {
            let n = cmp::min(dst.len(), src.len());
            dst[..n].copy_from_slice(&src[..n]);
            n
        }

        // This copy cannot panic because W >= (1+USIZE_BYTES)*2
        // and `w` is at most 1+USIZE_BYTES bytes long.
        let w = left_encode(W);
        copy(&mut first[i..], w.as_fixed_bytes());
        i += w.len();

        // Try and copy over the prefix. This copy cannot panic
        // because W >= (1*USIZE_BYTES)*2 and `i` is at most
        // 1+USIZE_BYTES.
        copy(&mut first[i..], prefix.as_fixed_bytes());
        i += prefix.len();

        // Fill the remainder of the block with `s`.
        let n = copy(&mut first[i..], s);
        (first, &s[n..])
    };

    // `mid` is s[n..m].
    let (mid, rest) = as_chunks(s);

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
/// let v = bytepad::<32, _>([encode_string(b"hello, world!")]);
/// assert_eq!(
///     v.flat_map(|v| v.as_bytes().to_vec()).collect::<Vec<_>>(),
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
///     v.flat_map(|v| v.as_bytes().to_vec()).collect::<Vec<_>>(),
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
pub fn bytepad<'a, const W: usize, I>(s: I) -> BytePad<'a, W, <I as IntoIterator>::IntoIter>
where
    I: IntoIterator<Item = EncodedString<'a>>,
{
    const { assert!(W > 0) }

    BytePad {
        w: iter::once(BytePadItem::w(left_encode(W))),
        x: FlatEncStrs {
            iter: s.into_iter(),
            s: None,
        },
        pad: Pad::new(left_encode(W).len()),
        done: false,
    }
}

/// The result of [`bytepad`].
#[derive(Clone, Debug)]
pub struct BytePad<'a, const W: usize, I> {
    // `left_encode(W)`
    w: iter::Once<BytePadItem<'static>>,
    // The encoded input strings, X.
    x: FlatEncStrs<'a, I>,
    // Current padding.
    pad: Pad<W>,
    // True after having returned padding.
    done: bool,
}

impl<'a, const W: usize, I> Iterator for BytePad<'a, W, I>
where
    I: Iterator<Item = EncodedString<'a>>,
{
    type Item = BytePadItem<'a>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(w) = self.w.next() {
            return Some(w);
        }
        if let Some(v) = self.x.next() {
            let item = v.into_item();
            self.pad += item.len();
            return Some(item);
        }
        if !self.done {
            self.done = true;
            let pad = self.pad.to_remainder();
            if !pad.is_empty() {
                return Some(BytePadItem::pad(pad));
            }
        }
        None
    }

    #[cfg_attr(feature = "no-panic", no_panic)]
    fn fold<B, F>(mut self, init: B, mut f: F) -> B
    where
        F: FnMut(B, Self::Item) -> B,
    {
        let mut accum = init;
        if let Some(w) = self.w.next() {
            //accum = f(accum, BytePadItem::w(w));
            accum = f(accum, w);
        }
        for v in self.x {
            let item = v.into_item();
            self.pad += item.len();
            accum = f(accum, item);
        }
        if !self.done {
            self.done = true;
            let pad = self.pad.to_remainder();
            if !pad.is_empty() {
                accum = f(accum, BytePadItem::pad(pad));
            }
        }
        accum
    }
}

impl<'a, const W: usize, I> FusedIterator for BytePad<'a, W, I> where
    I: FusedIterator<Item = EncodedString<'a>>
{
}

/// An iterator that flattens [`EncodedString`]s into their
/// parts.
#[derive(Clone, Debug)]
struct FlatEncStrs<'a, I> {
    iter: I,
    /// The string half of the current [`EncodedString`].
    s: Option<&'a [u8]>,
}

impl<'a, I> Iterator for FlatEncStrs<'a, I>
where
    I: Iterator<Item = EncodedString<'a>>,
{
    type Item = EncStrPart<'a>;

    #[inline]
    #[cfg_attr(feature = "no-panic", no_panic)]
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(s) = self.s.take() {
            return Some(EncStrPart::S(s));
        }
        let v = self.iter.next()?;
        let (p, s) = v.to_parts();
        self.s = Some(s);
        Some(EncStrPart::P(p))
    }
}

impl<'a, I> FusedIterator for FlatEncStrs<'a, I> where I: FusedIterator<Item = EncodedString<'a>> {}

/// Half of a [`EncodedString`].
#[derive(Clone, Debug)]
enum EncStrPart<'a> {
    /// The prefix.
    P(LeftEncodeBytes),
    /// The string data.
    S(&'a [u8]),
}

impl<'a> EncStrPart<'a> {
    fn into_item(self) -> BytePadItem<'a> {
        match self {
            EncStrPart::P(p) => BytePadItem::p(p),
            EncStrPart::S(s) => BytePadItem::s(s),
        }
    }
}

/// An item from [`BytePad`].
#[derive(Copy, Clone, Debug)]
pub struct BytePadItem<'a>(BytePadItemRepr<'a>);

impl<'a> BytePadItem<'a> {
    #[inline]
    const fn len(&self) -> usize {
        match &self.0 {
            BytePadItemRepr::W(v) => v.len(),
            BytePadItemRepr::P(v) => v.len(),
            BytePadItemRepr::S(v) => v.len(),
            BytePadItemRepr::Pad(v) => v.len(),
        }
    }

    /// Returns the byte representation of this item.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        match &self.0 {
            BytePadItemRepr::W(v) => v.as_bytes(),
            BytePadItemRepr::P(v) => v.as_bytes(),
            BytePadItemRepr::S(v) => v,
            BytePadItemRepr::Pad(v) => v,
        }
    }

    const fn w(v: LeftEncode) -> Self {
        Self(BytePadItemRepr::W(v))
    }
    const fn p(v: LeftEncodeBytes) -> Self {
        Self(BytePadItemRepr::P(v))
    }
    const fn s(v: &'a [u8]) -> Self {
        Self(BytePadItemRepr::S(v))
    }
    const fn pad(v: &'static [u8]) -> Self {
        Self(BytePadItemRepr::Pad(v))
    }
}

impl AsRef<[u8]> for BytePadItem<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Copy, Clone, Debug)]
enum BytePadItemRepr<'a> {
    W(LeftEncode),
    P(LeftEncodeBytes),
    S(&'a [u8]),
    Pad(&'static [u8]),
}

/// Padding modulo `W`.
#[derive(Copy, Clone, Debug)]
struct Pad<const W: usize>(usize);

impl<const W: usize> Pad<W> {
    const PAD: &[u8] = &[0u8; W];

    const fn new(n: usize) -> Self {
        const { assert!(W > 0) }

        Self(n % W)
    }

    fn to_remainder(self) -> &'static [u8] {
        const { assert!(W > 0) }

        if self.0 != 0 {
            &Self::PAD[..W - (self.0 % W)]
        } else {
            &[]
        }
    }
}

impl<const W: usize> Add for Pad<W> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        const { assert!(W > 0) }

        let a = self.0;
        let b = rhs.0;
        Self((a + b) % W)
    }
}
impl<const W: usize> Add<usize> for Pad<W> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: usize) -> Self::Output {
        const { assert!(W > 0) }

        let a = self.0;
        let b = rhs % W;
        Self((a + b) % W)
    }
}
impl<const W: usize> AddAssign<usize> for Pad<W> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: usize) {
        const { assert!(W > 0) }

        self.0 += rhs % W;
        self.0 %= W;
    }
}
impl<const W: usize> PartialEq<usize> for Pad<W> {
    #[inline(always)]
    fn eq(&self, other: &usize) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enc::encode_string;

    #[test]
    fn test_bytepad() {
        #[rustfmt::skip]
        let want = &[
            1, 32, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        ];
        let got = bytepad::<32, _>([encode_string(b"hello, world!")])
            .flat_map(|v| v.as_bytes().to_vec())
            .collect::<Vec<_>>();
        assert_eq!(got, want);

        #[rustfmt::skip]
        let want = &[
            1, 32, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
        ];
        let got = bytepad::<32, _>([
            encode_string(b"hello, world!"),
            encode_string(b"hello, world!"),
        ])
        .map(|v| v.as_bytes().to_vec())
        .flatten()
        .collect::<Vec<_>>();
        assert_eq!(got, want);
    }

    #[test]
    fn test_bytepad_blocks() {
        #[rustfmt::skip]
        let want = &[
            1, 32, 
            1, 104, 
            104, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        ];

        let (a, b, c) = bytepad_blocks::<32>(encode_string(b"hello, world!"));
        let mut got = Vec::new();
        got.extend(a);
        for block in b {
            got.extend(block);
        }
        if let Some(c) = c {
            got.extend(c);
        }
        assert_eq!(got, want);
    }
}
