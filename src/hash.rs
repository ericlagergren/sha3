use core::mem::{self, MaybeUninit};

/// A hash function.
pub trait Hash: Clone {
    /// The hash digest.
    type Digest: AsRef<[u8]>;
    /// Creates a new hash.
    fn new() -> Self;
    /// Updates the running hash with `data`.
    fn update(&mut self, data: &[u8]);
    /// Returns the hash digest.
    fn finalize(self) -> Self::Digest;
}

/// TupleHash over a generic hash.
#[derive(Clone, Debug)]
pub struct TupleHash<H> {
    hash: H,
}

// 1. z = "".
// 2. n = the number of input strings in the tuple X.
// 3. for i = 1 to n:
//        z = z || encode_string(X[i]).
// 4. newX = z || right_encode(L).
impl<H: Hash> Hash for TupleHash<H> {
    type Digest = H::Digest;

    fn new() -> Self {
        Self { hash: H::new() }
    }

    fn update(&mut self, _data: &[u8]) {}

    fn finalize(self) -> Self::Digest {
        self.hash.finalize()
    }
}

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

    /// Encodes `x` as a byte string in a way that can be
    /// unambiguously parsed from the beginning.
    pub fn left_encode(&mut self, x: usize) -> &[u8] {
        const { assert!(usize::BITS < 2040 - 3) }

        let dst = &mut self.buf[..1 + BITS_SIZE];

        copy_from_slice(&mut dst[1..], &x.to_be_bytes());

        // `x|1` ensures that `n < 8`. It's cheaper than the
        // obvious `if n == 8 { n -= 1; }`.
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
    /// This method avoids overflowing large values of `x`.
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
        // obvious `if n == 8 { n -= 1; }`.
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
        // obvious `if n == 8 { n -= 1; }`.
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
    /// This method avoids overflowing large values of `x`.
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
        // obvious `if n == 8 { n -= 1; }`.
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

impl Clone for EncBuf {
    #[inline]
    fn clone(&self) -> Self {
        // This is correct: the internal state is always
        // meaningless between calls to
        // {left,right}_encode_{bits,bytes}.
        Self::new()
    }
}

impl Default for EncBuf {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// From https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.copy_from_slice
fn copy_from_slice<'a, T>(dst: &'a mut [MaybeUninit<T>], src: &[T]) -> &'a mut [T]
where
    T: Copy,
{
    // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout
    let uninit_src: &[MaybeUninit<T>] = unsafe { mem::transmute(src) };

    dst.copy_from_slice(uninit_src);

    // SAFETY: Valid elements have just been copied into `this` so it is initialized
    unsafe { slice_assume_init_mut(dst) }
}

// From https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.slice_assume_init_mut
unsafe fn slice_assume_init_mut<T>(slice: &mut [MaybeUninit<T>]) -> &mut [T] {
    // SAFETY: similar to safety notes for `slice_get_ref`, but we have a
    // mutable reference which is also guaranteed to be valid for writes.
    unsafe { &mut *(slice as *mut [MaybeUninit<T>] as *mut [T]) }
}

unsafe fn slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
}

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
