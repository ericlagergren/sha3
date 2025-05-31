#![cfg(feature = "bytepad")]
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::transmute_ptr_to_ptr)]

use core::slice;

// From https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks
pub(crate) const fn as_chunks<T, const N: usize>(slice: &[T]) -> (&[[T; N]], &[T]) {
    const {
        assert!(N != 0, "chunk size must be non-zero");
    }
    let len_rounded_down = slice.len() / N * N;
    // SAFETY: The rounded-down value is always the same or smaller than the
    // original length, and thus must be in-bounds of the slice.
    let (multiple_of_n, remainder) = unsafe { slice.split_at_unchecked(len_rounded_down) };
    // SAFETY: We already panicked for zero, and ensured by construction
    // that the length of the subslice is a multiple of N.
    let array_slice = unsafe { as_chunks_unchecked(multiple_of_n) };
    (array_slice, remainder)
}

// From https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks_unchecked
const unsafe fn as_chunks_unchecked<T, const N: usize>(slice: &[T]) -> &[[T; N]] {
    let new_len = slice.len() / N;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    unsafe { slice::from_raw_parts(slice.as_ptr().cast(), new_len) }
}
