#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::transmute_ptr_to_ptr)]

use core::{
    mem::{self, MaybeUninit},
    slice,
};

// From https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.copy_from_slice
pub(crate) fn copy_from_slice<'a, T>(dst: &'a mut [MaybeUninit<T>], src: &[T]) -> &'a mut [T]
where
    T: Copy,
{
    // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout
    let uninit_src: &[MaybeUninit<T>] = unsafe { mem::transmute::<&[T], &[MaybeUninit<T>]>(src) };

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

// From https://doc.rust-lang.org/std/mem/union.MaybeUninit.html#method.slice_assume_init_ref
pub(crate) unsafe fn slice_assume_init_ref<T>(slice: &[MaybeUninit<T>]) -> &[T] {
    // SAFETY: casting `slice` to a `*const [T]` is safe since the caller guarantees that
    // `slice` is initialized, and `MaybeUninit` is guaranteed to have the same layout as `T`.
    // The pointer obtained is valid since it refers to memory owned by `slice` which is a
    // reference and thus guaranteed to be valid for reads.
    unsafe { &*(slice as *const [MaybeUninit<T>] as *const [T]) }
}

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
