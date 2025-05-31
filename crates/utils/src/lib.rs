//! SHA-3 utilities.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod bytepad;
mod enc;
mod util;

pub use bytepad::{bytepad, bytepad_blocks, BytePad};
pub use enc::{
    encode_string, left_encode, left_encode_bytes, right_encode, right_encode_bytes, EncodedString,
    EncodedStringIter, LeftEncode, LeftEncodeBytes, RightEncode, RightEncodeBytes,
};
