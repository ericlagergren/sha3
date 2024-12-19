//! SHA-3 utilities.

#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod enc;
mod util;

pub use enc::*;
