//! KMAC per NIST [SP 800-185].
//!
//! [SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(unused_qualifications)]
#![deny(clippy::alloc_instead_of_core)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::expect_used)]
#![deny(clippy::implicit_saturating_sub)]
#![deny(clippy::indexing_slicing)]
#![deny(clippy::missing_panics_doc)]
#![deny(clippy::panic)]
#![deny(clippy::ptr_as_ptr)]
#![deny(clippy::string_slice)]
#![deny(clippy::transmute_ptr_to_ptr)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::wildcard_imports)]
#![deny(missing_docs)]
#![deny(rust_2018_idioms)]
#![deny(unused_lifetimes)]

pub mod enc;
mod util;

pub use enc::*;
