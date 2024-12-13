//! TupleHash per NIST [SP 800-185].
//!
//! [SP 800-185]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

mod hash;

pub use hash::{EncBuf, Hash, TupleHash};
