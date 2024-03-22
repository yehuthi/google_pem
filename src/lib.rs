//! Fetches Google PEM and validates JWTs.
//!
//! This API has three levels:
//! - Fetch, cache, and validate keys: [`cache::Keys`].
//! - Fetch and validate keys: [`keys::Keys`].
//! - Fetch keys: [`fetch::into`], [`fetch::process_headers`] (or [`fetch::body`]), and [`Parse`].

pub mod fetch;
mod parse;
pub use parse::Parse;
pub mod keys;
pub mod cache;

pub use cache::Keys;

/// Parses PEM data into a (key id, escaped key) iterator.
pub fn parse<'a>(data: &'a mut [u8]) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
	parse::Parse::new(data)
}

