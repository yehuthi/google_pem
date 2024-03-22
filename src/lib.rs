pub mod fetch;
pub mod parse;
pub mod keys;
pub mod cache;

pub use cache::Keys;

/// Parses PEM data into a (key id, escaped key) iterator.
pub fn parse<'a>(data: &'a mut [u8]) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
	parse::Parse::new(data)
}

