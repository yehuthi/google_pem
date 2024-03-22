//! PEM endpoint parsing.

use std::marker::PhantomData;

/// A parsing iterator for the PEM endpoint.
///
/// It parses the HTTP body of the PEM endpoint, and yields tuples of key ID and key.
///
/// Note: this iterator modifies its source in-place (to turn JSON "\n" sequence into actual
/// newline characters).
pub struct Parse<'a> {
	ptr: *mut u8,
	len: usize,
	phantom: PhantomData<&'a ()>,
}

impl<'a> Parse<'a> {
	/// Creates a new [`Parse`]r.
	#[inline] pub fn new(data: &'a mut [u8]) -> Self {
		Self {
			ptr: data.as_mut_ptr(),
			len: data.len(),
			phantom: PhantomData::default(),
		}
	}
}

impl<'a> From<&'a mut [u8]> for Parse<'a> { #[inline] fn from(data: &'a mut [u8]) -> Self { Self::new(data) } }

impl<'a> Iterator for Parse<'a> {
	type Item = (&'a [u8], &'a [u8]);

	fn next(&mut self) -> Option<Self::Item> {
		let mut indices = [0;4];
		let mut index_pos = 0;

		for i in 0..self.len {
			if unsafe { *self.ptr.add(i) } == b'"' {
				indices[index_pos] = i;
				index_pos += 1;
				if index_pos == 4 {
					let id = unsafe {
						std::slice::from_raw_parts(self.ptr.add(indices[0] + 1), indices[1] - indices[0] - 1)
					};
					let key = unsafe {
						std::slice::from_raw_parts_mut(self.ptr.add(indices[2] + 1), indices[3] - indices[2] - 1)
					};
					let key = &*unescape(key);
					self.ptr = unsafe { self.ptr.add(i + 1) };
					return Some((id, key));
				}
			}
		}
		self.len = 0;
		None
	}
}

/// Changes "\\n" into "\n".
///
/// Returns the resulting (typically shorter) slice.
fn unescape(s: &mut [u8]) -> &mut [u8] {
	let mut n = 0;
	for i in 0..s.len() {
		if s[i] == b'\\' && (i + 1) < s.len() && s[i + 1] == b'n' {
			s[i] = b'\n';
			s.copy_within(i + 2.., i + 1);
			n += 1;
		}
	}
	let new_len = s.len() - n;
	&mut s[..new_len]
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_unescape() {
		let mut s = *b"hello\\nworld\\n";
		let s = unescape(&mut s);
		assert_eq!(&s[..], b"hello\nworld\n")
	}
}
