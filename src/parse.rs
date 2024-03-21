use std::marker::PhantomData;

pub struct Parse<'a> {
	ptr: *mut u8,
	len: usize,
	phantom: PhantomData<&'a ()>,
}

impl<'a> Parse<'a> {
	pub fn new(data: &'a mut [u8]) -> Self {
		Self {
			ptr: data.as_mut_ptr(),
			len: data.len(),
			phantom: PhantomData::default(),
		}
	}
}

impl<'a> From<&'a mut [u8]> for Parse<'a> { fn from(data: &'a mut [u8]) -> Self { Self::new(data) } }

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

/*
impl<'a> Parse<'a> {
	pub const fn new(data: &'a [u8]) -> Self { Self(data) }
}
impl<'a> From<&'a [u8]> for Parse<'a> { fn from(data: &'a [u8]) -> Self { Self::new(data) } }
impl<'a> From<&'a str> for Parse<'a> { fn from(data: &'a str) -> Self { Self::from(data.as_bytes()) } }

impl<'a> Parse<'a> { fn eof<T>(&mut self) -> Option<T> { self.0 = &[]; None } }
impl<'a> Iterator for Parse<'a> {
	type Item = (&'a [u8], &'a [u8]);

	fn next(&mut self) -> Option<Self::Item> {
		let mut seps = self.0.iter().enumerate().filter(|(_,&c)| c == b'\"').map(|(i,_)|i);
		let Some(s1) = seps.next() else { return self.eof() };
		let Some(s2) = seps.next() else { return self.eof() };
		let Some(s3) = seps.next() else { return self.eof() };
		let Some(s4) = seps.next() else { return self.eof() };
		let id = &self.0[s1+1..s2];
		let key = &self.0[s3+1..s4];
		self.0 = &self.0[s4+1..];
		Some((id, key))
	}
}
*/

pub fn unescape(s: &mut [u8]) -> &mut [u8] {
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
