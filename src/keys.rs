use std::{mem::MaybeUninit, hash::{DefaultHasher, Hasher}, fmt::Debug};
use std::hash::Hash;

use jsonwebtoken::DecodingKey;
use once_cell::sync::Lazy;

const KEYS_CAPACITY: usize = 2 + /* slack */ 2;

pub struct Keys {
	id: [MaybeUninit<u64>; KEYS_CAPACITY],
	key: [MaybeUninit<DecodingKey>; KEYS_CAPACITY],
	len: u8,
}

impl Default for Keys { fn default() -> Self { Self::new() } }

impl Keys {
	pub const fn new() -> Self {
		Self {
			id: unsafe { MaybeUninit::<[MaybeUninit<u64>; KEYS_CAPACITY]>::uninit().assume_init() },
			key: unsafe { MaybeUninit::<[MaybeUninit<DecodingKey>; KEYS_CAPACITY]>::uninit().assume_init() },
			len: 0,
		}
	}

	pub const fn len(&self) -> usize { self.len as usize }
	pub const fn is_empty(&self) -> bool { self.len == 0 }
	pub fn clear(&mut self) { self.len = 0; }

	pub unsafe fn push_unchecked(&mut self, id: &[u8], key: &[u8]) -> Result<(), jsonwebtoken::errors::Error> {
		debug_assert!(self.len() < KEYS_CAPACITY);
		let id_hash = hash(id);
		let key = DecodingKey::from_rsa_pem(key)?;
		let i = self.len();
		*self.id.get_unchecked_mut(i) = MaybeUninit::new(id_hash);
		*self.key.get_unchecked_mut(i) = MaybeUninit::new(key);
		self.len += 1;
		Ok(())
	}

	pub fn push(&mut self, id: &[u8], key: &[u8]) -> Result<bool, jsonwebtoken::errors::Error> {
		if self.len() >= KEYS_CAPACITY { return Ok(false); }
		unsafe { self.push_unchecked(id, key)?; }
		Ok(true)
	}

	pub fn try_extend<'i>(&mut self, iter: impl IntoIterator<Item = (&'i [u8], &'i [u8])>) -> Result<bool, jsonwebtoken::errors::Error> {
		for (id, key) in iter {
			if !self.push(id, key)? { return Ok(false) }
		}
		Ok(true)
	}

	pub fn iter(&self) -> impl Iterator<Item = (u64, &DecodingKey)> {
		self.id.iter()
			.zip(self.key.iter())
			.take(self.len())
			.map(|(id, key)| unsafe { (id.assume_init(), key.assume_init_ref()) })
	}

	pub fn get(&self, id: &[u8]) -> Option<&DecodingKey> {
		let id = hash(id);
		self.iter()
			.find(|&(kid,_)| kid == id)
			.map(|(_, key)| key)
	}

	pub fn validate<Claims: serde::de::DeserializeOwned>(&self, token: &str) -> Result<jsonwebtoken::TokenData<Claims>, ValidateError> {
		let kid = jsonwebtoken::decode_header(token).map_err(ValidateError::DecodeHeader)?.kid.ok_or(ValidateError::TokenMissingKeyId)?;
		let key = self.get(kid.as_bytes()).ok_or(ValidateError::UnknownKey)?;
		static VALIDATION: Lazy<jsonwebtoken::Validation> = Lazy::new(|| {
			let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
			validation.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);
			validation.validate_aud = false;
			validation
		});
		jsonwebtoken::decode(token, key, &VALIDATION).map_err(ValidateError::DecodeToken)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
	#[error("failed to decode the token header: {0}")]
	DecodeHeader(jsonwebtoken::errors::Error),
	#[error("the token does not have a key ID")]
	TokenMissingKeyId,
	#[error("failed to decode the token: {0}")]
	DecodeToken(jsonwebtoken::errors::Error),
	#[error("token needs an unknown key ID")]
	UnknownKey,
}

fn hash(a: &[u8]) -> u64 {
	let mut hasher = DefaultHasher::default();
	a.hash(&mut hasher);
	hasher.finish()
}
