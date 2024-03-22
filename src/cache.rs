//! Caching [`Keys`].

use std::mem::MaybeUninit;

use serde::de::DeserializeOwned;

/// Caching [`crate::keys::Keys`].
pub struct Keys<INSTANT = std::time::SystemTime> {
	pub keys: crate::keys::Keys,
	expiration: MaybeUninit<INSTANT>,
}

impl<INSTANT> Default for Keys<INSTANT> {
	fn default() -> Self { Self::new() }
}

impl<INSTANT> Keys<INSTANT> {
	/// New empty set of keys.
	pub const fn new() -> Self {
		Self {
			keys: crate::keys::Keys::new(),
			expiration: MaybeUninit::uninit(),
		}
	}

	/// Checks if the cache is valid.
	pub fn is_valid(&self) -> bool where INSTANT: crate::fetch::Instant {
		!self.keys.is_empty() && unsafe { self.expiration.assume_init_ref() }.is_expired()
	}

	/// Validates a token.
	pub async fn validate<Claims: DeserializeOwned>(&mut self, token: &str) -> Result<jsonwebtoken::TokenData<Claims>, Error> where INSTANT: crate::fetch::Instant {
		if !self.is_valid() {
			self.keys.clear();
			let (_, age) = self.keys.extend_fetch().await?;
			self.expiration = MaybeUninit::new(age.expiration_now());
		}
		Ok(self.keys.validate(token)?)
	}
}

/// [`Keys::validate`] error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("failed to fetch keys: {0}")]
	FetchExtend(#[from] crate::keys::FetchExtendError),
	#[error("failed to validate token: {0}")]
	Validate(#[from] crate::keys::ValidateError),
}
