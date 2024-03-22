use std::{time::SystemTime, mem::MaybeUninit};

use serde::de::DeserializeOwned;

pub struct Keys {
	pub keys: crate::keys::Keys,
	pub expiration: MaybeUninit<SystemTime>,
}

impl Default for Keys {
	fn default() -> Self { Self::new() }
}

impl Keys {
	pub const fn new() -> Self {
		Self {
			keys: crate::keys::Keys::new(),
			expiration: MaybeUninit::uninit(),
		}
	}

	pub fn is_valid(&self) -> bool {
		!self.keys.is_empty() && SystemTime::now() < unsafe { self.expiration.assume_init() }
	}

	pub async fn validate<Claims: DeserializeOwned>(&mut self, token: &str) -> Result<jsonwebtoken::TokenData<Claims>, Error> {
		if !self.is_valid() {
			self.keys.clear();
			let (_, age) = self.keys.extend_fetch().await?;
			self.expiration = MaybeUninit::new(age.expiration_now());
		}
		Ok(self.keys.validate(token)?)
	}
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("failed to fetch keys: {0}")]
	FetchExtend(#[from] crate::keys::FetchExtendError),
	#[error("failed to validate token: {0}")]
	Validate(#[from] crate::keys::ValidateError),
}
