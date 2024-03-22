//! [`fetch::into`](into)

use std::{sync::Arc, time::SystemTime};

use once_cell::sync::Lazy;
use rustls::pki_types::ServerName;
use tokio::{net::TcpStream, io::{AsyncWriteExt, AsyncReadExt}};
use tokio_rustls::{rustls, TlsConnector};

/// TLS connector.
static CONNECTOR: Lazy<TlsConnector> = Lazy::new(|| {
	let mut root_store = rustls::RootCertStore::empty();
	root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
	let client_config = rustls::ClientConfig::builder()
		.with_root_certificates(root_store)
		.with_no_client_auth();
	TlsConnector::from(Arc::new(client_config))
});

/// The Google API server name.
static SERVER_NAME: Lazy<ServerName<'static>> = Lazy::new(|| "googleapis.com".try_into().expect("invalid DNS name"));

/// Fetches an HTTP PEM response into the given buffer and returns the number of bytes written.
///
/// Since it includes HTTP data, you might want to [`process_headers`] to extract the expiration
/// time for the keys, or if you don't care you can just get the [`body`].
///
/// Then you might want to [`parse`](crate::parse()) it.
pub async fn into(buffer: &mut [u8]) -> Result<usize, ErrorFetch> {
	let stream = TcpStream::connect("googleapis.com:443").await.map_err(ErrorFetch::Connect)?;
	let mut stream = CONNECTOR.connect(SERVER_NAME.clone(), stream).await.map_err(ErrorFetch::ConnectTcp)?;
	const REQUEST: &[u8] = b"GET /oauth2/v1/certs HTTP/1.0\r\nHost: www.googleapis.com\r\n\r\n";
	stream.write(REQUEST).await.map_err(ErrorFetch::RequestWrite)?;
	let mut bytes_read = 0;
	while let Ok(n) = stream.read(&mut buffer[bytes_read..]).await {
		if n == 0 { break; }
		bytes_read += n;
	}
	Ok(bytes_read)
}

/// Error when fetching PEMs.
#[derive(Debug, thiserror::Error)]
pub enum ErrorFetch {
	#[error("TCP connection error: {0}")]
	Connect(tokio::io::Error),
	#[error("TLS connection error: {0}")]
	ConnectTcp(tokio::io::Error),
	#[error("failed to write request: {0}")]
	RequestWrite(tokio::io::Error),
}

/// Instant / date-time types.
pub trait Instant {
	/// Gets the current instant.
	fn now() -> Self;
	/// Checks if the instant is before some other instant.
	fn is_before(&self, other: &Self) -> bool;
	/// Adds seconds to the instant.
	fn add_seconds(&mut self, seconds: u64);

	/// Checks if the given instant is expired, that is, if it already occurred.
	fn is_expired(&self) -> bool where Self: Sized {
		self.is_before(&Self::now())
	}
}

impl Instant for SystemTime {
	fn now() -> Self { Self::now() }
	fn is_before(&self, other: &Self) -> bool { self < other }
	fn add_seconds(&mut self, seconds: u64) {
		*self = *self + std::time::Duration::from_secs(seconds);
	}
}

impl Instant for std::time::Instant {
	fn now() -> Self { Self::now() }

	fn is_before(&self, other: &Self) -> bool { self < other }

	fn add_seconds(&mut self, seconds: u64) {
		*self = *self + std::time::Duration::from_secs(seconds);
	}
}

#[derive(Debug, Hash, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Age<T = u64> {
	pub age: T,
	pub max_age: T,
}

impl Age<u64> {
	pub fn expiration<I: Instant>(self, mut time: I) -> I {
		time.add_seconds(self.max_age - self.age);
		time
	}

	pub fn expiration_now<I: Instant>(self) -> I {
		self.expiration(I::now())
	}
}

/// Yields a tuple of the keys expiration data, and the [`body`] index.
pub fn process_headers(response: &[u8]) -> Result<(Age, usize), ErrorProcess> {
	use memchr::memmem;

	fn find_prefixed_number(data: &[u8], prefix: &[u8]) -> Option<u64> {
		let prefix = memmem::find(data, prefix)? + prefix.len();
		let prefix_len = data[prefix..].iter().copied().take_while(|&c| c.is_ascii_digit()).count();
		let number = &data[prefix..prefix + prefix_len];
		atoi::atoi(number)
	}

	let skipped = memchr::memchr(b'\n', response).unwrap_or(0);
	let response = &response[skipped..];
	let max_age = find_prefixed_number(response, b"max-age=").ok_or(ErrorProcess::MaxAge)?;
	let age = find_prefixed_number(response, b"Age: ").unwrap_or(0);
	let crlfcrlf = b"\r\n\r\n";
	let body = body(response).ok_or(ErrorProcess::Body)? + crlfcrlf.len() + skipped;
	Ok((Age { age, max_age }, body))
}

/// Gets the body index of an HTTP response.
pub fn body(response: &[u8]) -> Option<usize> {
	use memchr::memmem;
	let crlfcrlf = b"\r\n\r\n";
	memmem::find(response, crlfcrlf).map(|n| n + crlfcrlf.len())
}

/// Error when processing a response.
#[derive(Debug, thiserror::Error)]
pub enum ErrorProcess {
	#[error("couldn't find max-age in the response")]
	MaxAge,
	#[error("couldn't find response body")]
	Body,
}

#[cfg(test)]
mod test {
	use super::*;

	static SAMPLE: &[u8] = b"HTTP/1.0 200 OK\r\nServer: scaffolding on HTTPServer2\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nX-Content-Type-Options: nosniff\r\nDate: Fri, 26 Jan 2024 19:49:49 GMT\r\nExpires: Sat, 27 Jan 2024 02:00:59 GMT\r\nCache-Control: public, max-age=22270, must-revalidate, no-transform\r\nContent-Type: application/json; charset=UTF-8\r\nAge: 9\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\nAccept-Ranges: none\r\nVary: Origin,X-Origin,Referer,Accept-Encoding\r\n\r\n{\n  \"48a63bc4767f8550a532dc630cf7eb49ff397e7c\": \"-----BEGIN CERTIFICATE-----\\nMIIDJjCCAg6gAwIBAgIITpARon8gBycwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\\nAwwrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\\nFw0yNDAxMTUwNDM4MTNaFw0yNDAxMzExNjUzMTNaMDYxNDAyBgNVBAMMK2ZlZGVy\\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrCvOXTp/AHo4ibrYjE0bs1c0gOaB0Gu9/\\nT2hvYaynpmYBeBTi2sc9Rit0FoCVTloelyFcJ/+ZUv5Tl3NGp5UVCxWqyPg8QgTo\\nTk4/DwTC6Y/Z/MtBKzCmQqYkkoVx2dx9DvfRAGidFQSEqQhuJh2JwmXnJOQ5F3T8\\nGZ90tX3yv6wTAQc3iXNMnXn7LD3Shv9Hq8AfjA/IJI3dd7n/NXpHgQ0vY2UqfYdP\\n2VtXseG1CieB5rzB+e2FSF1kffyQjhJLmcBoJU3EQDOW8m1Qh0KlKCNSBxtqH4PB\\njf2XgPzTSQvGRwXYIZc9KakXwY+zVpZKxi6ljyxNLL2oIUkU8XHxAgMBAAGjODA2\\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQBN1buL5aXabeBGUuQctOv5Op/yXrwx\\nsckGU0hPb1/9OBQzvJ1IXQ5XQBqyHLNI/alt1qAFp0Q/aY8G/Lf0FWlUZvRqYmJ1\\n34ZxZJBJRL2cl5cV3uke3meVcm4/MYIezJHA+VZ2ApVYWEYFU4757SwkKyXcP7vE\\nwInJwTcwNaEO7bpCD6UPGYUqX7HJ56woVDk/mq3Y7c2S7iloXODbivU+mHKNNowl\\nfp2cMnDCKAkNNFOJ9qGwv5VQ0ZLPn9P1c+0pjA9ym8Gq6AUUcDlf40PrmMi/X7iL\\nvEcijJS73YkPAMD+0X3DPsks2Y0HFZ4/zwELkbHQYgNeIwwEvT6AGvy6\\n-----END CERTIFICATE-----\\n\",\n  \"85e55107466b7e29836199c58c7581f5b923be44\": \"-----BEGIN CERTIFICATE-----\\nMIIDJzCCAg+gAwIBAgIJAIvQopve/48XMA0GCSqGSIb3DQEBBQUAMDYxNDAyBgNV\\nBAMMK2ZlZGVyYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20w\\nHhcNMjQwMTIzMDQzODE0WhcNMjQwMjA4MTY1MzE0WjA2MTQwMgYDVQQDDCtmZWRl\\ncmF0ZWQtc2lnbm9uLnN5c3RlbS5nc2VydmljZWFjY291bnQuY29tMIIBIjANBgkq\\nhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4tVDrq5RbeDtlJ2Xh2dikE840LWflr89\\nCm3cGI9mQGlskTigV0anoViOH92Z1sqWAp5e1aRkLlCm+KAWc69uvOW/X70jEhzD\\nJVREeB3h+RAnzxYrbUgDEgltiUaM8Zxtt8hiVh/GDAudRmSP9kDxXL5xnJETF1gn\\nwAHa0j7cM4STLKbtwKi73CEmTjTLqGAES8XVnXp8VWGb6IuQzdmBIJkfcFog4Inq\\n93F4Cj/SXsSjECG3j56VxgwnloPCHTXVn/xS1s3OjoBCOvOVSJfg2nSTWNi93JGR\\n9pWZevh7Sq8Clw8H2lvIAPV/HYdxvsucWg8sJuTa6ZZSxT1WmBkW6QIDAQABozgw\\nNjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr\\nBgEFBQcDAjANBgkqhkiG9w0BAQUFAAOCAQEApInd0KdnkC03WXCAchOuIk9hCvoO\\nWKTlv0wapUx4I8F8qQBDkbDpRXhF4mxMwwemcIAtRWMf12wso9cukjnMw1xeo2ec\\nIaJFqHQGHsSXiU9XcIUhcS/X9tqXCVgY6FZUw9R/7k3fWw+se+R3sKKOKPUAt9sz\\n2AQ9F67emxiyVCgCD0nzx0sj0vy/Yr3GS9K4Y9UGMi2Vur8E2v/ZDko6VqcBFwIz\\ne1Vhwr5G8T6OsWf1xeEV+FpsUy2e14JhmsrNWYYMQgyxgBxH2LmNqyvudX7IVTsR\\n1Cep5Xa7BJbADYSEFiArwnlQ9p0QMNrzhPg7W8IoMMpDaSpQeQ1nYX2ecQ==\\n-----END CERTIFICATE-----\\n\"\n}\n";

	#[test]
	fn test_process_headers() {
		let (age, body) = process_headers(SAMPLE).unwrap();
		assert_eq!(age, Age { age: 9, max_age: 22270 });
		assert!(&SAMPLE[body..].starts_with(b"{\n  \"48a63bc4767f85"))
	}
}
