use std::io::Write;

#[derive(Debug, serde::Deserialize)]
pub struct Claims {
	pub aud: String,
	pub email: String,
	pub email_verified: bool,
	pub name: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
	let mut input = String::with_capacity(5<<10);
	print!(">");
	std::io::stdout().flush().unwrap();
	std::io::stdin().read_line(&mut input).unwrap();
	let input = input.trim();
	let mut keys = google_pem::keys::Keys::default();
	keys.extend_fetch().await.unwrap();
	let claims = keys.validate::<Claims>(input).unwrap();
	println!("{claims:?}");
}
