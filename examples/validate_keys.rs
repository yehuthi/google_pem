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
    let mut buffer = [0u8;5<<10];
    let mut input = String::with_capacity(5<<10);
    print!(">");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();
    match google_pem::fetch::into(&mut buffer).await {
        Ok(len) => {
            let body = google_pem::fetch::body(&buffer).unwrap();
            let mut keys = google_pem::keys::Keys::default();
            keys.try_extend(google_pem::parse(&mut buffer[body..len])).unwrap();
            let claims = keys.validate::<Claims>(input).unwrap();
            println!("{claims:?}");
        },
        Err(e) => {
            eprintln!("{e}");
        }
    }
}
