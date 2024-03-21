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
    let key_id = jsonwebtoken::decode_header(&input).unwrap().kid.unwrap();
    match google_pem::fetch::into(&mut buffer).await {
        Ok(len) => {
            let body = google_pem::fetch::body(&buffer).unwrap();
            for (id, key) in google_pem::parse(&mut buffer[body..len]) {
                if id == key_id.as_bytes() {
                    let decode = jsonwebtoken::DecodingKey::from_rsa_pem(&key).unwrap();
                    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
                    validation.set_issuer(&["accounts.google.com", "https://accounts.google.com"]);
                    validation.validate_aud = false;
                    let data = jsonwebtoken::decode::<Claims>(&input, &decode, &validation).unwrap();
                    println!("{data:?}");
                    return;
                }
            }
            eprintln!("key ID not found");
        },
        Err(e) => {
            eprintln!("{e}");
        }
    }
}
