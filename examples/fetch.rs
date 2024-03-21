use std::{io::Write, time::SystemTime};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut buffer = [0u8;5<<10];
    let mut out = std::io::stdout();
    match google_pem::fetch::into(&mut buffer).await {
        Ok(len) => {
            let (age, body) = google_pem::fetch::process_headers(&buffer[..len]).unwrap();
            let expiration = age.expiration_now::<SystemTime>();
            println!("Google PEM (valid for {} seconds)", expiration.duration_since(SystemTime::now()).unwrap().as_secs());
            let body = &mut buffer[body..len];
            for (key_id, key_value) in google_pem::parse(body) {
                let _ = out.write_all(key_id);
                let _ = out.write_all(b":\n");
                let _ = out.write_all(key_value);
                let _ = out.write_all(b"\n");
            }
        },
        Err(e) => eprintln!("Error: {e}"),
    }
}
