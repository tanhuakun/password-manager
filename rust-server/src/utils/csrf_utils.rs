use crate::config::CSRF_TOKEN_BYTES;
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;

pub fn generate_csrf_token() -> String {
    let mut secret_bytes = [0u8; CSRF_TOKEN_BYTES];
    let mut rng = rand::thread_rng();
    rng.fill(&mut secret_bytes[..]);

    general_purpose::STANDARD.encode(&secret_bytes)
}
