use chrono::Utc;
use jsonwebtoken::{decode, encode, errors::Error, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use std::convert::TryFrom;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
    exp: usize,
}

pub fn generate_token(user_id: i32, encoding_key: &EncodingKey) -> Result<String, Error> {
    let header = Header::default();
    let claims = Claims {
        user_id: user_id,
        exp: usize::try_from(Utc::now().timestamp() + 60 * 60 * 24).unwrap(),
    };

    encode(&header, &claims, encoding_key)
}

pub fn verify_token(token: &str, decoding_key: &DecodingKey) -> Result<Claims, Error> {
    decode::<Claims>(&token, decoding_key, &Validation::default()).map(|data| data.claims)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn generate_verify_token() {
        let user_id = 1000;
        let secret = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";

        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let token = generate_token(user_id, &encoding_key).unwrap();
        let claims = verify_token(&token, &decoding_key).unwrap();
        assert_eq!(user_id, claims.user_id);
    }
}
