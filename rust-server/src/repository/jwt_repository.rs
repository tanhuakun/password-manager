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
