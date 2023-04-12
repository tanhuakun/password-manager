use std::fmt;

use crate::config::{ACCESS_TOKEN_TIME_SECONDS, REFRESH_TOKEN_TIME_SECONDS};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub user_id: i32,
    exp: i64,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshClaims {
    pub user_id: i32,
    exp: i64,
    pub iat: i64,
}

#[derive(Debug)]
pub enum Errors {
    TokenExpired,
    DecodeError, // catch all for decoding errors, because for now we are not interested in them
    EncodeError, // catch all for encoding errors, because for now we are not interested in them
}

impl Errors {
    fn get_message(&self) -> &'static str {
        match self {
            Errors::TokenExpired => "Token has expired!",
            Errors::DecodeError => "Error while decoding!",
            Errors::EncodeError => "Error while encoding!",
        }
    }
}

impl std::error::Error for Errors {}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_message())
    }
}

pub fn generate_access_token(user_id: i32, encoding_key: &EncodingKey) -> Result<String, Errors> {
    let header = Header::default();
    let claims = Claims {
        user_id: user_id,
        exp: Utc::now().timestamp() + ACCESS_TOKEN_TIME_SECONDS,
    };

    encode(&header, &claims, encoding_key).map_err(|_| Errors::EncodeError)
}

pub fn verify_access_token(token: &str, decoding_key: &DecodingKey) -> Result<Claims, Errors> {
    decode::<Claims>(&token, decoding_key, &Validation::default())
        .map(|data| data.claims)
        .map_err(|e| {
            if e.into_kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                return Errors::TokenExpired {};
            } else {
                return Errors::DecodeError;
            }
        })
}

pub fn generate_refresh_token(user_id: i32, encoding_key: &EncodingKey) -> Result<String, Errors> {
    let header = Header::default();
    let claims = RefreshClaims {
        user_id: user_id,
        exp: Utc::now().timestamp() + REFRESH_TOKEN_TIME_SECONDS,
        iat: Utc::now().timestamp(),
    };

    encode(&header, &claims, encoding_key).map_err(|_| Errors::EncodeError)
}

pub fn verify_refresh_token(
    token: &str,
    decoding_key: &DecodingKey,
) -> Result<RefreshClaims, Errors> {
    decode::<RefreshClaims>(&token, decoding_key, &Validation::default())
        .map(|data| data.claims)
        .map_err(|e| {
            if e.into_kind() == jsonwebtoken::errors::ErrorKind::ExpiredSignature {
                return Errors::TokenExpired {};
            } else {
                return Errors::DecodeError;
            }
        })
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

        let token = generate_access_token(user_id, &encoding_key).unwrap();
        let claims = verify_access_token(&token, &decoding_key).unwrap();
        assert_eq!(user_id, claims.user_id);
    }
}
