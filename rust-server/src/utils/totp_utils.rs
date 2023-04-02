use base32::Alphabet;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

/*************
Important note:

Only support for sha1, 30 seconds and 6 digits is implemented.
This is because Google Authenticator defaults to those values, and I do not see any purpose for adding support for other values.

It is easily extensible by adding columns in the user database to have such support in the future.
*************/

const TIME_STEP: u64 = 30;
const CODE_LENGTH: usize = 6;
const KEY_SIZE: usize = 20; // Keys SHOULD be of the length of the HMAC output to facilitate interoperability - RFC6238. SHA1 is 20 bytes

const ISSUER: &str = "PasswordManager";

pub fn generate_secret_key() -> String {
    let mut secret_bytes = [0u8; KEY_SIZE];
    let mut rng = rand::thread_rng();
    rng.fill(&mut secret_bytes[..]);

    base32::encode(Alphabet::RFC4648 { padding: true }, &secret_bytes)
}

pub fn generate_totp_url(secret: &str, username: &str) -> String {
    let username_with_no_spaces = str::replace(username, " ", ".");

    let x = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        ISSUER, username_with_no_spaces, secret, ISSUER, "SHA1", CODE_LENGTH, TIME_STEP
    );

    return x;
}

pub fn generate_totp(secret: String) -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    generate_totp_using_time(secret, seconds)
}

fn generate_totp_using_time(secret: String, seconds: u64) -> String {
    let key = base32::decode(Alphabet::RFC4648 { padding: true }, &secret).unwrap();

    let timestamp = seconds / TIME_STEP;

    let message = timestamp.to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&key).unwrap();
    mac.update(message.as_ref());
    let hash = mac.finalize().into_bytes();

    let offset = hash.last().unwrap() & 0xf; // The first half byte (nibble) of the last byte

    let mut sub_hash: [u8; 4] = [0; 4];

    sub_hash.copy_from_slice(&hash[offset as usize..(offset + 4) as usize]);

    let mut code = i32::from_be_bytes(sub_hash);

    code &= 0x7FFFFFFF;
    code %= 1_000_000;
    let mut code_str = code.to_string();
    for i in 0..(CODE_LENGTH - code_str.len()) {
        code_str.insert(i, '0');
    }
    code_str
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn generate_secret_is_base32_test() {
        let secret = generate_secret_key();
        let decoded = base32::decode(Alphabet::RFC4648 { padding: true }, &secret);
        assert!(decoded.is_some());
    }

    #[test]
    fn generate_totp_test() {
        assert_eq!(
            generate_totp_using_time("T6URMQE5UCCCAV6GZVCF7AUEKZ4DFXTJ".to_owned(), 1680413109),
            "639102"
        );
        assert_eq!(
            generate_totp_using_time("OTEXZHMLQROTSVWYSXEXBMUTJDOEGDNG".to_owned(), 1680413146),
            "927612"
        );
        assert_eq!(
            generate_totp_using_time("JBSWY3DPEHPK3PXP".to_owned(), 1680413281),
            "725869"
        );
    }
}
