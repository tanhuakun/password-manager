#[cfg(test)]
pub mod test_utils {
    use crate::config::CSRF_HEADER_NAME;
    use crate::utils::csrf_utils::generate_csrf_token;

    pub const TEST_CSRF_TOKEN: &str = "abcdefghijklmnop";
    pub const CSRF_TOKEN_HEADER: (&str, &str) = (CSRF_HEADER_NAME, TEST_CSRF_TOKEN);
}