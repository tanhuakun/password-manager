#[cfg(test)]
pub mod test_utils {
    use crate::config::CSRF_HEADER_NAME;

    pub const TEST_CSRF_TOKEN: &str = "abcdefghijklmnop";
    pub const CSRF_TOKEN_HEADER: (&str, &str) = (CSRF_HEADER_NAME, TEST_CSRF_TOKEN);
}
