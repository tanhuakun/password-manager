use std::env;
use std::fs;

pub const ACCESS_TOKEN_TIME_SECONDS: i64 = 60 * 15; // 15 minutes
pub const REFRESH_TOKEN_TIME_SECONDS: i64 = 60 * 60 * 24; // 1 day
pub const AUTH_COOKIE_NAME: &str = "access_token";
pub const REFRESH_COOKIE_NAME: &str = "refresh_token";
pub const CSRF_COOKIE_NAME: &str = "csrf_token";
pub const CSRF_HEADER_NAME: &str = "csrf-token";
pub const CSRF_TOKEN_BYTES: usize = 20;

const DATABASE_URL_ENV_NAME: &str = "DATABASE_URL";
const REDIS_URL_ENV_NAME: &str = "REDIS_URL";
const JWT_SECRET_ENV_NAME: &str = "JWT_SECRET";

pub struct VariableConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
}

pub struct VariableConfigBuilder {}

impl VariableConfigBuilder {
    pub fn read_all_config() -> VariableConfig {
        let database_url = Self::read_var(DATABASE_URL_ENV_NAME);
        let redis_url = Self::read_var(REDIS_URL_ENV_NAME);
        let jwt_secret = Self::read_var(JWT_SECRET_ENV_NAME);

        VariableConfig {
            database_url: database_url,
            redis_url: redis_url,
            jwt_secret: jwt_secret,
        }
    }

    pub fn read_var(env_variable_name: &str) -> String {
        let value = match env::var(env_variable_name) {
            Ok(val) => val,
            Err(_) => {
                let file_name = env::var(format!("{}_FILE", env_variable_name)).expect(
                    &(format!("{} not set through envrionment nor file", env_variable_name)),
                );
                let contents = match fs::read_to_string(file_name) {
                    Ok(val) => val,
                    Err(_) => {
                        panic!();
                    }
                };
                // read first line only
                contents.lines().next().unwrap().trim().to_owned()
            }
        };
        println!("The value is: {}", value);
        value
    }
}
