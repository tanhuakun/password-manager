use diesel::prelude::*;
use serde::Serialize;

#[derive(Queryable)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: Option<String>,
    pub registration_type: String,
    pub totp_enabled: bool,
    pub totp_base32: Option<String>,
}

use super::schema::users;

#[derive(Insertable, Serialize)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub password: Option<String>,
    pub registration_type: String,
}
