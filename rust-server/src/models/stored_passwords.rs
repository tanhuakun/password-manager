use diesel::prelude::*;
use serde::Serialize;

#[derive(Queryable, Serialize, Clone)]
pub struct StoredPassword {
    pub id: i32,
    pub user_id: i32,
    pub purpose: String,
    pub password: String,
}

use super::schema::stored_passwords;

#[derive(Insertable, Serialize)]
#[diesel(table_name = stored_passwords)]
pub struct NewStoredPassword {
    pub user_id: i32,
    pub purpose: String,
    pub password: String,
}
