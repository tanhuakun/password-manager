use diesel::prelude::*;
use serde::Serialize;

#[derive(Queryable)]
pub struct UserOAuth {
    pub id: i32,
    pub user_id: i32,
    pub oauth_id: String,
    pub oauth_provider: String,
}

use super::schema::users_oauth;

#[derive(Insertable, Serialize)]
#[diesel(table_name = users_oauth)]
pub struct NewUserOAuth {
    pub user_id: i32,
    pub oauth_id: String,
    pub oauth_provider: String,
}
