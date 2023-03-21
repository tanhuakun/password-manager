use crate::models::users::{NewUser, User};
use crate::models::users_oauth::{NewUserOAuth, UserOAuth};
use argon2::{self, Config};
use diesel::prelude::*;
use rand::Rng;

type DbError = Box<dyn std::error::Error + Send + Sync>;

pub const MANUAL_REGISTRATION: &str = "Manual";
pub const OAUTH_REGISTRATION: &str = "OAuth";
pub const GOOGLE_PROVIDER: &str = "Google";

fn hash_password(password_to_hash: &str) -> String {
    let config = Config::default();
    let mut salt = vec![0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill(&mut salt[..]);
    argon2::hash_encoded(password_to_hash.as_bytes(), &salt, &config)
        .expect("Error in argon::hash_encoded, something wrong?")
}

fn verify_password(password_to_hash: &str, hash: &str) -> bool {
    argon2::verify_encoded(hash, password_to_hash.as_bytes())
        .expect("Error in argon::verify_encoded, something wrong?")
}

// some variables might be mispelled to prevent collision with column imported inside the function, true for all functions.
pub fn find_user_by_username_and_registration(
    conn: &mut MysqlConnection,
    usrname: &str,
    registratio_type: &str,
) -> Result<Option<User>, DbError> {
    use crate::models::schema::users::dsl::*;

    let user = users
        .filter(username.eq(usrname))
        .filter(registration_type.eq(registratio_type))
        .first::<User>(conn)
        .optional()?;

    Ok(user)
}

pub fn find_user_by_id(conn: &mut MysqlConnection, user_id: i32) -> Result<Option<User>, DbError> {
    use crate::models::schema::users::dsl::*;

    let user = users
        .filter(id.eq(user_id))
        .first::<User>(conn)
        .optional()?;

    Ok(user)
}

pub fn find_oauth_user_by_oauth_id(
    conn: &mut MysqlConnection,
    auth_id: &str,
) -> Result<Option<UserOAuth>, DbError> {
    use crate::models::schema::users_oauth::dsl::*;

    let user = users_oauth
        .filter(oauth_id.eq(auth_id))
        .first::<UserOAuth>(conn)
        .optional()?;

    Ok(user)
}

pub fn check_user_login(
    conn: &mut MysqlConnection,
    usrname: &str,
    pass: &str,
) -> Result<Option<User>, DbError> {
    use crate::models::schema::users::dsl::*;

    let user = users
        .filter(username.eq(usrname))
        .first::<User>(conn)
        .optional()?;

    if user.is_none() {
        return Ok(user);
    }

    let password_hash = (user.as_ref()).unwrap().password.as_ref().unwrap(); // TODO is this the best way?

    let is_valid_password = verify_password(pass, &password_hash);

    if !is_valid_password {
        return Ok(None);
    } else {
        return Ok(user);
    }
}

pub fn insert_new_user<'a>(
    conn: &mut MysqlConnection,
    usrname: &'a str,
    pass: Option<&'a str>,
    registratio_type: &str,
) -> Result<NewUser, DbError> {
    use crate::models::schema::users::dsl::*;
    let hashed_password = pass.map(|p| hash_password(p));

    let new_user = NewUser {
        username: usrname.to_owned(),
        password: hashed_password,
        registration_type: registratio_type.to_owned(),
    };

    diesel::insert_into(users).values(&new_user).execute(conn)?;

    Ok(new_user)
}

pub fn insert_new_oauth_user<'a>(
    conn: &mut MysqlConnection,
    usr_id: i32,
    auth_id: &'a str,
    auth_provider: &'a str,
) -> Result<NewUserOAuth, DbError> {
    use crate::models::schema::users_oauth::dsl::*;

    let new_user = NewUserOAuth {
        user_id: usr_id,
        oauth_id: auth_id.to_owned(),
        oauth_provider: auth_provider.to_owned(),
    };

    diesel::insert_into(users_oauth)
        .values(&new_user)
        .execute(conn)?;

    Ok(new_user)
}
