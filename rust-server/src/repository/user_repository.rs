use crate::database::{DbError, DbPool, ERR_POOL_CANNOT_GET_CONNECTION};
use crate::models::users::{NewUser, User};
use crate::models::users_oauth::{NewUserOAuth, UserOAuth};
use argon2::{self, Config};
use diesel::dsl::sql;
use diesel::prelude::*;
use rand::Rng;

pub const MANUAL_REGISTRATION: &str = "Manual";
pub const OAUTH_REGISTRATION: &str = "OAuth";
pub const GOOGLE_PROVIDER: &str = "Google";

pub trait UserRepository: Send + Sync {
    fn find_user_by_username_and_registration(
        &self,
        _usrname: &str,
        _registratio_type: &str,
    ) -> Result<Option<User>, DbError> {
        unimplemented!()
    }

    fn find_user_by_id(&self, _user_id: i32) -> Result<Option<User>, DbError> {
        unimplemented!()
    }

    fn find_oauth_user_by_oauth_id(&self, _auth_id: &str) -> Result<Option<UserOAuth>, DbError> {
        unimplemented!()
    }

    fn check_user_login(&self, _usrname: &str, _pass: &str) -> Result<Option<User>, DbError> {
        unimplemented!()
    }

    fn insert_new_user<'a>(
        &self,
        _usrname: &'a str,
        _pass: Option<&'a str>,
        _registratio_type: &str,
    ) -> Result<NewUser, DbError> {
        unimplemented!()
    }

    fn insert_new_oauth_user<'a>(
        &self,
        _usrname: &'a str,
        _auth_id: &'a str,
        _auth_provider: &'a str,
    ) -> Result<NewUserOAuth, DbError> {
        unimplemented!()
    }

    fn update_user_totp_secret(
        &self,
        _usr_id: i32,
        _totp_secret_base32: &str,
    ) -> Result<(), DbError> {
        unimplemented!()
    }

    fn set_user_totp_enabled(&self, _usr_id: i32, _is_enabled: bool) -> Result<(), DbError> {
        unimplemented!()
    }
}

pub struct UserRepositoryMain {
    pub conn_pool: DbPool,
}

impl UserRepository for UserRepositoryMain {
    // some variables might be mispelled to prevent collision with column imported inside the function, true for all functions.
    fn find_user_by_username_and_registration(
        &self,
        usrname: &str,
        registratio_type: &str,
    ) -> Result<Option<User>, DbError> {
        use crate::models::schema::users::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);
        let user = users
            .filter(username.eq(usrname))
            .filter(registration_type.eq(registratio_type))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    fn find_user_by_id(&self, user_id: i32) -> Result<Option<User>, DbError> {
        use crate::models::schema::users::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        let user = users
            .filter(id.eq(user_id))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    fn find_oauth_user_by_oauth_id(&self, auth_id: &str) -> Result<Option<UserOAuth>, DbError> {
        use crate::models::schema::users_oauth::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        let user = users_oauth
            .filter(oauth_id.eq(auth_id))
            .first::<UserOAuth>(&mut conn)
            .optional()?;

        Ok(user)
    }

    fn check_user_login(&self, usrname: &str, pass: &str) -> Result<Option<User>, DbError> {
        use crate::models::schema::users::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        let user = users
            .filter(username.eq(usrname))
            .first::<User>(&mut conn)
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

    fn insert_new_user<'a>(
        &self,
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

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        diesel::insert_into(users)
            .values(&new_user)
            .execute(&mut conn)?;

        Ok(new_user)
    }

    fn insert_new_oauth_user<'a>(
        &self,
        usrname: &'a str,
        auth_id: &'a str,
        auth_provider: &'a str,
    ) -> Result<NewUserOAuth, DbError> {
        use crate::models::schema::users::dsl::*;
        use crate::models::schema::users_oauth::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        let new_user_oauth = conn.transaction(move |conn| {
            let new_user = NewUser {
                username: usrname.to_owned(),
                password: None,
                registration_type: OAUTH_REGISTRATION.to_owned(),
            };

            diesel::insert_into(users).values(&new_user).execute(conn)?;

            // TODO, is this reliable?
            let last_insert_id: i32 =
                diesel::select(sql::<diesel::sql_types::Integer>("LAST_INSERT_ID()"))
                    .first(conn)
                    .expect("Error getting last inserted ID");

            let new_user_ouath = NewUserOAuth {
                user_id: last_insert_id,
                oauth_id: auth_id.to_owned(),
                oauth_provider: auth_provider.to_owned(),
            };

            diesel::insert_into(users_oauth)
                .values(&new_user_ouath)
                .execute(conn)
                .map(|_x| new_user_ouath)
        })?;

        Ok(new_user_oauth)
    }

    fn update_user_totp_secret(
        &self,
        usr_id: i32,
        totp_secret_base32: &str,
    ) -> Result<(), DbError> {
        use crate::models::schema::users::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        diesel::update(users)
            .filter(id.eq(usr_id))
            .set(totp_base32.eq(totp_secret_base32))
            .execute(&mut conn)?;

        Ok(())
    }

    fn set_user_totp_enabled(&self, usr_id: i32, is_enabled: bool) -> Result<(), DbError> {
        use crate::models::schema::users::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        diesel::update(users)
            .filter(id.eq(usr_id))
            .set(totp_enabled.eq(is_enabled))
            .execute(&mut conn)?;

        Ok(())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verify_password() {
        let password = "abcdefghi123#!@";
        let hash = hash_password(password);
        assert!(verify_password(password, &hash));
    }
}
