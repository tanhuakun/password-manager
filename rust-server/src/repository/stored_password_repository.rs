use crate::database::{DbError, DbPool, ERR_POOL_CANNOT_GET_CONNECTION};
use crate::models::stored_passwords::{NewStoredPassword, StoredPassword};
use diesel::dsl::sql;
use diesel::prelude::*;

pub trait StoredPasswordRepository: Send + Sync {
    fn find_passwords_by_user(&self, _usr_id: i32) -> Result<Vec<StoredPassword>, DbError> {
        unimplemented!()
    }
    fn insert_new_password<'a>(
        &self,
        _usr_id: i32,
        _password_purpose: &'a str,
        _passwrd: &str,
    ) -> Result<StoredPassword, DbError> {
        unimplemented!()
    }

    fn find_password_by_user_and_purpose<'a>(
        &self,
        _usr_id: i32,
        _password_purpose: &'a str,
    ) -> Result<Option<StoredPassword>, DbError> {
        unimplemented!();
    }

    fn delete_password_by_ids(
        &self,
        _usr_id: i32,
        _stored_password_id: i32,
    ) -> Result<(), DbError> {
        unimplemented!()
    }
}

pub struct StoredPasswordRepositoryMain {
    pub conn_pool: DbPool,
}

impl StoredPasswordRepository for StoredPasswordRepositoryMain {
    fn find_passwords_by_user(&self, usr_id: i32) -> Result<Vec<StoredPassword>, DbError> {
        use crate::models::schema::stored_passwords::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);
        let stored_password_vec = stored_passwords
            .filter(user_id.eq(usr_id))
            .load::<StoredPassword>(&mut conn)?;

        Ok(stored_password_vec)
    }

    fn find_password_by_user_and_purpose<'a>(
        &self,
        usr_id: i32,
        password_purpose: &'a str,
    ) -> Result<Option<StoredPassword>, DbError> {
        use crate::models::schema::stored_passwords::dsl::*;

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);
        let stored_password = stored_passwords
            .filter(user_id.eq(usr_id))
            .filter(purpose.eq(password_purpose))
            .first::<StoredPassword>(&mut conn)
            .optional()?;

        Ok(stored_password)
    }

    fn insert_new_password<'a>(
        &self,
        usr_id: i32,
        password_purpose: &'a str,
        passwrd: &'a str,
    ) -> Result<StoredPassword, DbError> {
        use crate::models::schema::stored_passwords::dsl::*;

        let new_stored_password = NewStoredPassword {
            user_id: usr_id,
            purpose: password_purpose.to_owned(),
            password: passwrd.to_owned(),
        };

        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        let result = conn.transaction(move |conn| {
            diesel::insert_into(stored_passwords)
                .values(&new_stored_password)
                .execute(conn)?;

            let last_insert_id: i32 =
                diesel::select(sql::<diesel::sql_types::Integer>("LAST_INSERT_ID()"))
                    .first(conn)
                    .expect("Error getting last inserted ID");

            Ok::<StoredPassword, DbError>(StoredPassword {
                id: last_insert_id,
                user_id: new_stored_password.user_id,
                purpose: new_stored_password.purpose,
                password: new_stored_password.password,
            })
        })?;
        Ok(result)
    }

    fn delete_password_by_ids(&self, usr_id: i32, stored_password_id: i32) -> Result<(), DbError> {
        use crate::models::schema::stored_passwords::dsl::*;
        let mut conn = self.conn_pool.get().expect(ERR_POOL_CANNOT_GET_CONNECTION);

        diesel::delete(
            stored_passwords
                .filter(user_id.eq(usr_id))
                .filter(id.eq(stored_password_id)),
        )
        .execute(&mut conn)?;
        Ok(())
    }
}
