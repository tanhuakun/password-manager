use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

pub type DbError = Box<dyn std::error::Error + Send + Sync>;
pub type DbPool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

pub const ERR_POOL_CANNOT_GET_CONNECTION: &str = "Cannot get connection from pool!";

pub fn create_db_pool(database_url: String) -> DbPool {
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);

    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

pub fn run_migrations(conn: &mut DbPool) -> Result<(), DbError> {
    conn.get().unwrap().run_pending_migrations(MIGRATIONS)?;

    Ok(())
}
