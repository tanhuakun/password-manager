use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
};
use dotenvy::dotenv;
use handlers::authentication::{check_login, google_login, login, register};
use jsonwebtoken::{DecodingKey, EncodingKey};
use std::env;

pub mod handlers;
pub mod models;
pub mod repository;

type DbPool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = create_db_pool();

    let secret = env::var("JWT_SECRET").expect("JWT SECRET NOT SET");

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(web::Data::new(encoding_key.clone()))
            .app_data(web::Data::new(decoding_key.clone()))
            .wrap(Cors::permissive())
            .service(
                web::scope("/api")
                    .service(google_login)
                    .service(login)
                    .service(register)
                    .service(check_login),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

pub fn create_db_pool() -> DbPool {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);

    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}
