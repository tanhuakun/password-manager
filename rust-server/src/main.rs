use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use database::create_db_pool;
use dotenvy::dotenv;
use handlers::authentication::{check_login, google_login, login, register};
use jsonwebtoken::{DecodingKey, EncodingKey};
use repository::user_repository::{UserRepository, UserRepositoryMain};
use std::env;
use std::sync::Arc;

pub mod database;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod utils;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = create_db_pool(database_url);

    let secret = env::var("JWT_SECRET").expect("JWT SECRET NOT SET");

    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());

    let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryMain { conn_pool: pool });
    let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(encoding_key.clone()))
            .app_data(web::Data::new(decoding_key.clone()))
            .app_data(user_repository_data.clone())
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
