use actix_cors::Cors;
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpServer};
use database::create_db_pool;
use dotenvy::dotenv;
use handlers::authentication::{
    check_login, disable_2fa, finalise_2fa_secret, get_2fa_url, google_login, login, register,
    verify_2fa,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use repository::user_repository::{UserRepository, UserRepositoryMain};
use std::env;
use std::sync::Arc;

pub mod config;
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

    let session_secret_key = Key::generate();
    let redis_connection_string = env::var("REDIS_URL").expect("REDIS_URL NOT SET");
    let store = RedisSessionStore::new(redis_connection_string)
        .await
        .unwrap();

    let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryMain { conn_pool: pool });
    let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(encoding_key.clone()))
            .app_data(web::Data::new(decoding_key.clone()))
            .app_data(user_repository_data.clone())
            .wrap(Cors::permissive()) // TODO, change this
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/auth")
                            .wrap(
                                SessionMiddleware::builder(
                                    store.clone(),
                                    session_secret_key.clone(),
                                )
                                .session_lifecycle(
                                    PersistentSession::default()
                                        .session_ttl(time::Duration::seconds(300)),
                                )
                                .build(),
                            )
                            .service(google_login)
                            .service(login)
                            .service(register)
                            .service(check_login)
                            .service(verify_2fa),
                    )
                    .service(
                        web::scope("/2fa")
                            .service(get_2fa_url)
                            .service(finalise_2fa_secret)
                            .service(disable_2fa),
                    ),
            )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
