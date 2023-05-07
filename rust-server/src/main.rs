use actix_governor::{Governor, GovernorConfigBuilder};
use actix_session::{config::PersistentSession, storage::RedisSessionStore, SessionMiddleware};
use actix_web::{cookie::Key, web, App, HttpServer};
use config::VariableConfigBuilder;
use database::{create_db_pool, run_migrations};
use dotenvy::dotenv;
use handlers::authentication::{
    check_login, disable_2fa, finalise_2fa_secret, get_2fa_url, get_new_access_token, google_login,
    login, logout, register, verify_2fa,
};
use handlers::passwords::{
    add_password, check_master_password_set, delete_password, get_passwords, set_master_password,
    verify_master_password,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use repository::stored_password_repository::{
    StoredPasswordRepository, StoredPasswordRepositoryMain,
};
use repository::user_repository::{UserRepository, UserRepositoryMain};
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

    let var_config = VariableConfigBuilder::read_all_config();

    let mut pool = create_db_pool(var_config.database_url);

    run_migrations(&mut pool).expect("Failed to run migrations!");

    let secret = var_config.jwt_secret;

    let encoding_key = EncodingKey::from_base64_secret(&secret).unwrap();
    let decoding_key = DecodingKey::from_base64_secret(&secret).unwrap();

    let session_secret_key = Key::generate();

    let store = RedisSessionStore::new(var_config.redis_url).await.unwrap();

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(5)
        .finish()
        .unwrap();

    let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryMain {
        conn_pool: pool.clone(),
    });
    let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

    let stored_password_repository: Arc<dyn StoredPasswordRepository> =
        Arc::new(StoredPasswordRepositoryMain { conn_pool: pool });
    let stored_password_repository_data: web::Data<dyn StoredPasswordRepository> =
        web::Data::from(stored_password_repository);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(encoding_key.clone()))
            .app_data(web::Data::new(decoding_key.clone()))
            .app_data(user_repository_data.clone())
            .app_data(stored_password_repository_data.clone())
            .service(
                web::scope("/api")
                    .service(
                        web::scope("/auth")
                            .wrap(Governor::new(&governor_conf))
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
                            .service(verify_2fa)
                            .service(get_new_access_token)
                            .service(logout),
                    )
                    .service(
                        web::scope("/2fa")
                            .service(get_2fa_url)
                            .service(finalise_2fa_secret)
                            .service(disable_2fa),
                    )
                    .service(
                        web::scope("/passwords")
                            .service(check_master_password_set)
                            .service(set_master_password)
                            .service(verify_master_password)
                            .service(add_password)
                            .service(get_passwords)
                            .service(delete_password),
                    ),
            )
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
