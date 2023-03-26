use crate::repository::jwt_repository::{generate_token, verify_token};
use crate::repository::user_repository::{UserRepository, GOOGLE_PROVIDER, MANUAL_REGISTRATION};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::Payload,
    get, post, web, Error, FromRequest, HttpRequest, HttpResponse, Responder, Result,
};
use futures_util::future::{ready, Ready};
use jsonwebtoken::{DecodingKey, EncodingKey};
use reqwest::{get, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const AUTH_COOKIE_NAME: &str = "access_token";

#[derive(Serialize)]
pub struct AuthenticatedUser {
    pub user_id: i32,
}

#[derive(Deserialize)]
pub struct NewUserDetails {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct LoginDetails {
    username: String,
    password: String,
}

#[derive(Deserialize)]
pub struct GoogleLoginDetails {
    access_token: String,
}

#[derive(Deserialize)]
pub struct GoogleOAuthResponse {
    name: String,
    id: String,
}

// Extractor for Authentication, used to require login for API routes.
impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let decoding_key = req.app_data::<web::Data<DecodingKey>>().unwrap();

        let cookie = req.cookie(AUTH_COOKIE_NAME);
        if let Some(cookie_value) = cookie {
            let token = cookie_value.value();

            let jwt_claims =
                verify_token(&token, decoding_key).map_err(actix_web::error::ErrorUnauthorized);

            let result = jwt_claims.map(|claim| AuthenticatedUser {
                user_id: claim.user_id,
            });
            return ready(result);
        }
        ready(Err(Error::from(actix_web::error::ErrorUnauthorized(
            "Unauthorized",
        ))))
    }
}

#[post("/register")]
pub async fn register(
    user_repository: web::Data<dyn UserRepository>,
    user_details: web::Json<NewUserDetails>,
) -> Result<impl Responder> {
    let user_repository_clone = user_repository.clone();

    let username = user_details.username.clone();

    let user_result = web::block(move || {
        // Only manual registration users require no username conflict
        user_repository_clone.find_user_by_username_and_registration(&username, MANUAL_REGISTRATION)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    if let Some(_) = user_result {
        let response_body = json!({
            "msg": "User taken"
        });

        return Ok(HttpResponse::Conflict().json(response_body));
    }

    let user = web::block(move || {
        user_repository.insert_new_user(
            &user_details.username,
            Some(&user_details.password),
            MANUAL_REGISTRATION,
        )
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().json(json!(
        {
            "username": user.username
        }
    )))
}

#[post("/login")]
pub async fn login(
    user_repository: web::Data<dyn UserRepository>,
    user_details: web::Json<LoginDetails>,
    encoding_key: web::Data<EncodingKey>,
) -> Result<impl Responder> {
    let login_result = web::block(move || {
        user_repository.check_user_login(&user_details.username, &user_details.password)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    if login_result.is_none() {
        let response_body = json!({
            "msg": "Wrong details"
        });

        return Ok(HttpResponse::Unauthorized().json(response_body));
    }

    let auth_token = login_result
        .map(|auth_user_details| generate_token(auth_user_details.id, &encoding_key).unwrap())
        .unwrap();

    let mut response = HttpResponse::Ok();

    let cookie = Cookie::build(AUTH_COOKIE_NAME, auth_token)
        .http_only(true)
        .same_site(SameSite::None) // TODO require better security.
        .finish();

    response.cookie(cookie);
    Ok(response.finish())
}

#[post("/google_login")]
pub async fn google_login(
    user_repository: web::Data<dyn UserRepository>,
    google_login_details: web::Json<GoogleLoginDetails>,
    encoding_key: web::Data<EncodingKey>,
) -> Result<impl Responder> {
    let google_access_token = &google_login_details.access_token;

    let url = Url::parse(&format!(
        "https://www.googleapis.com/oauth2/v2/userinfo?access_token={}",
        google_access_token
    ))
    .unwrap();

    let response = get(url)
        .await
        .map_err(actix_web::error::ErrorInternalServerError)?;

    let json_body = response.json::<Value>().await.unwrap();

    let oauth_details: GoogleOAuthResponse = serde_json::from_value(json_body).unwrap();

    let cloned_oauth_details_id = oauth_details.id.clone();
    let cloned_user_repository = user_repository.clone();

    let oauth_user = web::block(move || {
        cloned_user_repository.find_oauth_user_by_oauth_id(&cloned_oauth_details_id)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let auth_token;
    if let Some(oauth_user) = oauth_user {
        let cloned_user_repository = user_repository.clone();

        // user should be present because a user is created for each user_oauth entry.
        let user = web::block(move || cloned_user_repository.find_user_by_id(oauth_user.user_id))
            .await?
            .map_err(actix_web::error::ErrorInternalServerError)?;
        auth_token = generate_token(user.unwrap().id, &encoding_key).unwrap();
    } else {
        let new_oauth_user = web::block(move || {
            user_repository.insert_new_oauth_user(
                &oauth_details.name,
                &oauth_details.id,
                GOOGLE_PROVIDER,
            )
        })
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?;

        auth_token = generate_token(new_oauth_user.user_id, &encoding_key).unwrap()
    }

    let mut response = HttpResponse::Ok();

    let cookie = Cookie::build(AUTH_COOKIE_NAME, auth_token)
        .http_only(true)
        .same_site(SameSite::None) // TODO require better security.
        .finish();

    response.cookie(cookie);
    Ok(response.finish())
}

#[get("/check_login")]
pub async fn check_login(authenticated_user: AuthenticatedUser) -> Result<impl Responder> {
    Ok(HttpResponse::Ok().json(json!({
        "user_id" : authenticated_user.user_id
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::DbError;
    use crate::models::users::{NewUser, User};
    use crate::repository::user_repository::{UserRepository, MANUAL_REGISTRATION};
    use actix_web::{http, test, web, App};
    use std::sync::Arc;

    pub struct UserRepositoryUserExistsStub {}

    impl UserRepository for UserRepositoryUserExistsStub {
        // some variables might be mispelled to prevent collision with column imported inside the function, true for all functions.
        fn find_user_by_username_and_registration(
            &self,
            _usrname: &str,
            _registratio_type: &str,
        ) -> Result<Option<User>, DbError> {
            return Ok(Some(User {
                id: 1,
                username: String::from("Test"),
                password: Some(String::from("Test")),
                registration_type: String::from(MANUAL_REGISTRATION),
            }));
        }
    }

    pub struct UserRepositoryRegistrationSuccessStub {}

    impl UserRepository for UserRepositoryRegistrationSuccessStub {
        // some variables might be mispelled to prevent collision with column imported inside the function, true for all functions.
        fn find_user_by_username_and_registration(
            &self,
            _usrname: &str,
            _registratio_type: &str,
        ) -> Result<Option<User>, DbError> {
            return Ok(None);
        }

        fn insert_new_user<'a>(
            &self,
            _usrname: &'a str,
            _pass: Option<&'a str>,
            _registratio_type: &str,
        ) -> Result<NewUser, DbError> {
            return Ok(NewUser {
                username: String::from("Test"),
                password: Some(String::from("Test")),
                registration_type: String::from(MANUAL_REGISTRATION),
            });
        }
    }
    pub struct UserRepositoryCheckLoginSuccessStub {}

    impl UserRepository for UserRepositoryCheckLoginSuccessStub {
        fn check_user_login(&self, _usrname: &str, _pass: &str) -> Result<Option<User>, DbError> {
            return Ok(Some(User {
                id: 1,
                username: String::from("Test"),
                password: Some(String::from("Test")),
                registration_type: String::from(MANUAL_REGISTRATION),
            }));
        }
    }

    pub struct UserRepositoryCheckLoginFailureStub {}

    impl UserRepository for UserRepositoryCheckLoginFailureStub {
        fn check_user_login(&self, _usrname: &str, _pass: &str) -> Result<Option<User>, DbError> {
            return Ok(None);
        }
    }

    #[actix_web::test]
    async fn register_conflict_test() {
        let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryUserExistsStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let app = test::init_service(
            App::new()
                .service(register)
                .app_data(user_repository_data.clone()),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(json!({
                "username": "test",
                "password": "test"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::CONFLICT);
    }

    #[actix_web::test]
    async fn register_success_test() {
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryRegistrationSuccessStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let app = test::init_service(
            App::new()
                .service(register)
                .app_data(user_repository_data.clone()),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(json!({
                "username": "test",
                "password": "test"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn login_success_and_token_test() {
        let secret = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryCheckLoginSuccessStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let app = test::init_service(
            App::new()
                .service(login)
                .app_data(user_repository_data.clone())
                .app_data(web::Data::new(encoding_key)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(json!({
                "username": "test",
                "password": "test"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;

        let cookies: Vec<_> = resp
            .headers()
            .get_all(http::header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_owned())
            .collect();
        let auth_token = cookies
            .iter()
            .find(|s| s.starts_with(AUTH_COOKIE_NAME))
            .unwrap()
            .split_once("=")
            .unwrap()
            .1
            .split_once(";")
            .unwrap()
            .0;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert!(verify_token(auth_token, &decoding_key).is_ok());
    }

    #[actix_web::test]
    async fn login_unauthorized_test() {
        let secret = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryCheckLoginFailureStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let app = test::init_service(
            App::new()
                .service(login)
                .app_data(user_repository_data.clone())
                .app_data(web::Data::new(encoding_key)),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(json!({
                "username": "test",
                "password": "test"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn check_login_success_test() {
        let secret = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let app = test::init_service(
            App::new()
                .service(check_login)
                .app_data(web::Data::new(encoding_key.clone()))
                .app_data(web::Data::new(decoding_key.clone())),
        )
        .await;

        let auth_token = generate_token(1, &encoding_key).unwrap();

        let req = test::TestRequest::get()
            .uri("/check_login")
            .cookie(
                Cookie::build(AUTH_COOKIE_NAME, auth_token)
                    .http_only(true)
                    .finish(),
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn check_login_failure_test() {
        let secret = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let app = test::init_service(
            App::new()
                .service(check_login)
                .app_data(web::Data::new(encoding_key.clone()))
                .app_data(web::Data::new(decoding_key.clone())),
        )
        .await;

        let req = test::TestRequest::get()
            .uri("/check_login")
            .cookie(
                Cookie::build(AUTH_COOKIE_NAME, "fake_token")
                    .http_only(true)
                    .finish(),
            )
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::UNAUTHORIZED);
    }
}
