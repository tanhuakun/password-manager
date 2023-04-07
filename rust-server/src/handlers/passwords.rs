use crate::handlers::authentication::AuthenticatedUser;
use crate::repository::user_repository::{Errors, UserRepository};
use actix_web::{get, post, web, HttpResponse, Responder, Result};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct Password {
    password: String,
}

#[get("/check_master_password_set")]
pub async fn check_master_password_set(
    user_repository: web::Data<dyn UserRepository>,
    authenticated_user: AuthenticatedUser,
) -> Result<impl Responder> {
    let user_id = authenticated_user.user_id;

    let user = web::block(move || user_repository.find_user_by_id(user_id))
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?
        .unwrap();

    let result;
    if user.password.is_none() {
        result = "false";
    } else {
        result = "true";
    }

    Ok(HttpResponse::Ok().json(json!({ "result": result })))
}

#[post("/set_master_password")]
pub async fn set_master_password(
    user_repository: web::Data<dyn UserRepository>,
    authenticated_user: AuthenticatedUser,
    new_password: web::Json<Password>,
) -> Result<impl Responder> {
    let user_id = authenticated_user.user_id;

    let cloned_user_repository = user_repository.clone();
    let user = web::block(move || cloned_user_repository.find_user_by_id(user_id))
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?
        .unwrap();

    if user.password.is_some() {
        return Ok(HttpResponse::Conflict().json(json!({
            "msg" : "Password is set!"
        })));
    }

    web::block(move || user_repository.set_user_password(user_id, new_password.password.clone()))
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Ok().finish())
}

#[post("/verify_master_password")]
pub async fn verify_master_password(
    user_repository: web::Data<dyn UserRepository>,
    authenticated_user: AuthenticatedUser,
    password: web::Json<Password>,
) -> Result<impl Responder> {
    let user_id = authenticated_user.user_id;

    let is_password_ok_result =
        web::block(move || user_repository.check_user_password(user_id, &password.password))
            .await?;

    if let Err(e) = is_password_ok_result {
        match &e.downcast_ref::<Errors>() {
            Some(Errors::PasswordNotSetError) => {
                println!("Password not set error!");
                return Ok(HttpResponse::Conflict().json(json!({
                    "msg" : "Password is not set!"
                })));
            }
            _ => return Ok(HttpResponse::InternalServerError().finish()),
        }
    }

    let result;
    if is_password_ok_result.unwrap() {
        result = "true";
    } else {
        result = "false";
    }

    Ok(HttpResponse::Ok().json(json!({ "result": result })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AUTH_COOKIE_NAME;
    use crate::database::DbError;
    use crate::models::users::User;
    use crate::repository::user_repository::{UserRepository, MANUAL_REGISTRATION};
    use crate::utils::jwt_utils::generate_token;
    use actix_web::dev::ServiceResponse;
    use actix_web::test::TestRequest;
    use actix_web::{cookie::Cookie, test, web, App};
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use std::sync::Arc;

    const SECRET: &str = "1qGpT9oS0dChQ287Ve1Uyha6CRG3nqGI";

    async fn generate_response(
        user_repository_data: web::Data<dyn UserRepository>,
        test_request: TestRequest,
    ) -> ServiceResponse {
        let encoding_key = EncodingKey::from_secret(SECRET.as_bytes());
        let decoding_key = DecodingKey::from_secret(SECRET.as_bytes());

        let app = test::init_service(
            App::new()
                .service(set_master_password)
                .service(check_master_password_set)
                .service(verify_master_password)
                .app_data(user_repository_data.clone())
                .app_data(web::Data::new(encoding_key.clone()))
                .app_data(web::Data::new(decoding_key.clone())),
        )
        .await;

        test::call_service(&app, test_request.to_request()).await
    }

    fn build_auth_cookie<'a>() -> Cookie<'a> {
        let encoding_key = EncodingKey::from_secret(SECRET.as_bytes());
        let auth_token = generate_token(1, &encoding_key).unwrap();
        Cookie::build(AUTH_COOKIE_NAME, auth_token)
            .http_only(true)
            .finish()
    }

    pub struct UserRepositoryPasswordIsSetStub {}

    impl UserRepository for UserRepositoryPasswordIsSetStub {
        fn find_user_by_id(&self, _user_id: i32) -> std::result::Result<Option<User>, DbError> {
            return Ok(Some(User {
                id: 1,
                username: String::from("Test"),
                password: Some(String::from("Test")),
                registration_type: String::from(MANUAL_REGISTRATION),
                totp_enabled: false,
                totp_base32: None,
            }));
        }
    }

    pub struct UserRepositoryPasswordIsNotSetStub {}

    impl UserRepository for UserRepositoryPasswordIsNotSetStub {
        fn find_user_by_id(&self, _user_id: i32) -> std::result::Result<Option<User>, DbError> {
            return Ok(Some(User {
                id: 1,
                username: String::from("Test"),
                password: None,
                registration_type: String::from(MANUAL_REGISTRATION),
                totp_enabled: false,
                totp_base32: None,
            }));
        }

        fn set_user_password(
            &self,
            _usr_id: i32,
            _new_password: String,
        ) -> std::result::Result<(), DbError> {
            Ok(())
        }
    }

    pub struct UserRepositoryCheckPasswordNotExistsStub {}

    impl UserRepository for UserRepositoryCheckPasswordNotExistsStub {
        fn check_user_password(
            &self,
            _usr_id: i32,
            _pass: &str,
        ) -> std::result::Result<bool, DbError> {
            Err(Box::from(Errors::PasswordNotSetError))
        }
    }

    pub struct UserRepositoryCheckPasswordOkStub {}

    impl UserRepository for UserRepositoryCheckPasswordOkStub {
        fn check_user_password(
            &self,
            _usr_id: i32,
            _pass: &str,
        ) -> std::result::Result<bool, DbError> {
            Ok(true)
        }
    }

    pub struct UserRepositoryCheckPasswordNotOkStub {}

    impl UserRepository for UserRepositoryCheckPasswordNotOkStub {
        fn check_user_password(
            &self,
            _usr_id: i32,
            _pass: &str,
        ) -> std::result::Result<bool, DbError> {
            Ok(false)
        }
    }

    #[actix_web::test]
    async fn check_master_password_set_true_test() {
        let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryPasswordIsSetStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::get()
            .uri("/check_master_password_set")
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let body = test::read_body(resp).await;
        let expected_response = json!({"result": "true"}); // Set your expected response here
        assert_eq!(body, serde_json::to_string(&expected_response).unwrap());
    }

    #[actix_web::test]
    async fn check_master_password_set_false_test() {
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryPasswordIsNotSetStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::get()
            .uri("/check_master_password_set")
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);

        let body = test::read_body(resp).await;
        let expected_response = json!({"result": "false"}); // Set your expected response here
        assert_eq!(body, serde_json::to_string(&expected_response).unwrap());
    }

    #[actix_web::test]
    async fn set_master_password_conflict_test() {
        let user_repository: Arc<dyn UserRepository> = Arc::new(UserRepositoryPasswordIsSetStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::post()
            .uri("/set_master_password")
            .set_json(json!({
                "password": "123456"
            }))
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::CONFLICT);
    }

    #[actix_web::test]
    async fn set_master_password_success_test() {
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryPasswordIsNotSetStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::post()
            .uri("/set_master_password")
            .set_json(json!({
                "password": "123456"
            }))
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn verify_master_password_conflict_test() {
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryCheckPasswordNotExistsStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::post()
            .uri("/verify_master_password")
            .set_json(json!({
                "password": "123456"
            }))
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::CONFLICT);
    }

    #[actix_web::test]
    async fn verify_master_password_false_test() {
        let user_repository: Arc<dyn UserRepository> =
            Arc::new(UserRepositoryCheckPasswordOkStub {});
        let user_repository_data: web::Data<dyn UserRepository> = web::Data::from(user_repository);

        let req = test::TestRequest::post()
            .uri("/verify_master_password")
            .set_json(json!({
                "password": "123456"
            }))
            .cookie(build_auth_cookie());

        let resp = generate_response(user_repository_data, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        let body = test::read_body(resp).await;
        let expected_response = json!({"result": "true"}); // Set your expected response here
        assert_eq!(body, serde_json::to_string(&expected_response).unwrap());
    }
}
