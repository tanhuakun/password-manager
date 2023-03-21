use crate::repository::jwt_repository::{generate_token, verify_token};
use crate::repository::user_repository::{
    check_user_login, find_oauth_user_by_oauth_id, find_user_by_id,
    find_user_by_username_and_registration, insert_new_oauth_user, insert_new_user,
    GOOGLE_PROVIDER, MANUAL_REGISTRATION, OAUTH_REGISTRATION,
};
use actix_web::{
    cookie::{Cookie, SameSite},
    dev::Payload,
    get, post, web, Error, FromRequest, HttpRequest, HttpResponse, Responder, Result,
};
use diesel::{
    prelude::*,
    r2d2::{self, ConnectionManager},
};
use futures_util::future::{ready, Ready};
use jsonwebtoken::{DecodingKey, EncodingKey};
use reqwest::{get, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

type DbPool = r2d2::Pool<ConnectionManager<MysqlConnection>>;

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

        let cookie = req.cookie("access_token");
        if let Some(cookie_value) = cookie {
            let token = cookie_value.value();

            let jwt_claims = verify_token(&token, decoding_key)
                .map_err(actix_web::error::ErrorInternalServerError);

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
    pool: web::Data<DbPool>,
    user_details: web::Json<NewUserDetails>,
) -> Result<impl Responder> {
    let pool_clone = pool.clone();

    let username = user_details.username.clone();

    let user_result = web::block(move || {
        let mut conn = pool.get().expect("couldn't get db connection from pool");
        // Only manual registration users require no username conflict
        find_user_by_username_and_registration(&mut conn, &username, MANUAL_REGISTRATION)
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
        let mut conn = pool_clone
            .get()
            .expect("couldn't get db connection from pool");
        insert_new_user(
            &mut conn,
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
    pool: web::Data<DbPool>,
    user_details: web::Json<LoginDetails>,
    encoding_key: web::Data<EncodingKey>,
) -> Result<impl Responder> {
    let login_result = web::block(move || {
        let mut conn = pool.get().expect("couldn't get db connection from pool");
        check_user_login(&mut conn, &user_details.username, &user_details.password)
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
        .map(|auth_user_details| {
            generate_token(auth_user_details.id, encoding_key.as_ref()).unwrap()
        })
        .unwrap();

    let mut response = HttpResponse::Ok();

    let cookie = Cookie::build("access_token", auth_token)
        .http_only(true)
        .same_site(SameSite::None) // TODO require better security.
        .finish();

    response.cookie(cookie);
    Ok(response.finish())
}

#[post("/google_login")]
pub async fn google_login(
    pool: web::Data<DbPool>,
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

    let cloned_pool = pool.clone();
    let cloned_oauth_details_id = oauth_details.id.clone();

    let oauth_user = web::block(move || {
        let mut conn = cloned_pool
            .get()
            .expect("couldn't get db connection from pool");
        find_oauth_user_by_oauth_id(&mut conn, &cloned_oauth_details_id)
    })
    .await?
    .map_err(actix_web::error::ErrorInternalServerError)?;

    let auth_token;
    if let Some(oauth_user) = oauth_user {
        let cloned_pool = pool.clone();
        // user should be present because a user is created for each user_oauth entry.
        let user = web::block(move || {
            let mut conn = cloned_pool
                .get()
                .expect("couldn't get db connection from pool");
            find_user_by_id(&mut conn, oauth_user.user_id)
        })
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?;
        auth_token = generate_token(user.unwrap().id, encoding_key.as_ref()).unwrap();
    } else {
        let new_oauth_user = web::block(move || {
            let mut conn = pool.get().expect("couldn't get db connection from pool");
            conn.transaction(move |mut conn| {
                let new_user =
                    insert_new_user(&mut conn, &oauth_details.name, None, OAUTH_REGISTRATION)
                        .unwrap();
                let user_details = find_user_by_username_and_registration(
                    &mut conn,
                    &new_user.username,
                    OAUTH_REGISTRATION,
                )
                .unwrap()
                .unwrap();
                insert_new_oauth_user(
                    &mut conn,
                    user_details.id,
                    &oauth_details.id,
                    GOOGLE_PROVIDER,
                )
            })
        })
        .await?
        .map_err(actix_web::error::ErrorInternalServerError)?;

        auth_token = generate_token(new_oauth_user.user_id, encoding_key.as_ref()).unwrap()
    }

    let mut response = HttpResponse::Ok();

    let cookie = Cookie::build("access_token", auth_token)
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
