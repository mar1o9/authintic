use std::{
    env,
    sync::{Arc, LazyLock},
};

use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    Json, RequestPartsExt,
};
use axum_extra::{
    TypedHeader, headers::Authorization,
    headers::authorization::Bearer,
};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header,
    Validation, decode, encode,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    app::AppContext,
    bgworker::{Creds, Email, Job},
    models::{
        entities::user,
        user::{LoginParams, RegisterParams},
    },
};

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = env::var("JWT_SECRET").unwrap();
    Keys::new(secret.as_bytes())
});

pub async fn jwt_register(
    State(ctx): State<Arc<AppContext>>,
    Json(params): Json<RegisterParams>,
) -> Result<
    (StatusCode, Json<Value>),
    (StatusCode, AuthError),
> {
    if !user::Model::validate_credentials(
        &params.email,
        &params.password,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            AuthError::WrongCredentials,
        ));
    }
    let res =
        user::Model::create_with_password(&ctx.db, &params)
            .await;

    match res {
        Ok(_user) => {
            tracing::info!("success!");
            let Some(tx) = &ctx.tx else {
                tracing::error!("the sender is None :()");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    AuthError::UnAbleToSendMail,
                ));
            };

            match tx
                .send(Job::SendEmail {
                    email: Email {
                        from: Some("".to_string()),
                        to: _user.email,
                        reply_to: None,
                        subject: "Email Verification"
                            .to_string(),
                        html: "".to_string(),
                        ..Default::default()
                    },
                    creds: Creds {
                        user: ctx
                            .config
                            .mailer
                            .auth
                            .user
                            .clone(),
                        password: ctx
                            .config
                            .mailer
                            .auth
                            .password
                            .clone(),
                    },
                    relay: ctx.config.mailer.host.clone(),
                })
                .await
            {
                Ok(_) => tracing::info!(
                    "mail passed to bgworker"
                ),
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        AuthError::UnAbleToSendMail,
                    ));
                }
            };

            return Ok((
                StatusCode::CREATED,
                Json(json!({})),
            ));
        }
        Err(err) => {
            tracing::info!(
                message = err.to_string(),
                user_email = &params.email,
                "could not register user",
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                AuthError::ErrorCratingUser {
                    error_message: err.to_string(),
                },
            ));
        }
    };
}

pub async fn jwt_login(
    State(ctx): State<Arc<AppContext>>,
    Json(params): Json<LoginParams>,
) -> Result<(StatusCode, Json<AuthBody>), AuthError> {
    // Check credentials
    if !user::Model::validate_credentials(
        &params.email,
        &params.password,
    ) {
        return Err(AuthError::WrongCredentials);
    }

    let Ok(user) =
        user::Model::find_by_email(&ctx.db, &params.email)
            .await
    else {
        tracing::debug!(
            email = params.email,
            "login attempt with non-existent email"
        );
        return Err(AuthError::WrongCredentials);
    };

    let valid = user.verify_password(&params.password);

    if !valid {
        return Err(AuthError::UnAuthrized);
    }

    let token =
        match Claims::new(user.username, &KEYS.encoding) {
            Ok(claims) => claims,
            Err(err) => {
                tracing::error!(
                    "error: {}",
                    err.to_string()
                );
                return Err(AuthError::TokenCreation {
                    error_message: err.to_string(),
                });
            }
        };
    tracing::info!("success!");
    // Send the authorized token
    Ok((StatusCode::OK, Json(AuthBody::new(token))))
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    subj: String,
    exp: DateTime<Utc>,
    iat: DateTime<Utc>,
}

impl Claims {
    pub fn new(
        user_name: String,
        secret: &EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        // Token valid for 7 days
        let expiration = now + Duration::hours(24 * 7);

        let claims = Claims {
            subj: user_name,
            exp: expiration,
            iat: now,
        };

        let header = Header::new(Algorithm::HS256);

        let token = encode(&header, &claims, &secret)?;
        Ok(token)
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let mut validation =
            Validation::new(Algorithm::HS256);
        // Customize validation if needed, e.g., for 'iss', 'aud'
        validation.set_required_spec_claims(&[
            "exp", "subj", "iat",
        ]);
        let token_data = decode::<Claims>(
            bearer.token(),
            &KEYS.decoding,
            &validation,
        )
        .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum AuthError {
    #[error("wrong credentials")]
    WrongCredentials,
    #[error("missing credentials")]
    MissingCredentials,
    #[error("error creating token: {error_message}")]
    TokenCreation { error_message: String },
    #[error("invalid token")]
    InvalidToken,
    #[error("user already exists: {error_message}")]
    UserAlreadyExists { error_message: String },
    #[error("user dose not exists: {error_message}")]
    UserDoseNotExists { error_message: String },
    #[error("error hashing passowrd {error_message}")]
    PasswordHashError { error_message: String },
    #[error("error creating user: {error_message}")]
    ErrorCratingUser { error_message: String },
    #[error("error validating parameters {error_message}")]
    FaildToValidateParameters { error_message: String },
    #[error("invalid parameter {error_message}")]
    InvalidParam { error_message: String },
    #[error("Un authrized to accsess this account")]
    UnAuthrized,
    #[error("Un able to send mail contact support")]
    UnAbleToSendMail,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        self.to_string().into_response()
    }
}
