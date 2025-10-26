use std::{
    env,
    sync::{Arc, LazyLock},
};

use axum::{
    Json, RequestPartsExt, extract::FromRequestParts,
    extract::State, http::StatusCode, http::request::Parts,
    response::IntoResponse,
};
use axum_extra::{
    TypedHeader, headers::Authorization,
    headers::authorization::Bearer,
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header,
    Validation, decode, encode,
};
use regex::Regex;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait,
    EntityTrait, QueryFilter,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{AppState, entities::user};

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = env::var("JWT_SECRET").unwrap();
    Keys::new(secret.as_bytes())
});

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

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtAuthParams {
    pub email: String,
    pub username: String,
    pub password: String,
}

impl JwtAuthParams {
    fn validate_email_string(
        &self
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let re = Regex::new(
            r"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*",
        )?;

        Ok(re.is_match(&self.email))
    }
    fn validate_password_string(
        &self
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let is_len_ok = self.password.len() >= 8
            && self.password.len() <= 32;
        let has_lower =
            Regex::new(r"[a-z]")?.is_match(&self.password);
        let has_upper =
            Regex::new(r"[A-Z]")?.is_match(&self.password);
        let has_digit =
            Regex::new(r"\d")?.is_match(&self.password);
        let has_symbol = Regex::new(r"[@$!%*?&]")?
            .is_match(&self.password);

        Ok(is_len_ok
            && has_lower
            && has_upper
            && has_digit
            && has_symbol)
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

pub fn validate_token(
    token: &str,
    secret: &[u8],
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::RS256);
    // Customize validation if needed, e.g., for 'iss', 'aud'
    validation
        .set_required_spec_claims(&["exp", "subj", "iat"]);

    let token_data = decode::<Claims>(
        token,
        &decoding_key,
        &validation,
    )?;
    Ok(token_data.claims)
}
#[derive(Debug, thiserror::Error)]
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
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AuthError::MissingCredentials => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AuthError::TokenCreation { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
            ),
            AuthError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AuthError::UserAlreadyExists { .. } => {
                (StatusCode::CONFLICT, self.to_string())
            }
            AuthError::PasswordHashError { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
            ),
            AuthError::ErrorCratingUser { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
            ),
            AuthError::FaildToValidateParameters {
                ..
            } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                self.to_string(),
            ),
            AuthError::InvalidParam { .. } => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            AuthError::UserDoseNotExists { .. } => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

pub async fn jwt_register(
    State(state): State<Arc<AppState>>,
    Json(params): Json<JwtAuthParams>,
) -> Result<(StatusCode, Json<AuthBody>), AuthError> {
    // Check if the user sent the credentials
    let is_valid_email_string =
        match params.validate_email_string() {
            Ok(is_valid) => is_valid,
            Err(err) => {
                return Err(
                    AuthError::FaildToValidateParameters {
                        error_message: err.to_string(),
                    },
                );
            }
        };
    let is_valid_password_string =
        match params.validate_password_string() {
            Ok(is_valid) => is_valid,
            Err(err) => {
                return Err(
                    AuthError::FaildToValidateParameters {
                        error_message: err.to_string(),
                    },
                );
            }
        };
    if !is_valid_email_string {
        return Err(AuthError::InvalidParam {
            error_message: "Invalid email format"
                .to_string(),
        });
    }
    if !is_valid_password_string {
        return Err(AuthError::InvalidParam {
            error_message: "Invalid password format"
                .to_string(),
        });
    }
    // check if a user with the same email or username exists
    let user = user::Entity::find()
        .filter(user::Column::Email.eq(&params.email))
        .filter(user::Column::Username.eq(&params.username))
        .one(&state.db)
        .await
        .expect("faild querying the database");
    match user {
        Some(user) => {
            if user.username == params.username {
                return Err(AuthError::UserAlreadyExists {
                           error_message:
                               "user with this username already exists"
                                   .to_string(),
                       });
            } else if user.email == params.email {
                return Err(AuthError::UserAlreadyExists {
                           error_message:
                               "user with this email already exists"
                                   .to_string(),
                       });
            }
        }
        None => {}
    }

    let pass_hash =
        match hash(params.password, DEFAULT_COST) {
            Ok(pass) => pass,
            Err(err) => {
                return Err(AuthError::PasswordHashError {
                    error_message: err.to_string(),
                });
            }
        };

    let user = user::ActiveModel {
        username: Set(params.username),
        email: Set(params.email),
        password: Set(pass_hash),
        ..Default::default()
    }
    .insert(&state.db)
    .await;
    let user = match user {
        Ok(user) => user,
        Err(err) => {
            tracing::error!("error: {}", err.to_string());
            return Err(AuthError::ErrorCratingUser {
                error_message: err.to_string(),
            });
        }
    };

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
    Ok((StatusCode::CREATED, Json(AuthBody::new(token))))
}

pub async fn jwt_login(
    State(state): State<Arc<AppState>>,
    Json(params): Json<JwtAuthParams>,
) -> Result<(StatusCode, Json<AuthBody>), AuthError> {
    // Check credentials
    let is_valid_email_string =
        match params.validate_email_string() {
            Ok(is_valid) => is_valid,
            Err(err) => {
                return Err(
                    AuthError::FaildToValidateParameters {
                        error_message: err.to_string(),
                    },
                );
            }
        };
    let is_valid_password_string =
        match params.validate_password_string() {
            Ok(is_valid) => is_valid,
            Err(err) => {
                return Err(
                    AuthError::FaildToValidateParameters {
                        error_message: err.to_string(),
                    },
                );
            }
        };
    if !is_valid_email_string {
        return Err(AuthError::InvalidParam {
            error_message: "Invalid email format"
                .to_string(),
        });
    }
    if !is_valid_password_string {
        return Err(AuthError::InvalidParam {
            error_message: "Invalid password format"
                .to_string(),
        });
    }

    // check if a user with the same email or username exists
    let user = user::Entity::find()
        .filter(user::Column::Email.eq(&params.email))
        .filter(user::Column::Username.eq(&params.username))
        .one(&state.db)
        .await
        .expect("faild querying the database");
    let user = match user {
        Some(user) => user,
        None => {
            return Err(AuthError::UserDoseNotExists {
                error_message: "couldn't find this user"
                    .to_string(),
            });
        }
    };

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
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_email_string() {
        let params = JwtAuthParams {
            email: "user@email.com".to_string(),
            username: "user_name".to_string(),
            password: "Password@1".to_string(),
        };
        let is_valid_email_string =
            params.validate_email_string().unwrap();
        assert_eq!(is_valid_email_string, true);
    }
    #[test]
    fn test_invalid_email_string() {
        let params = JwtAuthParams {
            email: "useremailcom".to_string(),
            username: "user_name".to_string(),
            password: "Password@1".to_string(),
        };
        let is_valid_email_string =
            params.validate_email_string().unwrap();
        assert_eq!(is_valid_email_string, false);
    }

    #[test]
    fn test_valid_password_string() {
        let params = JwtAuthParams {
            email: "user@email.com".to_string(),
            username: "user_name".to_string(),
            password: "Password@1".to_string(),
        };
        let is_valid_password_string =
            match params.validate_password_string() {
                Ok(is_valid) => is_valid,
                Err(err) => panic!("{}", err.to_string()),
            };
        assert_eq!(is_valid_password_string, true);
    }
    #[test]
    fn test_invalid_password_string() {
        let params = JwtAuthParams {
            email: "user@email.com".to_string(),
            username: "user_name".to_string(),
            password: "short1".to_string(),
        };
        let is_valid_password_string =
            match params.validate_password_string() {
                Ok(is_valid) => is_valid,
                Err(err) => panic!("{}", err.to_string()),
            };
        assert_eq!(is_valid_password_string, false);
    }
}
