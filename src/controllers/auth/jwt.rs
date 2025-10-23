use std::sync::Arc;

use std::sync::LazyLock;

use axum::{
    Json, RequestPartsExt, extract::FromRequestParts, extract::State,
    http::StatusCode, http::request::Parts, response::IntoResponse,
};
use axum_extra::{
    TypedHeader, headers::Authorization, headers::authorization::Bearer,
};
use bcrypt::{DEFAULT_COST, hash};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, entities::users};

static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    Keys::new(secret.as_bytes())
});

#[derive(Debug, Deserialize, Serialize)]
pub struct JwtRegisterParams {
    pub email: String,
    pub username: String,
    pub password: String,
    pub name: String,
}

pub async fn jwt_register(
    State(state): State<Arc<AppState>>,
    Json(params): Json<JwtRegisterParams>,
) -> Result<Json<AuthBody>, AuthError> {
    // Check if the user sent the credentials
    if params.email.is_empty() || params.password.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    let user = users::Entity::find()
        .filter(users::Column::Email.eq(&params.email))
        .filter(users::Column::Username.eq(&params.username))
        .one(&state.db)
        .await
        .expect("error quering db");
    if user.is_some() {
        return Err(AuthError::UserAlreadyExists);
    }

    let pass_hash = match hash(params.password, DEFAULT_COST) {
        Ok(pass) => pass,
        Err(err) => {
            return Err(AuthError::PasswordHashError {
                error_message: err.to_string(),
            });
        }
    };

    let user_uuid = Uuid::new_v4();

    let user = users::ActiveModel {
        pid: Set(user_uuid),
        username: Set(params.username),
        name: Set(params.name),
        email: Set(params.email),
        password: Set(pass_hash),
        ..Default::default()
    }
    .insert(&state.db)
    .await;
    let user = match user {
        Ok(user) => user,
        Err(err) => {
            return Err(AuthError::ErrorCratingUser {
                error_message: err.to_string(),
            });
        }
    };

    let token = match Claims::new(user.pid.to_string(), &KEYS.encoding) {
        Ok(claims) => claims,
        Err(err) => {
            return Err(AuthError::TokenCreation {
                error_message: err.to_string(),
            });
        }
    };

    // Send the authorized token
    Ok(Json(AuthBody::new(token)))
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
        let mut validation = Validation::new(Algorithm::RS256);
        // Customize validation if needed, e.g., for 'iss', 'aud'
        validation.set_required_spec_claims(&["exp", "subj", "iat"]);
        let token_data =
            decode::<Claims>(bearer.token(), &KEYS.decoding, &validation)
                .map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }
}

impl Claims {
    pub fn new(
        pid: String,
        secret: &EncodingKey,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        // Token valid for 7 days
        let expiration = now + Duration::hours(24 * 7);

        let claims = Claims {
            subj: pid,
            exp: expiration,
            iat: now,
        };

        let header = Header::new(Algorithm::RS256);

        let token = encode(&header, &claims, &secret)?;
        Ok(token)
    }
}

pub fn validate_token(
    token: &str,
    secret: &[u8],
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(secret);
    let mut validation = Validation::new(Algorithm::RS256);
    // Customize validation if needed, e.g., for 'iss', 'aud'
    validation.set_required_spec_claims(&["exp", "subj", "iat"]);

    let token_data = decode::<Claims>(token, &decoding_key, &validation)?;
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
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("error hashing passowrd {error_message}")]
    PasswordHashError { error_message: String },
    #[error("error creating user: {error_message}")]
    ErrorCratingUser { error_message: String },
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
            AuthError::TokenCreation { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AuthError::InvalidToken => {
                (StatusCode::UNAUTHORIZED, self.to_string())
            }
            AuthError::UserAlreadyExists => {
                (StatusCode::CONFLICT, self.to_string())
            }
            AuthError::PasswordHashError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            AuthError::ErrorCratingUser { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}
