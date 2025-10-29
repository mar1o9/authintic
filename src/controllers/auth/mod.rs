use std::sync::Arc;

use axum::{
    routing::{post},
    Router,
};

use crate::{
    app::AppContext,
    controllers::auth::jwt::{jwt_login, jwt_register},
};

pub mod jwt;

pub fn create_auth_router(
    state: Arc<AppContext>
) -> Router<Arc<AppContext>> {
    Router::new()
        .route("/jwt/register", post(jwt_register))
        .route("/jwt/login", post(jwt_login))
        .with_state(state)
}
