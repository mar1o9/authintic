use std::sync::Arc;

use axum::Router;

use crate::{
    app::AppContext, controllers::auth::create_auth_router,
};

pub fn create_api_router(
    state: Arc<AppContext>
) -> Router<Arc<AppContext>> {
    Router::new()
        .with_state(state.clone())
        .nest("/auth", create_auth_router(state))
}
