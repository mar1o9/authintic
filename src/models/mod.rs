pub mod entities;
pub mod user;

#[derive(thiserror::Error, Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum ModelError {
    #[error("Entity already exists")]
    EntityAlreadyExists,

    #[error("Entity not found")]
    EntityNotFound,

    #[error("jwt error")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error(transparent)]
    DbErr(#[from] sea_orm::DbErr),

    #[error(transparent)]
    Any(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("{0}")]
    Message(String),
}
