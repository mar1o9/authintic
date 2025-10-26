use sea_orm::{
    ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, DbErr, Statement,
};
use std::time::Duration;

pub async fn open_db(
    db_url: &str,
    db_name: &str,
) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(db_url);
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Debug);
    let db = Database::connect(opt).await?;

    let db = &match db.get_database_backend() {
        DbBackend::MySql => {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                format!(
                    "CREATE DATABASE IF NOT EXISTS `{}`;",
                    db_name
                ),
            ))
            .await?;

            db
        }
        DbBackend::Postgres => {
            db.execute(Statement::from_string(
                db.get_database_backend(),
                format!(
                    "CREATE DATABASE IF NOT EXISTS `{}`;",
                    db_name
                ),
            ))
            .await?;

            db
        }
        DbBackend::Sqlite => db,
    };

    Ok(db.to_owned())
}
