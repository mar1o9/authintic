use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(
        &self,
        manager: &SchemaManager,
    ) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(pk_auto(Users::Id))
                    .col(uuid_uniq(Users::Pid))
                    .col(string_uniq(Users::Username))
                    .col(string(Users::Name))
                    .col(string_uniq(Users::Email))
                    .col(string(Users::Password))
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone() // Example: using timestamp with time zone
                            .not_null()
                            .extra(
                                "DEFAULT CURRENT_TIMESTAMP"
                                    .to_owned(),
                            ), // Default to current time
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null()
                            .extra(
                                "DEFAULT CURRENT_TIMESTAMP"
                                    .to_owned(),
                            ),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(
        &self,
        manager: &SchemaManager,
    ) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(
                Table::drop()
                    .table(Users::Table)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Pid,
    Username,
    Name,
    Email,
    Password,
    CreatedAt,
    UpdatedAt,
}
