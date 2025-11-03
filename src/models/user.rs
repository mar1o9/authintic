use regex::Regex;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait,
    DatabaseConnection, EntityTrait, QueryFilter,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};

use bcrypt::{DEFAULT_COST, hash};
pub use super::entities::user::{
    self, ActiveModel, Entity, Model,
};
use super::ModelError;

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterParams {
    pub email: String,
    pub password: String,
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginParams {
    pub email: String,
    pub password: String,
}

impl Model {
    // validates email string
    //
    // # Errors
    //
    // if any parsing errors occured
    pub fn validate_email_string(
        email: &str
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let re = Regex::new(
            r"\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*",
        )?;

        Ok(re.is_match(email))
    }
    // validates password string
    //
    // # Errors
    //
    // if any parsing errors occured
    pub fn validate_password_string(
        password: &str
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let is_len_ok =
            password.len() >= 8 && password.len() <= 32;
        let has_lower =
            Regex::new(r"[a-z]")?.is_match(password);
        let has_upper =
            Regex::new(r"[A-Z]")?.is_match(password);
        let has_digit =
            Regex::new(r"\d")?.is_match(password);
        let has_symbol =
            Regex::new(r"[@$!%*?&]")?.is_match(password);

        Ok(is_len_ok
            && has_lower
            && has_upper
            && has_digit
            && has_symbol)
    }

    pub fn validate_credentials(
       email: &str,
        password: &str,
    ) -> bool {
        // Check if the user sent the credentials
        let is_valid_email_string =
            match Model::validate_email_string(email) {
                Ok(is_valid) => is_valid,
                Err(_err) => return false,
            };
        let is_valid_password_string =
            match Model::validate_password_string(password)
            {
                Ok(is_valid) => is_valid,
                Err(_err) => return false,
            };
        if !is_valid_email_string {
            return false;
        }
        if !is_valid_password_string {
            return false;
        }
        is_valid_email_string && is_valid_password_string
    }

    /// finds a user by email
    ///
    /// # Errors
    ///
    /// When could not find user by the given token or DB query error
    pub async fn find_by_email(
        db: &DatabaseConnection,
        email: &str,
    ) -> Result<Self, ModelError> {
        let user = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(db)
            .await?;
        match user {
            Some(user) => return Ok(user),
            None => {
                return Err(ModelError::EntityNotFound);
            }
        }
    }

    /// Verifies whether the provided plain password matches the hashed password
    ///
    /// # Errors
    ///
    /// when could not verify password
    #[must_use]
    pub fn verify_password(
        &self,
        password: &str,
    ) -> bool {
        let Ok(is_valid) =
            bcrypt::verify(password, &self.password)
        else {
            return false;
        };
        return is_valid;
    }

    /// Asynchronously creates a user with a password and saves it to the
    /// database.
    ///
    /// # Errors
    ///
    /// When could not save the user into the DB
    pub async fn create_with_password(
        db: &DatabaseConnection,
        params: &RegisterParams,
    ) -> Result<Self, ModelError> {
        let txn = db.begin().await?;

        if user::Entity::find()
            .filter(user::Column::Email.eq(&params.email))
            .one(&txn)
            .await?
            .is_some()
        {
            return Err(ModelError::EntityAlreadyExists {});
        }

        let password_hash =
            hash(&params.password, DEFAULT_COST)
                .map_err(|e| ModelError::Any(e.into()))?;
        let user = user::ActiveModel {
            email: ActiveValue::set(
                params.email.to_string(),
            ),
            password: ActiveValue::set(password_hash),
            name: ActiveValue::set(params.name.to_string()),
            ..Default::default()
        }
        .insert(&txn)
        .await?;

        txn.commit().await?;

        Ok(user)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_email_string() {
        let email = "user@email.com";
        let is_valid_email_string =
            Model::validate_email_string(email).unwrap();
        assert_eq!(is_valid_email_string, true);
    }
    #[test]
    fn test_invalid_email_string() {
        let email = "useremailcom";
        let is_valid_email_string =
            Model::validate_email_string(email).unwrap();
        assert_eq!(is_valid_email_string, false);
    }
    #[test]
    fn test_empty_email_string() {
        let email = "";
        let is_valid_email_string =
            Model::validate_email_string(email).unwrap();
        assert_eq!(is_valid_email_string, false);
    }

    #[test]
    fn test_valid_password_string() {
        let password = "Password@1";
        let is_valid_password_string =
            match Model::validate_password_string(password) {
                Ok(is_valid) => is_valid,
                Err(err) => panic!("{}", err.to_string()),
            };
        assert_eq!(is_valid_password_string, true);
    }
    #[test]
    fn test_invalid_password_string() {
        let password = "short1";
        let is_valid_password_string =
            match Model::validate_password_string(password) {
                Ok(is_valid) => is_valid,
                Err(err) => panic!("{}", err.to_string()),
            };
        assert_eq!(is_valid_password_string, false);
    }

    #[test]
    fn test_empty_password_string() {
        let password = "";
        let is_valid_password_string =
            match Model::validate_password_string(password) {
                Ok(is_valid) => is_valid,
                Err(err) => panic!("{}", err.to_string()),
            };
        assert_eq!(is_valid_password_string, false);
    }
}
