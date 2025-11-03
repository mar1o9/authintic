use std::error;
use std::str::FromStr;

use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Serialize, Deserialize};
use serde_variant::to_variant_name;
use tokio::sync::mpsc;
use tokio::task;

/// The structure representing an email details.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Email {
    /// Mailbox to `From` header
    pub from: Option<String>,
    /// Mailbox to `To` header
    pub to: String,
    /// Mailbox to `ReplyTo` header
    pub reply_to: Option<String>,
    /// Subject header to message
    pub subject: String,
    /// Plain text message
    pub text: String,
    /// HTML template
    pub html: String,
    /// BCC header to message
    pub bcc: Option<String>,
    /// CC header to message
    pub cc: Option<String>,
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq
)]
pub enum JobStatus {
    #[serde(rename = "queued")]
    Queued,
    #[serde(rename = "processing")]
    Processing,
    #[serde(rename = "completed")]
    Completed,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "cancelled")]
    Cancelled,
}

impl std::str::FromStr for JobStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(Self::Queued),
            "processing" => Ok(Self::Processing),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("Invalid status: {s}")),
        }
    }
}

impl std::fmt::Display for JobStatus {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        to_variant_name(self)
            .expect("only enum supported")
            .fmt(f)
    }
}

#[derive(Debug)]
pub struct Creds {
    pub user: String,
    pub password: String,
}

#[derive(Debug)]
pub enum Job {
    SendEmail {
        email: Email,
        creds: Creds,
        relay: String,
    },
}

fn send_email(
    email: Email,
    creds: Creds,
    relay: String,
) -> Result<(), Box<dyn error::Error>> {
    let Some(from) = email.from else {
        return Err("empty source email"
            .to_string()
            .into());
    };
    let msg = Message::builder()
        .from(Mailbox::from_str(&from)?)
        .to(email.to.parse().unwrap())
        .subject(email.subject)
        .header(ContentType::TEXT_HTML)
        .body(email.html)?;

    let creds =
        Credentials::new(creds.user, creds.password);

    // Open a remote connection to gmail
    let mailer: SmtpTransport =
        SmtpTransport::relay(&relay)?
            .credentials(creds)
            .build();
    mailer.send(&msg)?;

    Ok(())
}

/// Worker manager that runs jobs in background
pub async fn worker_manager(mut rx: mpsc::Receiver<Job>) {
    while let Some(job) = rx.recv().await {
        // Spawn each job in its own task for parallelism
        task::spawn(async move {
            match job {
                Job::SendEmail {
                    email,
                    creds,
                    relay,
                } => {
                    tracing::info!("Sending Email");
                    match send_email(email, creds, relay) {
                        Ok(_) => tracing::info!(
                            "email sent successfuly"
                        ),
                        Err(err) => {
                            tracing::error!(err);
                        }
                    };
                }
            }
        });
    }
}
