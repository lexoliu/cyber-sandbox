use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::{error::CredentialError, file::MAX_BYTES};

/// One bearer token, as the host is currently prepared to lend it.
///
/// This is the whole of what crosses into a session: a token that is already limited in
/// time by whoever issued it, and the moment it stops being accepted. What is *not* here
/// is the credential the host could mint more tokens with, and its absence is the point —
/// a struct with nowhere to put a refresh token cannot carry one by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bearer {
    /// The token itself.
    pub token: String,
    /// When it stops being accepted, if the issuer said so.
    #[serde(with = "jiff::fmt::serde::timestamp::millisecond::optional")]
    pub expires_at: Option<Timestamp>,
}

impl Bearer {
    /// Sends the token over a connection that carries exactly one of them.
    ///
    /// The message is the whole connection rather than a line within it: the host has one
    /// thing to say, and closing after saying it is what tells the other end it has heard
    /// all of it.
    ///
    /// # Errors
    /// Fails when the token cannot be encoded or the connection fails.
    pub async fn send<W>(&self, mut sink: W) -> Result<(), CredentialError>
    where
        W: AsyncWrite + Unpin,
    {
        let encoded = serde_json::to_vec(self).map_err(CredentialError::Encode)?;
        sink.write_all(&encoded)
            .await
            .map_err(CredentialError::Stream)?;
        sink.shutdown().await.map_err(CredentialError::Stream)
    }

    /// Receives a token from such a connection.
    ///
    /// # Errors
    /// Fails when the connection fails or what arrives is not a token.
    pub async fn receive<R>(source: R) -> Result<Self, CredentialError>
    where
        R: AsyncRead + Unpin,
    {
        let mut encoded = Vec::new();
        // Bounded because a reader that keeps reading until the other end feels like
        // stopping is a reader the other end decides the memory footprint of.
        source
            .take(MAX_BYTES as u64)
            .read_to_end(&mut encoded)
            .await
            .map_err(CredentialError::Stream)?;
        serde_json::from_slice(&encoded).map_err(CredentialError::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer() -> Bearer {
        Bearer {
            token: "sk-ant-oat01-example".to_owned(),
            expires_at: Some(Timestamp::from_millisecond(1_788_000_000_000).unwrap()),
        }
    }

    #[tokio::test]
    async fn a_token_survives_the_trip() {
        let mut wire = Vec::new();
        bearer().send(&mut wire).await.unwrap();

        assert_eq!(Bearer::receive(wire.as_slice()).await.unwrap(), bearer());
    }

    #[tokio::test]
    async fn an_expiry_crosses_as_the_milliseconds_both_ends_count_in() {
        let mut wire = Vec::new();
        bearer().send(&mut wire).await.unwrap();

        let sent: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert_eq!(
            sent["expiresAt"],
            serde_json::json!(1_788_000_000_000_i64),
            "an expiry that crosses as a formatted date is one the reader compares \
             against a number and never finds expired"
        );
    }

    #[tokio::test]
    async fn a_token_that_never_expires_is_told_apart_from_one_that_expired_at_zero() {
        let forever = Bearer {
            token: "sk-ant-oat01-example".to_owned(),
            expires_at: None,
        };
        let mut wire = Vec::new();
        forever.send(&mut wire).await.unwrap();

        assert_eq!(Bearer::receive(wire.as_slice()).await.unwrap(), forever);
    }
}
