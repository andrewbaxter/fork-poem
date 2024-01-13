use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::EncodingKey;
use reqwest::Client;
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};

use super::{listener::ChallengeTypeParameters, ACME_KEY_ALG};
use crate::listener::acme::{
    jose::{self, header},
    protocol::{
        CsrRequest, Directory, FetchAuthorizationResponse, Identifier, NewOrderRequest,
        NewOrderResponse,
    },
};
/// The result of [`issue_cert`] function.

/// A client for ACME-supporting TLS certificate services.
pub struct AcmeClient {
    pub(crate) client: Client,
    pub(crate) directory: Directory,
    pub(crate) key_pair: EncodingKey,
    pub(crate) contacts: Vec<String>,
}

impl AcmeClient {
    /// Create a new client. `directory_url` is the url for the ACME provider. `contacts` is a list
    /// of URLS (ex: `mailto:`) the ACME service can use to reach you if there's issues with your certificates.
    pub async fn try_new(directory_url: &str, contacts: Vec<String>) -> IoResult<Self> {
        let client = Client::new();
        let directory = get_directory(&client, directory_url).await?;
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::generate_pkcs8(ACME_KEY_ALG, &rng)
            .map_err(|_| IoError::new(ErrorKind::Other, "failed to generate acme key pair"))?;
        Ok(Self {
            client,
            directory,
            key_pair: EncodingKey::from_ec_der(key_pair.as_ref()),
            contacts,
        })
    }

    /// Similar to `try_new` but uses a provided key instead of generating a new one.
    pub async fn try_new_with_key(
        directory_url: &str,
        contacts: Vec<String>,
        key: EncodingKey,
    ) -> IoResult<Self> {
        let client = Client::new();
        let directory = get_directory(&client, directory_url).await?;
        Ok(Self {
            client,
            directory,
            key_pair: key,
            contacts,
        })
    }
    pub(crate) async fn new_order<T: AsRef<str>>(
        &mut self,
        domains: &[T],
        kid: &str,
    ) -> IoResult<NewOrderResponse> {
        tracing::debug!(kid = kid, "new order request");

        let nonce = get_nonce(&self.client, &self.directory).await?;
        let resp: NewOrderResponse = jose::request_json(
            &self.client,
            &self.directory.new_order,
            &jsonwebtoken::encode_jws(
                &header(kid, nonce, &self.directory.new_order),
                Some(&NewOrderRequest {
                    identifiers: domains
                        .iter()
                        .map(|domain| Identifier {
                            ty: "dns".to_string(),
                            value: domain.as_ref().to_string(),
                        })
                        .collect(),
                }),
                &self.key_pair,
            )
            .map_err(|err| {
                IoError::new(ErrorKind::Other, format!("failed to encode payload: {err}"))
            })?,
        )
        .await?;

        tracing::debug!(status = resp.status.as_str(), "order created");
        Ok(resp)
    }

    pub(crate) async fn fetch_authorization(
        &self,
        auth_url: &str,
        kid: &str,
    ) -> IoResult<FetchAuthorizationResponse> {
        tracing::debug!(auth_uri = %auth_url, "fetch authorization");

        let nonce = get_nonce(&self.client, &self.directory).await?;
        let resp: FetchAuthorizationResponse = jose::request_json(
            &self.client,
            auth_url,
            &jsonwebtoken::encode_jws(&header(kid, nonce, auth_url), None::<&()>, &self.key_pair)
                .map_err(|err| {
                IoError::new(ErrorKind::Other, format!("failed to encode payload: {err}"))
            })?,
        )
        .await?;

        tracing::debug!(
            identifier = ?resp.identifier,
            status = resp.status.as_str(),
            "authorization response",
        );

        Ok(resp)
    }

    pub(crate) async fn trigger_challenge(
        &self,
        domain: &str,
        challenge_type: &ChallengeTypeParameters<'_>,
        url: &str,
        kid: &str,
    ) -> IoResult<()> {
        tracing::debug!(
            auth_uri = %url,
            domain = domain,
            challenge_type = %challenge_type,
            "trigger challenge",
        );

        let nonce = get_nonce(&self.client, &self.directory).await?;
        jose::request(
            &self.client,
            url,
            &jsonwebtoken::encode_jws(
                &header(kid, nonce, url),
                Some(&serde_json::json!({})),
                &self.key_pair,
            )
            .map_err(|err| {
                IoError::new(ErrorKind::Other, format!("failed to encode payload: {err}"))
            })?,
        )
        .await?;

        Ok(())
    }

    pub(crate) async fn send_csr(
        &self,
        url: &str,
        kid: &str,
        csr: &[u8],
    ) -> IoResult<NewOrderResponse> {
        tracing::debug!(url = %url, "send certificate request");

        let nonce = get_nonce(&self.client, &self.directory).await?;
        jose::request_json(
            &self.client,
            url,
            &jsonwebtoken::encode_jws(
                &header(kid, nonce, url),
                Some(&CsrRequest {
                    csr: URL_SAFE_NO_PAD.encode(csr),
                }),
                &self.key_pair,
            )
            .map_err(|err| {
                IoError::new(ErrorKind::Other, format!("failed to encode payload: {err}"))
            })?,
        )
        .await
    }

    pub(crate) async fn obtain_certificate(&self, url: &str, kid: &str) -> IoResult<Vec<u8>> {
        tracing::debug!(url = %url, "send certificate request");

        let nonce = get_nonce(&self.client, &self.directory).await?;
        let resp = jose::request(
            &self.client,
            url,
            &jsonwebtoken::encode_jws(&header(kid, nonce, url), None::<&()>, &self.key_pair)
                .map_err(|err| {
                    IoError::new(ErrorKind::Other, format!("failed to encode payload: {err}"))
                })?,
        )
        .await?;

        Ok(resp
            .bytes()
            .await
            .map_err(|err| {
                IoError::new(
                    ErrorKind::Other,
                    format!("failed to download certificate: {err}"),
                )
            })?
            .to_vec())
    }
}

async fn get_directory(client: &Client, directory_url: &str) -> IoResult<Directory> {
    tracing::debug!("loading directory");

    let resp = client.get(directory_url).send().await.map_err(|err| {
        IoError::new(ErrorKind::Other, format!("failed to load directory: {err}"))
    })?;

    if !resp.status().is_success() {
        return Err(IoError::new(
            ErrorKind::Other,
            format!("failed to load directory: status = {}", resp.status()),
        ));
    }

    let directory = resp.json::<Directory>().await.map_err(|err| {
        IoError::new(ErrorKind::Other, format!("failed to load directory: {err}"))
    })?;

    tracing::debug!(
        new_nonce = ?directory.new_nonce,
        new_account = ?directory.new_account,
        new_order = ?directory.new_order,
        "directory loaded",
    );
    Ok(directory)
}

pub(crate) async fn get_nonce(client: &Client, directory: &Directory) -> IoResult<String> {
    tracing::debug!("creating nonce");

    let resp = client
        .get(&directory.new_nonce)
        .send()
        .await
        .map_err(|err| IoError::new(ErrorKind::Other, format!("failed to get nonce: {err}")))?;

    if !resp.status().is_success() {
        return Err(IoError::new(
            ErrorKind::Other,
            format!("failed to load directory: status = {}", resp.status()),
        ));
    }

    let nonce = resp
        .headers()
        .get("replay-nonce")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_default();

    tracing::debug!(nonce = nonce.as_str(), "nonce created");
    Ok(nonce)
}
