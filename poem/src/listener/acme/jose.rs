use std::io::{Error as IoError, ErrorKind, Result as IoResult};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{jwk::Jwk, jws::Jws, Header};
use reqwest::{Client, Response};
use ring::digest::{digest, Digest, SHA256};
use serde::{de::DeserializeOwned, Serialize};

pub(crate) fn header(kid: &str, nonce: String, url: &str) -> Header {
    Header {
        alg: jsonwebtoken::Algorithm::ES256,
        kid: Some(kid.to_string()),
        url: Some(url.to_string()),
        nonce: Some(nonce),
        ..Default::default()
    }
}

pub(crate) async fn request<T>(cli: &Client, url: &str, jws: &Jws<T>) -> IoResult<Response>
where
    T: Serialize,
{
    tracing::debug!(url = %url, "http request");

    let resp = cli
        .post(url)
        .json(jws)
        .header("content-type", "application/jose+json")
        .send()
        .await
        .map_err(|err| {
            IoError::new(
                ErrorKind::Other,
                format!("failed to send http request: {err}"),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.bytes().await.map_err(|err| {
            IoError::new(
                ErrorKind::Other,
                format!("failed to read response body: {err}"),
            )
        })?;
        return Err(IoError::new(
            ErrorKind::Other,
            format!(
                "unexpected status code: status = {}\nbody: {}",
                status,
                String::from_utf8_lossy(&body)
            ),
        ));
    }
    Ok(resp)
}

pub(crate) async fn request_json<T, R>(cli: &Client, url: &str, jws: &Jws<T>) -> IoResult<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let resp = request(cli, url, jws).await?;

    let data = resp
        .text()
        .await
        .map_err(|_| IoError::new(ErrorKind::Other, "failed to read response"))?;
    serde_json::from_str(&data)
        .map_err(|err| IoError::new(ErrorKind::Other, format!("bad response: {err}")))
}

fn sha256(data: impl AsRef<[u8]>) -> Digest {
    digest(&SHA256, data.as_ref())
}

pub(crate) fn key_authorization(jwk: &Jwk, token: &str) -> IoResult<String> {
    let key_authorization = format!(
        "{}.{}",
        token,
        URL_SAFE_NO_PAD.encode(sha256(&serde_json::to_vec(&jwk)?))
    );
    Ok(key_authorization)
}

pub(crate) fn key_authorization_sha256(jwk: &Jwk, token: &str) -> IoResult<impl AsRef<[u8]>> {
    Ok(sha256(key_authorization(jwk, token)?.as_bytes()))
}
