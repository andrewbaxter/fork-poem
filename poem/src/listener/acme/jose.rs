use chrono::{DateTime, NaiveDateTime, Utc};
use jsonwebtoken::{jwk::Jwk, jws::Jws, Header};
use reqwest::{header::HeaderMap, Client, Response};
use ring::digest::{digest, Digest, SHA256};
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Error as IoError, ErrorKind, Result as IoResult};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

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
    T: Serialize + std::fmt::Debug,
{
    tracing::debug!(url = %url, "http request");

    let resp = cli
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/jose+json")
        .json(jws)
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

pub(crate) enum RetryAfter {
    Relative(Duration),
    Absolute(DateTime<Utc>),
}

pub(crate) struct ResponseData<T> {
    pub(crate) location: Option<String>,
    pub(crate) retry_after: Option<RetryAfter>,
    pub(crate) data: T,
}

pub(crate) async fn request_json<T, R>(
    cli: &Client,
    url: &str,
    jws: &Jws<T>,
) -> IoResult<ResponseData<R>>
where
    T: Serialize + std::fmt::Debug,
    R: DeserializeOwned,
{
    let resp = request(cli, url, jws).await?;
    let loc = match resp.headers().get(reqwest::header::LOCATION) {
        Some(l) => Some(
            l.to_str()
                .map_err(|_| IoError::new(ErrorKind::Other, "location header not valid utf-8"))?
                .to_string(),
        ),
        None => None,
    };
    let retry_after = match resp.headers().get(reqwest::header::RETRY_AFTER) {
        Some(a) => loop {
            let a = a.to_str().map_err(|_| {
                IoError::new(ErrorKind::Other, "retry_after header not valid utf-8")
            })?;
            if let Ok(d) = u64::from_str(&a) {
                break Some(RetryAfter::Relative(Duration::from_secs(d)));
            }
            if let Ok(t) = NaiveDateTime::parse_from_str(&a, "%a, %d %b %Y %H:%M:%S GMT") {
                break Some(RetryAfter::Absolute(t.and_utc()));
            }
            return Err(IoError::new(
                ErrorKind::Other,
                "couldn't parse retry_after header as int or http date",
            ));
        },
        None => None,
    };

    let data = resp
        .text()
        .await
        .map_err(|_| IoError::new(ErrorKind::Other, "failed to read response"))?;
    Ok(ResponseData {
        location: loc,
        retry_after: retry_after,
        data: serde_json::from_str(&data)
            .map_err(|err| IoError::new(ErrorKind::Other, format!("bad response: {err}")))?,
    })
}

fn sha256(data: impl AsRef<[u8]>) -> Digest {
    digest(&SHA256, data.as_ref())
}

pub(crate) fn key_authorization(jwk: &Jwk, token: &str) -> IoResult<String> {
    let key_authorization = format!("{}.{}", token, jwk.thumbprint(&jsonwebtoken::DIGEST_SHA256));
    Ok(key_authorization)
}

pub(crate) fn key_authorization_sha256(jwk: &Jwk, token: &str) -> IoResult<impl AsRef<[u8]>> {
    Ok(sha256(key_authorization(jwk, token)?.as_bytes()))
}
