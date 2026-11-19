//! Joining a control plane (docs/api.md, Joining and credentials). Owned by the transport
//! track; the scaffold froze the signature.

use std::time::Duration;

use url::Url;

use crate::error::{Error, ErrorKind, Result};
use crate::protocol::{JoinError, JoinRequest, JoinResponse};
use crate::state::{Credentials, StateDir};

const JOIN_TIMEOUT: Duration = Duration::from_secs(60);

/// Exchanges a join token at the full join endpoint `url` for node credentials, and stores
/// them. `name` defaults to the hostname.
pub async fn join(
    url: &str,
    token: &str,
    name: Option<String>,
    state: &StateDir,
) -> Result<Credentials> {
    let url = check_url(url, "https", "http")?;
    let info = {
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            let installation_id = state.installation_id()?;
            let sandbox = crate::sandbox::probe();
            let identity = crate::identity::Identity::resolve(state.workload_user()?.as_deref())?;
            Ok::<_, Error>(crate::node_info::collect(
                &installation_id,
                name.as_deref(),
                &sandbox,
                &identity,
            ))
        })
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("node info collection failed: {err}")))??
    };
    let request = JoinRequest {
        join_token: token.to_string(),
        installation_id: info.installation_id.clone(),
        name: info.name.clone(),
        info,
    };

    let client = reqwest::Client::builder()
        .timeout(JOIN_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|err| Error::new(ErrorKind::Io, format!("cannot start HTTPS: {err}")))?;
    let response = client
        .post(url.clone())
        .json(&request)
        .send()
        .await
        .map_err(|err| {
            Error::new(
                ErrorKind::Io,
                format!("join request to {url} failed: {err}"),
            )
        })?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("join response from {url}: {err}")))?;
    if status != reqwest::StatusCode::OK {
        let reason = serde_json::from_slice::<JoinError>(&body)
            .map(|e| format!(": {}", e.error))
            .unwrap_or_default();
        return Err(match status.as_u16() {
            401 | 403 => Error::new(
                ErrorKind::PermissionDenied,
                format!("the join token is invalid, expired or spent ({status}){reason}"),
            ),
            _ => Error::new(ErrorKind::Io, format!("join failed with {status}{reason}")),
        });
    }
    let joined: JoinResponse = serde_json::from_slice(&body).map_err(|err| {
        Error::new(
            ErrorKind::Io,
            format!("bad join response from {url}: {err}"),
        )
    })?;
    check_url(&joined.endpoint, "wss", "ws")?;

    let credentials = Credentials {
        endpoint: joined.endpoint,
        node_id: joined.node_id,
        node_token: joined.node_token,
        name: request.name,
    };
    let stored = credentials.clone();
    let state = state.clone();
    tokio::task::spawn_blocking(move || state.store_credentials(&stored))
        .await
        .map_err(|err| Error::new(ErrorKind::Io, format!("storing credentials failed: {err}")))??;
    Ok(credentials)
}

/// Parses a control-plane URL: `secure` always, `plain` only to a loopback host, and never
/// with user credentials in it (api.md, Joining and credentials).
pub(crate) fn check_url(url: &str, secure: &str, plain: &str) -> Result<Url> {
    let parsed =
        Url::parse(url).map_err(|err| Error::invalid_params(format!("bad URL {url:?}: {err}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::invalid_params(format!(
            "the URL {url:?} carries credentials"
        )));
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    let scheme = parsed.scheme();
    if scheme == secure || (scheme == plain && loopback) {
        Ok(parsed)
    } else {
        Err(Error::invalid_params(format!(
            "the URL {url:?} must be {secure}:// ({plain}:// only to a loopback host)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_secure_unless_loopback() {
        for ok in [
            "https://control.example.com/api/nodes/join",
            "http://127.0.0.1:8080/join",
            "http://localhost/join",
            "http://[::1]:9/join",
        ] {
            assert!(check_url(ok, "https", "http").is_ok(), "{ok}");
        }
        assert!(check_url("wss://edge.example.com/c", "wss", "ws").is_ok());
        assert!(check_url("ws://127.0.0.2:1/c", "wss", "ws").is_ok());

        assert_eq!(
            check_url("http://control.example.com/join", "https", "http")
                .unwrap_err()
                .message,
            r#"the URL "http://control.example.com/join" must be https:// (http:// only to a loopback host)"#
        );
        assert!(check_url("ws://10.0.0.1/c", "wss", "ws").is_err());
        assert!(check_url("https://edge.example.com/c", "wss", "ws").is_err());
        assert_eq!(
            check_url("https://u:p@control.example.com/join", "https", "http")
                .unwrap_err()
                .message,
            r#"the URL "https://u:p@control.example.com/join" carries credentials"#
        );
        assert!(
            check_url("not a url", "https", "http")
                .unwrap_err()
                .message
                .starts_with(r#"bad URL "not a url""#)
        );
    }
}
