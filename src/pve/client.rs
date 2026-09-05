//! HTTP handler for the Proxmox VE REST API.
//!
//! One surface, unlike the UniFi side of the house: everything lives under
//! `https://<host>:8006/api2/json`, every response is a `{"data": …}` wrapper,
//! and nothing paginates. A request for another node's path is forwarded by
//! `pveproxy` to the node that owns it, so one endpoint covers a cluster.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::pve::config::Profile;

/// Cap on a response body, so a misbehaving node cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 32 << 20;

/// A non-2xx response from the API.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub message: String,
    /// Per-parameter complaints, which is how PVE reports a bad request.
    pub errors: Vec<String>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API error {}", self.status.as_u16())?;
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        for e in &self.errors {
            write!(f, "\n  {e}")?;
        }
        match self.status {
            StatusCode::UNAUTHORIZED => write!(
                f,
                "\nhint: check the token id (user@realm!name) and its secret"
            )?,
            StatusCode::FORBIDDEN => write!(
                f,
                "\nhint: the token authenticated but lacks a privilege here; run `mlab-proxmox whoami`"
            )?,
            _ => {}
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A configured connection to one Proxmox VE cluster.
pub struct Client {
    http: reqwest::Client,
    base: String,
    insecure: bool,
}

impl Client {
    /// Build a client from a validated profile.
    pub fn new(profile: &Profile, timeout: Duration) -> Result<Self> {
        profile.validate()?;
        let base = format!("https://{}/api2/json", profile.endpoint()?);

        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!(
            "PVEAPIToken={}={}",
            profile.token_id.trim(),
            profile.token_secret.trim()
        ))
        .context("the token contains characters that cannot go in a header")?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .danger_accept_invalid_certs(profile.insecure())
            // The token rides in a default header, which reqwest would replay
            // on a cross-host redirect; refuse to follow one instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the HTTP client")?;

        Ok(Client {
            http,
            base,
            insecure: profile.insecure(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn insecure(&self) -> bool {
        self.insecure
    }

    /// One GET, unwrapped.
    pub async fn get(&self, path: &str) -> Result<Value> {
        self.request(Method::GET, path, &[], None).await
    }

    /// One GET whose result is expected to be a list.
    pub async fn list(&self, path: &str) -> Result<Vec<Value>> {
        let v = self.get(path).await?;
        match v {
            Value::Array(rows) => Ok(rows),
            Value::Null => Ok(Vec::new()),
            other => Ok(vec![other]),
        }
    }

    /// The core handler: one request, the `data` member of one parsed body.
    ///
    /// `path` is relative to `/api2/json` and starts with `/`; it is sent as
    /// given, so callers escape their own segments with [`esc`].
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let build = || {
            let mut r = self.http.request(method.clone(), &url);
            if !query.is_empty() {
                r = r.query(query);
            }
            if let Some(b) = body {
                r = r.header(CONTENT_TYPE, "application/json").json(b);
            }
            r
        };

        // A pveproxy worker can close a pooled connection between two calls, and
        // a collection of sixty reads should not lose a whole section to that.
        // One retry, only for reads, only for a transport failure that is
        // neither a timeout nor a refused connection.
        let first = build().send().await;
        let resp = match first {
            Err(ref e) if method == Method::GET && !e.is_timeout() && !e.is_connect() => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                build().send().await
            }
            other => other,
        };

        let resp = resp.map_err(|e| {
            // reqwest hides the interesting part (certificate, DNS, refused)
            // in the source chain, so flatten it before adding a hint.
            let cause = error_chain(&e);
            let mut msg = format!("{method} {url}: {cause}");
            let lower = cause.to_lowercase();
            if lower.contains("certificate") || lower.contains("unknownissuer") {
                msg.push_str(
                    "\nhint: Proxmox serves a certificate from its own CA; drop --secure, or pass --insecure",
                );
            } else if e.is_timeout() {
                msg.push_str("\nhint: raise --timeout");
            } else if e.is_connect() {
                msg.push_str(
                    "\nhint: is the node reachable on this port? The API and the GUI both listen on 8006",
                );
            }
            anyhow!(msg)
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(anyhow!(
                "{method} {url} redirected to {to}; not following it, the token would leak to the new host"
            ));
        }

        let bytes = resp
            .bytes()
            .await
            .with_context(|| format!("reading the body of {method} {url}"))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!(
                "{method} {url}: response is {} bytes, over the {MAX_RESPONSE_BYTES} cap",
                bytes.len()
            ));
        }
        let text = String::from_utf8_lossy(&bytes).to_string();

        if !status.is_success() {
            return Err(api_error(status, &text).into());
        }

        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        let v: Value = serde_json::from_str(&text)
            .with_context(|| format!("{method} {url}: the response is not JSON"))?;
        // Everything the API returns is wrapped; a bare body means a proxy
        // answered instead of pveproxy, which is worth surfacing as-is.
        Ok(match v {
            Value::Object(mut o) if o.contains_key("data") => {
                o.remove("data").unwrap_or(Value::Null)
            }
            other => other,
        })
    }
}

/// Turn a failed response into a typed error. PVE puts the human sentence in
/// the HTTP reason line and the per-field complaints in an `errors` object.
fn api_error(status: StatusCode, body: &str) -> ApiError {
    let mut message = String::new();
    let mut errors = Vec::new();

    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(m) = v.get("message").and_then(Value::as_str) {
            message = m.trim().to_string();
        }
        if let Some(map) = v.get("errors").and_then(Value::as_object) {
            for (k, val) in map {
                let text = val.as_str().unwrap_or_default().trim();
                errors.push(format!("{k}: {text}"));
            }
        }
    }
    if message.is_empty() {
        // Not JSON, or JSON without a message: keep a short slice of the body
        // rather than dropping the only explanation there is.
        message = body.trim().chars().take(200).collect();
    }
    ApiError {
        status,
        message,
        errors,
    }
}

/// Percent-encode one path segment. Guest names, storage ids and node names
/// are user-chosen and reach the URL.
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Flatten a reqwest error and its causes into one line.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        let text = s.to_string();
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        src = s.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_segments_are_escaped() {
        assert_eq!(esc("pve-node1"), "pve-node1");
        assert_eq!(esc("local-lvm"), "local-lvm");
        assert_eq!(esc("a b/c"), "a%20b%2Fc");
        assert_eq!(esc("root@pam!mlab"), "root%40pam%21mlab");
    }

    #[test]
    fn a_parameter_failure_keeps_every_field_complaint() {
        let e = api_error(
            StatusCode::BAD_REQUEST,
            r#"{"data":null,"errors":{"vmid":"invalid format"},"message":"Parameter verification failed."}"#,
        );
        assert_eq!(e.message, "Parameter verification failed.");
        assert_eq!(e.errors, vec!["vmid: invalid format"]);
    }

    #[test]
    fn a_non_json_failure_still_says_something() {
        let e = api_error(StatusCode::BAD_GATEWAY, "<html>bad gateway</html>");
        assert!(e.message.contains("bad gateway"));
    }
}
