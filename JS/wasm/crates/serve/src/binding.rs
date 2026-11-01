use super::http_types::{Headers, HttpError, Method, Response};
use async_trait::async_trait;
use http::HeaderMap;
use reqwest::Url;

use jrsonnet_evaluator::{
    function::TlaArg, gc::GcHashMap, manifest::ManifestFormat, trace::TraceFormat, State,
};
use jrsonnet_parser::IStr;

use std::{
    env, fs, io,
    net::IpAddr,
    path::{Path, PathBuf},
};
use tracing::error;

/// Validates and canonicalizes a guest-provided file path so that it remains strictly
/// within the configured WASM sandbox directory (`EDGECHAINS_SANDBOX_DIR` or current working directory).
pub fn validate_sandbox_file_path(raw_path: &str) -> io::Result<PathBuf> {
    if raw_path.trim().is_empty() || raw_path.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid or empty file path",
        ));
    }

    let sandbox_base = env::var("EDGECHAINS_SANDBOX_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let canonical_root = sandbox_base.canonicalize()?;
    let candidate = if Path::new(raw_path).is_absolute() {
        PathBuf::from(raw_path)
    } else {
        canonical_root.join(raw_path)
    };

    let canonical_target = candidate.canonicalize()?;
    if !canonical_target.starts_with(&canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Path traversal outside WASM sandbox root is not permitted",
        ));
    }

    Ok(canonical_target)
}

/// Checks whether an IP address belongs to loopback, link-local / cloud metadata (169.254.0.0/16),
/// RFC1918 private, or unspecified ranges.
pub fn is_restricted_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Validates outbound HTTP URLs from WASM guests to prevent Server-Side Request Forgery (SSRF)
/// against cloud metadata services (169.254.169.254) and internal loopback/private networks.
pub fn validate_outbound_url(url: &Url) -> Result<(), HttpError> {
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(HttpError::InvalidUrl);
    }

    if env::var("EDGECHAINS_ALLOW_PRIVATE_NETWORK").as_deref() == Ok("1") {
        return Ok(());
    }

    let host_str = url.host_str().ok_or(HttpError::InvalidUrl)?;
    let lower_host = host_str.trim_end_matches('.').to_ascii_lowercase();

    if lower_host == "localhost"
        || lower_host.ends_with(".localhost")
        || lower_host.ends_with(".local")
        || lower_host.ends_with(".internal")
        || lower_host == "metadata.google.internal"
    {
        return Err(HttpError::RequestError);
    }

    let clean_ip_candidate = lower_host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean_ip_candidate.parse::<IpAddr>() {
        if is_restricted_ip(&ip) {
            return Err(HttpError::RequestError);
        }
    }

    Ok(())
}

#[async_trait]
impl super::utils::Host for super::Host {
    async fn read_file(&mut self, path: String) -> wasmtime::Result<String> {
        let safe_path = validate_sandbox_file_path(&path).map_err(|e| {
            error!("Rejected unsafe or invalid file read {}: {}", path, e);
            e
        })?;
        let code = fs::read_to_string(&safe_path).map_err(|e| {
            error!("Failed to read file {:?}: {}", safe_path, e);
            io::Error::new(io::ErrorKind::Other, e)
        })?;
        Ok(code)
    }
}

#[async_trait]
impl super::outbound_http::Host for super::Host {
    async fn send_request(
        &mut self,
        req: super::http_types::Request,
    ) -> wasmtime::Result<Result<super::http_types::Response, super::http_types::HttpError>> {
        Ok(async {
            tracing::log::trace!("Attempting to send outbound HTTP request to {}", req.uri);

            let method = method_from(req.method);
            let url = Url::parse(&req.uri).map_err(|_| HttpError::InvalidUrl)?;
            validate_outbound_url(&url)?;
            let headers = request_headers(req.headers).map_err(|_| HttpError::RuntimeError)?;
            let body = req.body.unwrap_or_default().to_vec();

            if !req.params.is_empty() {
                tracing::log::warn!("HTTP params field is deprecated");
            }

            let client = self.client.get_or_insert_with(Default::default);

            let resp = client
                .request(method, url)
                .headers(headers)
                .body(body)
                .send()
                .await
                .map_err(log_reqwest_error)?;
            tracing::log::trace!("Returning response from outbound request to {}", req.uri);
            response_from_reqwest(resp).await
        }
        .await)
    }
}

pub fn log_reqwest_error(err: reqwest::Error) -> HttpError {
    let error_desc = if err.is_timeout() {
        "timeout error"
    } else if err.is_connect() {
        "connection error"
    } else if err.is_body() || err.is_decode() {
        "message body error"
    } else if err.is_request() {
        "request error"
    } else {
        "error"
    };
    tracing::warn!(
        "Outbound HTTP {}: URL {}, error detail {:?}",
        error_desc,
        err.url()
            .map(|u| u.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned()),
        err
    );
    HttpError::RuntimeError
}

pub fn method_from(m: Method) -> http::Method {
    match m {
        Method::Get => http::Method::GET,
        Method::Post => http::Method::POST,
        Method::Put => http::Method::PUT,
        Method::Delete => http::Method::DELETE,
        Method::Patch => http::Method::PATCH,
        Method::Head => http::Method::HEAD,
        Method::Options => http::Method::OPTIONS,
    }
}

pub async fn response_from_reqwest(res: reqwest::Response) -> Result<Response, HttpError> {
    let status = res.status().as_u16();
    let headers = response_headers(res.headers()).map_err(|_| HttpError::RuntimeError)?;
    let status_text = (&res.status().canonical_reason().unwrap_or("")).to_string();
    let body = Some(
        res.bytes()
            .await
            .map_err(|_| HttpError::RuntimeError)?
            .to_vec(),
    );

    Ok(Response {
        status,
        headers,
        body,
        status_text,
    })
}

pub fn request_headers(h: Headers) -> anyhow::Result<HeaderMap> {
    let mut res = HeaderMap::new();
    for (k, v) in h {
        res.insert(
            http::header::HeaderName::try_from(k)?,
            http::header::HeaderValue::try_from(v)?,
        );
    }
    Ok(res)
}

pub fn response_headers(h: &HeaderMap) -> anyhow::Result<Option<Vec<(String, String)>>> {
    let mut res: Vec<(String, String)> = vec![];

    for (k, v) in h {
        res.push((
            k.to_string(),
            std::str::from_utf8(v.as_bytes())?.to_string(),
        ));
    }

    Ok(Some(res))
}
