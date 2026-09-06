use reqwest::Url;
use serde::{Deserialize, Serialize};

pub const RIGHT: &str = "synthetic-folder:read";

/// Operator-approved destinations, not values accepted from the browser.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub grant: String,
    pub continuation: String,
    pub interaction: String,
    pub management: String,
    pub resource: String,
}

pub fn origin(raw: &str) -> Result<bool, &'static str> {
    let url = Url::parse(raw).map_err(|_| "Invalid workbench origin")?;
    let local = url.scheme() == "http" && loopback(&url);
    if url.origin().ascii_serialization() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || raw.contains('@')
        || (!local && (url.scheme() != "https" || url.port_or_known_default() != Some(443)))
    {
        return Err("Workbench origin must be canonical HTTPS or explicit HTTP loopback");
    }
    Ok(local)
}

pub fn targets(raw: &str, local: bool) -> Result<Vec<Target>, &'static str> {
    if raw.len() > 16_384 {
        return Err("Lifecycle target configuration exceeds 16 KiB");
    }
    let targets: Vec<Target> =
        serde_json::from_str(raw).map_err(|_| "Invalid lifecycle target configuration")?;
    if targets.len() > 4 {
        return Err("At most four lifecycle targets are permitted");
    }
    for target in &targets {
        if target.name.is_empty()
            || target.name.len() > 80
            || target.name.chars().any(char::is_control)
        {
            return Err("Invalid lifecycle target name");
        }
        for value in [
            &target.grant,
            &target.continuation,
            &target.interaction,
            &target.management,
            &target.resource,
        ] {
            endpoint(value, local)?;
        }
        if !target.interaction.ends_with('/')
            || !target.management.ends_with('/')
            || target.grant == target.continuation
            || target.resource == target.grant
            || target.resource == target.continuation
        {
            return Err("Lifecycle endpoints must be distinct; prefixes must end in a slash");
        }
    }
    Ok(targets)
}

pub fn endpoint(raw: &str, local: bool) -> Result<Url, &'static str> {
    let url = Url::parse(raw).map_err(|_| "Invalid lifecycle endpoint")?;
    if raw.len() > 2048
        || url.as_str() != raw
        || !url.username().is_empty()
        || url.password().is_some()
        || raw
            .split("://")
            .nth(1)
            .is_some_and(|s| s.split('/').next().is_some_and(|a| a.contains('@')))
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Lifecycle endpoint must be canonical without credentials, query or fragment");
    }
    if local && url.scheme() == "http" && loopback(&url) {
        return Ok(url);
    }
    let host = url.host_str().ok_or("Lifecycle endpoint needs a host")?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !host.contains('.')
        || host.starts_with('[')
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err("Lifecycle HTTPS endpoint requires a public DNS name on port 443");
    }
    Ok(url)
}

fn loopback(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

pub fn member(url: &str, prefix: &str) -> bool {
    url.strip_prefix(prefix).is_some_and(|tail| {
        !tail.is_empty()
            && tail.len() <= 128
            && tail
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    })
}

impl Target {
    pub fn permits(&self, method: &str, url: &str) -> bool {
        match method {
            "GET" => url == self.resource,
            "POST" => {
                url == self.grant || url == self.continuation || member(url, &self.management)
            }
            "DELETE" => url == self.continuation || member(url, &self.management),
            _ => false,
        }
    }
}
