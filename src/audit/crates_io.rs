//! crates.io fetcher — downloads Rust crates

use super::FetchResult;
use std::io::Write;

/// Download a crate from crates.io
pub async fn fetch(name: &str, version: Option<&str>) -> Result<FetchResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Resolve version if not specified
    let resolved_version = if let Some(v) = version {
        v.to_string()
    } else {
        resolve_latest_version(name).await?
    };

    // crates.io download URL
    let tarball_url = format!(
        "https://crates.io/api/v1/crates/{}/{}/download",
        name, resolved_version
    );

    let client = reqwest::Client::builder()
        .user_agent("skera-core/0.3.0 (copyright forensics)")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let response = client
        .get(&tarball_url)
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {}", tarball_url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "crates.io returned {} for {}@{}",
            response.status(),
            name,
            resolved_version
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let tarball_path = temp_dir.path().join("crate.tgz");
    let mut file = std::fs::File::create(&tarball_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write tarball: {}", e))?;

    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir_all(&unpack_dir)
        .map_err(|e| format!("Failed to create unpack dir: {}", e))?;

    let tar_output = std::process::Command::new("tar")
        .args(["xzf", tarball_path.to_str().unwrap_or(""), "-C", unpack_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        return Err(format!("Extraction failed: {}", stderr));
    }

    Ok(FetchResult {
        unpacked_dir: unpack_dir,
        name: name.to_string(),
        version: Some(resolved_version),
        source: "crates.io".to_string(),
        _temp_dir: temp_dir,
    })
}

async fn resolve_latest_version(name: &str) -> Result<String, String> {
    let client = reqwest::Client::builder()
        .user_agent("skera-core/0.3.0 (copyright forensics)")
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let api_url = format!("https://crates.io/api/v1/crates/{}", name);
    let response = client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| format!("Failed to query crates.io: {}", e))?;

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    json.get("crate")
        .and_then(|c| c.get("max_version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("Crate '{}' not found on crates.io", name))
}
