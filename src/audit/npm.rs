//! npm registry fetcher — downloads packages from registry.npmjs.org

use super::FetchResult;
use std::io::Write;

/// Download an npm package
pub async fn fetch(name: &str, version: Option<&str>) -> Result<FetchResult, String> {
    let temp_dir = tempfile::TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Resolve version from npm registry if not specified
    let resolved_version = if let Some(v) = version {
        v.to_string()
    } else {
        resolve_latest_version(name).await?
    };

    // Build tarball URL
    // npm registry URL format: https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz
    let basename = if name.starts_with('@') {
        // Scoped package: @scope/name → name
        name.split('/').last().unwrap_or(name)
    } else {
        name
    };

    let tarball_url = format!(
        "https://registry.npmjs.org/{}/-/{}-{}.tgz",
        name, basename, resolved_version
    );

    // Download the tarball
    let response = reqwest::get(&tarball_url)
        .await
        .map_err(|e| format!("Failed to download {}: {}", tarball_url, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "npm registry returned {} for {}",
            response.status(),
            tarball_url
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    // Write to temp file
    let tarball_path = temp_dir.path().join("package.tgz");
    let mut file = std::fs::File::create(&tarball_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write tarball: {}", e))?;

    // Extract the tarball using tar
    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir_all(&unpack_dir)
        .map_err(|e| format!("Failed to create unpack dir: {}", e))?;

    // Use tar to extract (available on both Unix and Windows with Git)
    let tar_output = std::process::Command::new("tar")
        .args(["xzf", tarball_path.to_str().unwrap_or(""), "-C", unpack_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to run tar: {}", e))?;

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        return Err(format!("tar extraction failed: {}", stderr));
    }

    Ok(FetchResult {
        unpacked_dir: unpack_dir,
        name: name.to_string(),
        version: Some(resolved_version),
        source: "npm".to_string(),
        _temp_dir: temp_dir,
    })
}

/// Resolve the latest version from npm registry
async fn resolve_latest_version(name: &str) -> Result<String, String> {
    let registry_url = format!("https://registry.npmjs.org/{}/latest", name);

    let response = reqwest::get(&registry_url)
        .await
        .map_err(|e| format!("Failed to query npm registry: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Package '{}' not found on npm", name));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse npm response: {}", e))?;

    json.get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No version field in npm response for '{}'", name))
}
