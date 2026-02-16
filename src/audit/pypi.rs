//! PyPI fetcher — downloads packages from pypi.org

use super::FetchResult;
use std::io::Write;

/// Download a package from PyPI
pub async fn fetch(name: &str, version: Option<&str>) -> Result<FetchResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Query PyPI JSON API
    let api_url = match version {
        Some(v) => format!("https://pypi.org/pypi/{}/{}/json", name, v),
        None => format!("https://pypi.org/pypi/{}/json", name),
    };

    let response = reqwest::get(&api_url)
        .await
        .map_err(|e| format!("Failed to query PyPI: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("Package '{}' not found on PyPI", name));
    }

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse PyPI response: {}", e))?;

    let resolved_version = json
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    // Find the sdist URL (source distribution)
    let urls = json
        .get("urls")
        .and_then(|u| u.as_array())
        .ok_or("No download URLs found")?;

    let sdist_url = urls
        .iter()
        .find(|u| {
            u.get("packagetype")
                .and_then(|p| p.as_str())
                .map(|p| p == "sdist")
                .unwrap_or(false)
        })
        .or_else(|| urls.first())
        .and_then(|u| u.get("url"))
        .and_then(|u| u.as_str())
        .ok_or("No suitable download URL found")?;

    // Download the archive
    let archive_response = reqwest::get(sdist_url)
        .await
        .map_err(|e| format!("Failed to download {}: {}", sdist_url, e))?;

    let bytes = archive_response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    // Write to temp file
    let ext = if sdist_url.ends_with(".zip") { "zip" } else { "tar.gz" };
    let archive_path = temp_dir.path().join(format!("package.{}", ext));
    let mut file = std::fs::File::create(&archive_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write archive: {}", e))?;

    // Extract
    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir_all(&unpack_dir)
        .map_err(|e| format!("Failed to create unpack dir: {}", e))?;

    let tar_output = std::process::Command::new("tar")
        .args(["xzf", archive_path.to_str().unwrap_or(""), "-C", unpack_dir.to_str().unwrap_or("")])
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
        source: "pypi".to_string(),
        _temp_dir: temp_dir,
    })
}
