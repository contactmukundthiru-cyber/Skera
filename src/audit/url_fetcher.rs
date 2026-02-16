//! Arbitrary URL fetcher — downloads a file from any URL

use super::FetchResult;
use std::io::Write;

/// Download a file from an arbitrary URL
pub async fn fetch(url: &str) -> Result<FetchResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("Failed to download {}: {}", url, e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP {} for {}", response.status(), url));
    }

    // Determine filename from URL
    let filename = url
        .split('/')
        .last()
        .unwrap_or("download")
        .split('?')
        .next()
        .unwrap_or("download");

    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir_all(&unpack_dir)
        .map_err(|e| format!("Failed to create dir: {}", e))?;

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let file_path = unpack_dir.join(filename);
    let mut file = std::fs::File::create(&file_path)
        .map_err(|e| format!("Failed to create file: {}", e))?;
    file.write_all(&bytes)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    Ok(FetchResult {
        unpacked_dir: unpack_dir,
        name: filename.to_string(),
        version: None,
        source: "url".to_string(),
        _temp_dir: temp_dir,
    })
}
