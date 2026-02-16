//! Chrome Web Store extension fetcher
//!
//! Downloads .crx files from the Chrome Web Store and unpacks them
//! for scanning. This is how we audit extensions like Securly.

use super::FetchResult;
use std::io::Write;

/// Download a Chrome extension by its ID
pub async fn fetch(extension_id: &str) -> Result<FetchResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    // Chrome Web Store download URL
    // This uses the CRX download endpoint used by Chrome itself
    let crx_url = format!(
        "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=120.0&acceptformat=crx2,crx3&x=id%3D{}%26uc",
        extension_id
    );

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let response = client
        .get(&crx_url)
        .send()
        .await
        .map_err(|e| format!("Failed to download extension {}: {}", extension_id, e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Chrome Web Store returned {} for extension {}",
            response.status(),
            extension_id
        ));
    }

    let bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read CRX: {}", e))?;

    // CRX files are ZIP files with a header that we need to skip
    // CRX3 header: magic(4) + version(4) + header_length(4) + header(N)
    let crx_bytes = bytes.as_ref();
    let zip_start = find_zip_start(crx_bytes)
        .ok_or_else(|| "Could not find ZIP content in CRX file".to_string())?;

    let zip_data = &crx_bytes[zip_start..];

    // Write ZIP to temp file
    let zip_path = temp_dir.path().join("extension.zip");
    let mut file = std::fs::File::create(&zip_path)
        .map_err(|e| format!("Failed to create temp file: {}", e))?;
    file.write_all(zip_data)
        .map_err(|e| format!("Failed to write ZIP: {}", e))?;

    // Extract the ZIP
    let unpack_dir = temp_dir.path().join("unpacked");
    std::fs::create_dir_all(&unpack_dir)
        .map_err(|e| format!("Failed to create unpack dir: {}", e))?;

    // Use PowerShell's Expand-Archive or tar on Windows
    let extract_result = std::process::Command::new("tar")
        .args(["xf", zip_path.to_str().unwrap_or(""), "-C", unpack_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to extract ZIP: {}", e))?;

    if !extract_result.status.success() {
        // Fallback: try PowerShell's Expand-Archive
        let ps_result = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    unpack_dir.display()
                ),
            ])
            .output()
            .map_err(|e| format!("Failed to run PowerShell: {}", e))?;

        if !ps_result.status.success() {
            let stderr = String::from_utf8_lossy(&ps_result.stderr);
            return Err(format!("ZIP extraction failed: {}", stderr));
        }
    }

    // Try to get the extension name from manifest.json
    let name = read_extension_name(&unpack_dir).unwrap_or_else(|| extension_id.to_string());

    Ok(FetchResult {
        unpacked_dir: unpack_dir,
        name,
        version: read_extension_version(&temp_dir.path().join("unpacked")),
        source: "chrome-web-store".to_string(),
        _temp_dir: temp_dir,
    })
}

/// Find the start of the ZIP content within a CRX file
fn find_zip_start(data: &[u8]) -> Option<usize> {
    // ZIP magic number: PK\x03\x04
    let zip_magic = &[0x50, 0x4B, 0x03, 0x04];
    data.windows(4).position(|w| w == zip_magic)
}

/// Read the extension name from manifest.json
fn read_extension_name(dir: &std::path::Path) -> Option<String> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("name")
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
}

/// Read the extension version from manifest.json
fn read_extension_version(dir: &std::path::Path) -> Option<String> {
    let manifest_path = dir.join("manifest.json");
    let content = std::fs::read_to_string(&manifest_path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}
