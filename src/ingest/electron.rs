//! Electron app extractor — unpacks ASAR archives

use std::path::{Path, PathBuf};

pub struct ElectronExtractResult {
    pub extract_dir: PathBuf,
    pub total_files: usize,
    pub total_bytes: u64,
    pub manifest_files: Vec<String>,
    pub _temp_dir: tempfile::TempDir,
}

/// Extract an Electron ASAR archive or app directory
///
/// Electron apps bundle their web content in ASAR archives.
/// The ASAR format is essentially a tar-like archive that can be
/// extracted with the `asar` npm tool or by parsing the header.
pub async fn extract_asar(path: &Path) -> Result<ElectronExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let extract_dir = temp_dir.path().join("electron");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    // If it's a directory (already unpacked app), just copy/symlink
    if path.is_dir() {
        // Look for app.asar inside
        let asar_path = path.join("resources").join("app.asar");
        if asar_path.exists() {
            return extract_asar_file(&asar_path, &extract_dir, temp_dir).await;
        }

        // Already unpacked — just use directly
        return Ok(ElectronExtractResult {
            extract_dir: path.to_path_buf(),
            total_files: 0,
            total_bytes: 0,
            manifest_files: detect_electron_manifests(path),
            _temp_dir: temp_dir,
        });
    }

    // It's an ASAR file — extract it
    extract_asar_file(path, &extract_dir, temp_dir).await
}

async fn extract_asar_file(
    asar_path: &Path,
    extract_dir: &Path,
    temp_dir: tempfile::TempDir,
) -> Result<ElectronExtractResult, String> {
    // Try npx asar extract
    let result = std::process::Command::new("npx")
        .args([
            "-y", "asar",
            "extract",
            asar_path.to_str().unwrap_or(""),
            extract_dir.to_str().unwrap_or(""),
        ])
        .output()
        .map_err(|e| format!("Failed to run asar extract: {}", e))?;

    if !result.status.success() {
        // Fallback: try to parse ASAR header manually
        // ASAR format: 4 bytes header size (LE), 4 bytes header string size (LE),
        // 4 bytes header size again, header JSON, then file contents
        return Err(format!(
            "ASAR extraction failed. Install asar: npm install -g asar. Error: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }

    let mut total_files = 0;
    let mut total_bytes = 0u64;

    for entry in walkdir::WalkDir::new(extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        total_files += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }

    let manifest_files = detect_electron_manifests(extract_dir);

    Ok(ElectronExtractResult {
        extract_dir: extract_dir.to_path_buf(),
        total_files,
        total_bytes,
        manifest_files,
        _temp_dir: temp_dir,
    })
}

fn detect_electron_manifests(dir: &Path) -> Vec<String> {
    let names = ["package.json", "electron-builder.yml", "forge.config.js"];
    names.iter()
        .filter(|n| dir.join(n).exists())
        .map(|n| n.to_string())
        .collect()
}
