//! Archive extractor — ZIP, TAR, GZIP, 7z, RAR, firmware

use std::path::{Path, PathBuf};

pub struct ArchiveExtractResult {
    pub extract_dir: PathBuf,
    pub total_files: usize,
    pub total_bytes: u64,
    pub _temp_dir: tempfile::TempDir,
}

/// Extract any archive format
pub async fn extract(path: &Path) -> Result<ArchiveExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let extract_dir = temp_dir.path().join("extracted");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let success = match ext.as_str() {
        "zip" => extract_zip(path, &extract_dir)?,
        "tar" => extract_tar(path, &extract_dir)?,
        "gz" | "tgz" => extract_tar_gz(path, &extract_dir)?,
        "bz2" | "tbz2" => extract_tar_bz2(path, &extract_dir)?,
        "xz" | "txz" => extract_tar_xz(path, &extract_dir)?,
        "7z" => extract_7z(path, &extract_dir)?,
        "rar" => extract_rar(path, &extract_dir)?,
        _ => {
            // Try to auto-detect from magic bytes
            let bytes = std::fs::read(path)
                .map_err(|e| format!("Failed to read file: {}", e))?;
            if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
                extract_zip(path, &extract_dir)?
            } else if bytes.starts_with(&[0x1F, 0x8B]) {
                extract_tar_gz(path, &extract_dir)?
            } else {
                return Err(format!("Unknown archive format: .{}", ext));
            }
        }
    };

    let _ = success;

    let mut total_files = 0;
    let mut total_bytes = 0u64;

    for entry in walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        total_files += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }

    Ok(ArchiveExtractResult {
        extract_dir,
        total_files,
        total_bytes,
        _temp_dir: temp_dir,
    })
}

/// Extract firmware images (binwalk-style)
pub async fn extract_firmware(path: &Path) -> Result<ArchiveExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let extract_dir = temp_dir.path().join("firmware");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    // Try binwalk first
    let binwalk_result = std::process::Command::new("binwalk")
        .args([
            "--extract",
            "--directory", extract_dir.to_str().unwrap_or(""),
            path.to_str().unwrap_or(""),
        ])
        .output();

    match binwalk_result {
        Ok(output) if output.status.success() => {
            // binwalk succeeded
        }
        _ => {
            // Fallback: just copy the file for string analysis
            let dest = extract_dir.join(
                path.file_name().unwrap_or_default()
            );
            std::fs::copy(path, &dest)
                .map_err(|e| format!("Failed to copy firmware: {}", e))?;
        }
    }

    let mut total_files = 0;
    let mut total_bytes = 0u64;

    for entry in walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        total_files += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
    }

    Ok(ArchiveExtractResult {
        extract_dir,
        total_files,
        total_bytes,
        _temp_dir: temp_dir,
    })
}

// ─── Format-specific extractors ────────────────────────────────────

fn extract_zip(path: &Path, dest: &Path) -> Result<bool, String> {
    // Try tar first (Windows 10+ supports ZIP via tar)
    let result = std::process::Command::new("tar")
        .args(["xf", path.to_str().unwrap_or(""), "-C", dest.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("tar: {}", e))?;

    if result.status.success() {
        return Ok(true);
    }

    // Fallback: PowerShell
    let ps = std::process::Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            &format!(
                "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                path.display(), dest.display()
            ),
        ])
        .output()
        .map_err(|e| format!("PowerShell: {}", e))?;

    if ps.status.success() {
        Ok(true)
    } else {
        Err("ZIP extraction failed".to_string())
    }
}

fn extract_tar(path: &Path, dest: &Path) -> Result<bool, String> {
    run_tar(&["xf", path.to_str().unwrap_or(""), "-C", dest.to_str().unwrap_or("")])
}

fn extract_tar_gz(path: &Path, dest: &Path) -> Result<bool, String> {
    run_tar(&["xzf", path.to_str().unwrap_or(""), "-C", dest.to_str().unwrap_or("")])
}

fn extract_tar_bz2(path: &Path, dest: &Path) -> Result<bool, String> {
    run_tar(&["xjf", path.to_str().unwrap_or(""), "-C", dest.to_str().unwrap_or("")])
}

fn extract_tar_xz(path: &Path, dest: &Path) -> Result<bool, String> {
    run_tar(&["xJf", path.to_str().unwrap_or(""), "-C", dest.to_str().unwrap_or("")])
}

fn extract_7z(path: &Path, dest: &Path) -> Result<bool, String> {
    let result = std::process::Command::new("7z")
        .args(["x", path.to_str().unwrap_or(""), &format!("-o{}", dest.display()), "-y"])
        .output()
        .map_err(|e| format!("7z not available: {}", e))?;
    Ok(result.status.success())
}

fn extract_rar(path: &Path, dest: &Path) -> Result<bool, String> {
    let result = std::process::Command::new("unrar")
        .args(["x", path.to_str().unwrap_or(""), dest.to_str().unwrap_or(""), "-y"])
        .output()
        .map_err(|e| format!("unrar not available: {}", e))?;
    Ok(result.status.success())
}

fn run_tar(args: &[&str]) -> Result<bool, String> {
    let result = std::process::Command::new("tar")
        .args(args)
        .output()
        .map_err(|e| format!("tar: {}", e))?;
    if result.status.success() {
        Ok(true)
    } else {
        Err(format!("tar failed: {}", String::from_utf8_lossy(&result.stderr)))
    }
}
