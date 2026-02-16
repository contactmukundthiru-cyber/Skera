//! Mobile app extractors — APK (Android) and IPA (iOS)

use std::path::{Path, PathBuf};

pub struct MobileExtractResult {
    pub extract_dir: PathBuf,
    pub total_files: usize,
    pub total_bytes: u64,
    pub content_types: Vec<String>,
    pub _temp_dir: tempfile::TempDir,
}

/// Extract an Android APK for scanning
///
/// APK files are ZIP archives containing:
/// - classes.dex (Dalvik bytecode)
/// - lib/*.so (native libraries)
/// - assets/ (bundled assets, often web views)
/// - res/ (resources)
/// - AndroidManifest.xml
pub async fn extract_apk(path: &Path) -> Result<MobileExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let extract_dir = temp_dir.path().join("apk");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    // APK is just a ZIP file
    let result = std::process::Command::new("tar")
        .args(["xf", path.to_str().unwrap_or(""), "-C", extract_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to extract APK: {}", e))?;

    if !result.status.success() {
        // Fallback to PowerShell
        let ps = std::process::Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    path.display(), extract_dir.display()
                ),
            ])
            .output()
            .map_err(|e| format!("Failed to extract APK: {}", e))?;

        if !ps.status.success() {
            return Err("APK extraction failed".to_string());
        }
    }

    let mut total_files = 0;
    let mut total_bytes = 0u64;
    let mut content_types = Vec::new();

    for entry in walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        total_files += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);

        if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
            let ct = match ext {
                "dex" => "dalvik/dex",
                "so" => "application/elf",
                "js" => "text/javascript",
                "html" => "text/html",
                "json" => "application/json",
                _ => continue,
            };
            if !content_types.contains(&ct.to_string()) {
                content_types.push(ct.to_string());
            }
        }
    }

    // Try to decompile DEX files if jadx is available
    let dex_files: Vec<PathBuf> = walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("dex"))
        .map(|e| e.path().to_path_buf())
        .collect();

    if !dex_files.is_empty() {
        let java_dir = extract_dir.join("decompiled_java");
        std::fs::create_dir_all(&java_dir).ok();

        // Try jadx for DEX → Java decompilation
        let jadx_result = std::process::Command::new("jadx")
            .args([
                "-d", java_dir.to_str().unwrap_or(""),
                "--no-res",
                path.to_str().unwrap_or(""),
            ])
            .output();

        if jadx_result.is_ok() {
            content_types.push("text/java-decompiled".to_string());
        }
    }

    Ok(MobileExtractResult {
        extract_dir,
        total_files,
        total_bytes,
        content_types,
        _temp_dir: temp_dir,
    })
}

/// Extract an iOS IPA for scanning
///
/// IPA files are ZIP archives containing:
/// - Payload/*.app/ (the app bundle)
///   - Mach-O binary
///   - Frameworks/ (embedded frameworks)
///   - Assets.car (compiled assets)
///   - Info.plist
pub async fn extract_ipa(path: &Path) -> Result<MobileExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let extract_dir = temp_dir.path().join("ipa");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    // IPA is a ZIP file
    let result = std::process::Command::new("tar")
        .args(["xf", path.to_str().unwrap_or(""), "-C", extract_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to extract IPA: {}", e))?;

    if !result.status.success() {
        let ps = std::process::Command::new("powershell")
            .args([
                "-NoProfile", "-Command",
                &format!(
                    "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                    path.display(), extract_dir.display()
                ),
            ])
            .output()
            .map_err(|e| format!("Failed to extract IPA: {}", e))?;

        if !ps.status.success() {
            return Err("IPA extraction failed".to_string());
        }
    }

    let mut total_files = 0;
    let mut total_bytes = 0u64;
    let mut content_types = Vec::new();

    for entry in walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        total_files += 1;
        total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);

        if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
            let ct = match ext {
                "dylib" => "application/mach-o",
                "framework" => "application/framework",
                "plist" => "application/plist",
                "js" => "text/javascript",
                "swift" => "text/swift",
                _ => continue,
            };
            if !content_types.contains(&ct.to_string()) {
                content_types.push(ct.to_string());
            }
        }
    }

    Ok(MobileExtractResult {
        extract_dir,
        total_files,
        total_bytes,
        content_types,
        _temp_dir: temp_dir,
    })
}
