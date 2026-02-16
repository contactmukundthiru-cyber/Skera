//! Docker image extractor — pulls and extracts container image layers

use std::path::PathBuf;

pub struct DockerExtractResult {
    pub extract_dir: PathBuf,
    pub total_files: usize,
    pub total_bytes: u64,
    pub _temp_dir: tempfile::TempDir,
}

/// Extract a Docker image for scanning
pub async fn extract_image(image: &str) -> Result<DockerExtractResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let tar_path = temp_dir.path().join("image.tar");
    let extract_dir = temp_dir.path().join("extracted");
    std::fs::create_dir_all(&extract_dir)
        .map_err(|e| format!("Failed to create extract dir: {}", e))?;

    // Step 1: Pull the image (if not already local)
    let pull = std::process::Command::new("docker")
        .args(["pull", image])
        .output()
        .map_err(|e| format!("Docker not available: {}", e))?;

    if !pull.status.success() {
        let stderr = String::from_utf8_lossy(&pull.stderr);
        return Err(format!("Failed to pull {}: {}", image, stderr));
    }

    // Step 2: Save image as tar
    let save = std::process::Command::new("docker")
        .args(["save", "-o", tar_path.to_str().unwrap_or("image.tar"), image])
        .output()
        .map_err(|e| format!("Failed to save image: {}", e))?;

    if !save.status.success() {
        let stderr = String::from_utf8_lossy(&save.stderr);
        return Err(format!("Failed to save image: {}", stderr));
    }

    // Step 3: Extract the tar
    let extract = std::process::Command::new("tar")
        .args(["xf", tar_path.to_str().unwrap_or(""), "-C", extract_dir.to_str().unwrap_or("")])
        .output()
        .map_err(|e| format!("Failed to extract: {}", e))?;

    if !extract.status.success() {
        let stderr = String::from_utf8_lossy(&extract.stderr);
        return Err(format!("Extraction failed: {}", stderr));
    }

    // Step 4: Extract each layer
    let layers_dir = extract_dir.join("layers");
    std::fs::create_dir_all(&layers_dir).ok();

    let mut total_files = 0usize;
    let mut total_bytes = 0u64;

    // Walk the extracted tar looking for layer.tar files
    for entry in walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_str().map(|n| n == "layer.tar").unwrap_or(false)
        })
    {
        let layer_extract_dir = layers_dir.join(format!("layer_{}", total_files));
        std::fs::create_dir_all(&layer_extract_dir).ok();

        let _ = std::process::Command::new("tar")
            .args(["xf", entry.path().to_str().unwrap_or(""), "-C", layer_extract_dir.to_str().unwrap_or("")])
            .output();

        // Count files in this layer
        for file_entry in walkdir::WalkDir::new(&layer_extract_dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            total_files += 1;
            total_bytes += file_entry.metadata().map(|m| m.len()).unwrap_or(0);
        }
    }

    Ok(DockerExtractResult {
        extract_dir,
        total_files,
        total_bytes,
        _temp_dir: temp_dir,
    })
}
