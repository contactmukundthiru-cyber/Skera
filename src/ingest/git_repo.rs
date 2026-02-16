//! Git repository cloner — clones repos for scanning with full history

use std::path::PathBuf;

pub struct GitCloneResult {
    pub repo_dir: PathBuf,
    pub _temp_dir: tempfile::TempDir,
}

/// Clone a git repository for scanning
pub async fn clone_and_prepare(
    url: &str,
    branch: Option<&str>,
    depth: Option<u32>,
) -> Result<GitCloneResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let repo_dir = temp_dir.path().join("repo");

    let mut args = vec!["clone".to_string()];

    if let Some(d) = depth {
        args.push("--depth".to_string());
        args.push(d.to_string());
    }

    if let Some(b) = branch {
        args.push("--branch".to_string());
        args.push(b.to_string());
    }

    args.push(url.to_string());
    args.push(repo_dir.to_str().unwrap_or("repo").to_string());

    let result = std::process::Command::new("git")
        .args(&args)
        .output()
        .map_err(|e| format!("Git not available: {}", e))?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("Git clone failed: {}", stderr));
    }

    Ok(GitCloneResult {
        repo_dir,
        _temp_dir: temp_dir,
    })
}
