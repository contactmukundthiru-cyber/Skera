//! Repository cloning — shallow clone to temp directory for scanning
//!
//! Implements `ScanTarget::Repository` which was previously unimplemented.

use std::path::PathBuf;
use tempfile::TempDir;

/// Clone a git repository for scanning
pub struct RepoCloner;

impl RepoCloner {
    /// Shallow-clone a repository URL to a temporary directory
    ///
    /// Supports:
    /// - https://github.com/user/repo
    /// - https://github.com/user/repo.git
    /// - git@github.com:user/repo.git
    pub fn shallow_clone(url: &str) -> Result<(TempDir, PathBuf), String> {
        let tmp = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let clone_path = tmp.path().to_path_buf();

        tracing::info!("Shallow cloning {} → {}", url, clone_path.display());

        // Use git CLI for maximum compatibility (handles auth, SSH keys, etc.)
        let output = std::process::Command::new("git")
            .args([
                "clone",
                "--depth", "1",
                "--single-branch",
                url,
                &clone_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("Failed to run git: {} (is git installed?)", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {}", stderr));
        }

        tracing::info!("Cloned successfully to {}", clone_path.display());
        Ok((tmp, clone_path))
    }

    /// Clone with a specific branch
    pub fn clone_branch(url: &str, branch: &str) -> Result<(TempDir, PathBuf), String> {
        let tmp = TempDir::new().map_err(|e| format!("Failed to create temp dir: {}", e))?;
        let clone_path = tmp.path().to_path_buf();

        let output = std::process::Command::new("git")
            .args([
                "clone",
                "--depth", "1",
                "--branch", branch,
                "--single-branch",
                url,
                &clone_path.to_string_lossy(),
            ])
            .output()
            .map_err(|e| format!("Failed to run git: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git clone failed: {}", stderr));
        }

        Ok((tmp, clone_path))
    }

    /// Check if git is available on the system
    pub fn is_available() -> bool {
        std::process::Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
