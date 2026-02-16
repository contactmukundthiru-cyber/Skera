//! Content-addressed scan cache
//!
//! Caches file-level scan results by SHA-256 hash. On subsequent scans,
//! only changed files are re-analyzed. Critical for CI/CD performance.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::detection::Violation;

/// Cached result for a single file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFileResult {
    pub sha256: String,
    pub violations: Vec<Violation>,
    pub scanned_at: String,
}

/// Cached dependency graph resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDepGraph {
    pub lockfile_hash: String,
    pub total_deps: usize,
    pub scanned_at: String,
}

/// On-disk scan cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCacheData {
    pub version: u32,
    pub files: HashMap<String, CachedFileResult>,
    pub dep_graphs: HashMap<String, CachedDepGraph>,
}

/// Content-addressed scan cache
pub struct ScanCache {
    cache_path: PathBuf,
    data: ScanCacheData,
    hits: usize,
    misses: usize,
}

impl ScanCache {
    /// Load cache from disk, or create empty
    pub fn load(project_root: &Path) -> Self {
        let cache_path = project_root.join(".skera-cache.json");
        let data = if cache_path.exists() {
            match std::fs::read_to_string(&cache_path) {
                Ok(content) => match serde_json::from_str::<ScanCacheData>(&content) {
                    Ok(d) if d.version == 1 => {
                        tracing::info!("Loaded scan cache ({} entries)", d.files.len());
                        d
                    }
                    _ => {
                        tracing::debug!("Cache version mismatch, starting fresh");
                        ScanCacheData::default()
                    }
                },
                Err(_) => ScanCacheData::default(),
            }
        } else {
            ScanCacheData::default()
        };

        Self {
            cache_path,
            data,
            hits: 0,
            misses: 0,
        }
    }

    /// Create a cache that will not persist (for testing or one-shot scans)
    pub fn ephemeral() -> Self {
        Self {
            cache_path: PathBuf::from("/dev/null"),
            data: ScanCacheData::default(),
            hits: 0,
            misses: 0,
        }
    }

    /// Check if we have a valid cached result for a file
    pub fn get(&mut self, path: &Path) -> Option<&CachedFileResult> {
        let hash = match hash_file(path) {
            Some(h) => h,
            None => return None,
        };

        let key = path.to_string_lossy().to_string();
        match self.data.files.get(&key) {
            Some(cached) if cached.sha256 == hash => {
                self.hits += 1;
                Some(cached)
            }
            _ => {
                self.misses += 1;
                None
            }
        }
    }

    /// Store a scan result for a file
    pub fn put(&mut self, path: &Path, violations: Vec<Violation>) {
        let hash = match hash_file(path) {
            Some(h) => h,
            None => return,
        };

        let key = path.to_string_lossy().to_string();
        self.data.files.insert(
            key,
            CachedFileResult {
                sha256: hash,
                violations,
                scanned_at: chrono::Utc::now().to_rfc3339(),
            },
        );
    }

    /// Save cache to disk
    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("Failed to serialize cache: {}", e))?;
        std::fs::write(&self.cache_path, json)
            .map_err(|e| format!("Failed to write cache: {}", e))?;
        tracing::info!(
            "Saved scan cache ({} entries, {}/{} hit rate)",
            self.data.files.len(),
            self.hits,
            self.hits + self.misses
        );
        Ok(())
    }

    /// Statistics
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn hits(&self) -> usize {
        self.hits
    }
    pub fn misses(&self) -> usize {
        self.misses
    }
}

impl Default for ScanCacheData {
    fn default() -> Self {
        Self {
            version: 1,
            files: HashMap::new(),
            dep_graphs: HashMap::new(),
        }
    }
}

/// Hash a file's contents with SHA-256
fn hash_file(path: &Path) -> Option<String> {
    let content = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Some(hex::encode(hasher.finalize()))
}
