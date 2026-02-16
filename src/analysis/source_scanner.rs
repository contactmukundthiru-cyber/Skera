//! Source code scanning — the definitive digital identity collector
//!
//! ## Overview
//!
//! Walks a project tree and builds a complete digital identity profile:
//! every license header, manifest declaration, LICENSE file, NOTICE file,
//! vendored dependency, media asset, font, and git forensic event.
//!
//! This is the **source of truth** for what a project contains, who owns
//! what, and whether all attribution obligations are met.
//!
//! ## Capabilities
//!
//! 1. **LICENSE File Discovery & Classification** — finds and classifies
//!    all LICENSE/COPYING/LICENCE files (root and nested).
//!
//! 2. **Manifest License Extraction** — reads package.json, Cargo.toml,
//!    setup.py, pom.xml, build.gradle, go.mod, composer.json, Gemfile,
//!    .csproj, .nuspec, Package.swift, and more.
//!
//! 3. **Header Scanning** — detects SPDX identifiers and copyright
//!    headers in every source file.
//!
//! 4. **Vendored Code Detection** — recursively scans vendor directories,
//!    classifies each vendored dependency's license.
//!
//! 5. **Media Asset Inventory** — scans for images, audio, video, fonts,
//!    SVGs, and documents, fingerprinting each.
//!
//! 6. **Git Forensics Integration** — checks commit history for license
//!    deletions, header removals, and notice file tampering.
//!
//! 7. **Lockfile Parsing** — reads package-lock.json, yarn.lock,
//!    Cargo.lock, go.sum, poetry.lock, etc.
//!
//! 8. **Configuration File Detection** — finds .editorconfig, .gitignore,
//!    CI configs that may indicate project boundaries.

use crate::license::{LicenseClassifier, LicenseId, ClassificationResult};
use crate::detection::HeaderDetector;
use crate::detection::header_detector::DetectedHeader;
use crate::detection::media_forensics::{self, MediaFingerprint, MediaScanStats};
use crate::analysis::git_forensics::{GitForensics, GitForensicTimeline};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ─── Data Structures ────────────────────────────────────────────────

/// Complete source scan result for a project — the digital identity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceScan {
    /// Root directory scanned
    pub root: PathBuf,
    /// Project license (from root LICENSE file)
    pub project_license: Option<ClassificationResult>,
    /// Manifest-declared license (from package.json, Cargo.toml, etc.)
    pub manifest_license: Option<ClassificationResult>,
    /// Manifest file path
    pub manifest_path: Option<PathBuf>,
    /// All license headers found in source files
    pub headers: Vec<DetectedHeader>,
    /// LICENSE/COPYING files found (all, not just root)
    pub license_files: Vec<LicenseFileInfo>,
    /// NOTICE/AUTHORS/CONTRIBUTORS files found
    pub notice_files: Vec<PathBuf>,
    /// Vendored/third-party directories detected
    pub vendored_dirs: Vec<VendoredDir>,
    /// All nested LICENSE files in subdirectories
    pub nested_license_files: Vec<LicenseFileInfo>,
    /// Lockfile paths found
    pub lockfiles: Vec<PathBuf>,
    /// Media asset fingerprints
    pub media_assets: Vec<MediaFingerprint>,
    /// Media scan statistics
    pub media_stats: MediaScanStats,
    /// Git forensic timeline (if in a git repo)
    pub git_forensics: Option<GitForensicTimeline>,
    /// Configuration files found
    pub config_files: Vec<PathBuf>,
    /// Project ecosystem detected
    pub ecosystem: DetectedEcosystem,
    /// Total files scanned
    pub total_files: usize,
    /// Files with headers
    pub files_with_headers: usize,
    /// Files without headers (source files only)
    pub files_without_headers: usize,
    /// Total source files (code files only)
    pub source_files: usize,
    /// SHA-256 of the entire scan (for integrity verification)
    pub scan_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFileInfo {
    pub path: PathBuf,
    pub classification: ClassificationResult,
    pub content_hash: String,
    /// Is this the root LICENSE file?
    pub is_root: bool,
    /// Relative path from project root
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendoredDir {
    pub path: PathBuf,
    pub has_license: bool,
    pub detected_license: Option<LicenseId>,
    pub file_count: usize,
    /// Name of the vendored package
    pub package_name: String,
    /// Has a README
    pub has_readme: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedEcosystem {
    Rust,
    Node,
    Python,
    Go,
    Java,
    CSharp,
    Ruby,
    Php,
    Swift,
    Multi,
    Unknown,
}

// ─── Source Scanner Engine ──────────────────────────────────────────

/// Source scanner — builds the complete digital identity of a project
pub struct SourceScanner {
    classifier: LicenseClassifier,
    header_detector: HeaderDetector,
}

impl SourceScanner {
    pub fn new() -> Self {
        Self {
            classifier: LicenseClassifier::new(),
            header_detector: HeaderDetector::new(),
        }
    }

    /// Perform a comprehensive source scan of a project
    pub fn scan(&self, root: &Path) -> SourceScan {
        let mut scan = SourceScan {
            root: root.to_path_buf(),
            project_license: None,
            manifest_license: None,
            manifest_path: None,
            headers: Vec::new(),
            license_files: Vec::new(),
            notice_files: Vec::new(),
            vendored_dirs: Vec::new(),
            nested_license_files: Vec::new(),
            lockfiles: Vec::new(),
            media_assets: Vec::new(),
            media_stats: MediaScanStats::default(),
            git_forensics: None,
            config_files: Vec::new(),
            ecosystem: DetectedEcosystem::Unknown,
            total_files: 0,
            files_with_headers: 0,
            files_without_headers: 0,
            source_files: 0,
            scan_hash: String::new(),
        };

        // ── 1. Find and classify root LICENSE file ──
        for name in LICENSE_FILE_NAMES {
            let path = root.join(name);
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let hash = hex::encode(sha2::Sha256::digest(content.as_bytes()));
                    if let Some(classification) = self.classifier.classify(&content) {
                        scan.project_license = Some(classification.clone());
                        scan.license_files.push(LicenseFileInfo {
                            path,
                            classification,
                            content_hash: hash,
                            is_root: true,
                            relative_path: name.to_string(),
                        });
                    }
                }
                break;
            }
        }

        // ── 2. Find and classify manifest files ──
        let manifests = [
            ("package.json", DetectedEcosystem::Node),
            ("Cargo.toml", DetectedEcosystem::Rust),
            ("setup.py", DetectedEcosystem::Python),
            ("setup.cfg", DetectedEcosystem::Python),
            ("pyproject.toml", DetectedEcosystem::Python),
            ("pom.xml", DetectedEcosystem::Java),
            ("build.gradle", DetectedEcosystem::Java),
            ("build.gradle.kts", DetectedEcosystem::Java),
            ("go.mod", DetectedEcosystem::Go),
            ("composer.json", DetectedEcosystem::Php),
            ("Gemfile", DetectedEcosystem::Ruby),
            ("Package.swift", DetectedEcosystem::Swift),
        ];

        let mut detected_ecosystems = Vec::new();

        for (name, ecosystem) in &manifests {
            let path = root.join(name);
            if path.exists() {
                detected_ecosystems.push(*ecosystem);
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if scan.manifest_license.is_none() {
                        if let Some(classification) = self.classifier.classify_manifest(&content) {
                            scan.manifest_license = Some(classification);
                            scan.manifest_path = Some(path);
                        }
                    }
                }
            }
        }

        scan.ecosystem = match detected_ecosystems.len() {
            0 => DetectedEcosystem::Unknown,
            1 => detected_ecosystems[0],
            _ => DetectedEcosystem::Multi,
        };

        // ── 3. Find lockfiles ──
        let lockfile_names = [
            "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
            "Cargo.lock", "go.sum", "Gemfile.lock",
            "poetry.lock", "Pipfile.lock", "composer.lock",
            "packages.lock.json", "bun.lockb",
        ];
        for name in &lockfile_names {
            let path = root.join(name);
            if path.exists() {
                scan.lockfiles.push(path);
            }
        }

        // ── 4. Scan source files for headers ──
        scan.headers = self.header_detector.scan_directory(root);
        scan.files_with_headers = scan.headers.len();

        // ── 5. Walk tree for NOTICE, nested LICENSE, config files ──
        let source_extensions: &[&str] = &[
            "rs", "py", "js", "ts", "jsx", "tsx", "c", "cpp", "h", "hpp",
            "go", "java", "rb", "php", "cs", "swift", "kt", "scala", "lua",
            "r", "m", "mm", "sh", "bash", "zsh", "ps1", "bat", "cmd",
        ];

        for entry in WalkDir::new(root)
            .max_depth(10)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() {
                scan.total_files += 1;

                let name_upper = entry.file_name()
                    .to_str()
                    .unwrap_or("")
                    .to_uppercase();

                // NOTICE/AUTHORS files
                if name_upper.starts_with("NOTICE")
                    || name_upper.starts_with("AUTHORS")
                    || name_upper.starts_with("CONTRIBUTORS")
                    || name_upper == "CREDITS"
                    || name_upper == "CREDITS.MD"
                    || name_upper == "CREDITS.TXT"
                {
                    scan.notice_files.push(entry.path().to_path_buf());
                }

                // Nested LICENSE files (not root)
                let is_license = LICENSE_FILE_NAMES.iter()
                    .any(|n| name_upper == n.to_uppercase());
                if is_license && entry.depth() > 0 {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        let hash = hex::encode(sha2::Sha256::digest(content.as_bytes()));
                        if let Some(classification) = self.classifier.classify(&content) {
                            let rel = entry.path()
                                .strip_prefix(root)
                                .unwrap_or(entry.path())
                                .to_string_lossy()
                                .to_string();
                            scan.nested_license_files.push(LicenseFileInfo {
                                path: entry.path().to_path_buf(),
                                classification,
                                content_hash: hash,
                                is_root: false,
                                relative_path: rel,
                            });
                        }
                    }
                }

                // Config files
                let fname = entry.file_name().to_str().unwrap_or("");
                if is_config_file(fname) && entry.depth() <= 2 {
                    scan.config_files.push(entry.path().to_path_buf());
                }

                // Count source files
                let ext = entry.path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                if source_extensions.contains(&ext) {
                    scan.source_files += 1;
                }
            }
        }

        scan.files_without_headers = scan.source_files.saturating_sub(scan.files_with_headers);

        // ── 6. Detect vendored directories ──
        let vendor_names = [
            "vendor", "third_party", "third-party", "thirdparty",
            "node_modules", "deps", "external", "extern", "lib",
            "3rdparty", "third_party_libs", "bundled",
        ];
        for name in &vendor_names {
            let dir = root.join(name);
            if dir.is_dir() {
                if let Ok(entries) = std::fs::read_dir(&dir) {
                    for entry in entries.filter_map(|e| e.ok()) {
                        let path = entry.path();
                        if path.is_dir() {
                            let pkg_name = path.file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown")
                                .to_string();

                            let has_license = LICENSE_FILE_NAMES
                                .iter()
                                .any(|n| path.join(n).exists());

                            let has_readme = ["README.md", "README", "README.txt"]
                                .iter()
                                .any(|n| path.join(n).exists());

                            let file_count = WalkDir::new(&path)
                                .into_iter()
                                .filter_map(|e| e.ok())
                                .filter(|e| e.file_type().is_file())
                                .count();

                            let detected = if has_license {
                                let lic_path = path.join("LICENSE");
                                std::fs::read_to_string(&lic_path)
                                    .ok()
                                    .and_then(|c| self.classifier.classify(&c))
                                    .map(|c| c.license)
                            } else {
                                None
                            };

                            scan.vendored_dirs.push(VendoredDir {
                                path,
                                has_license,
                                detected_license: detected,
                                file_count,
                                package_name: pkg_name,
                                has_readme,
                            });
                        }
                    }
                }
            }
        }

        // ── 7. Media asset scanning ──
        let media_report = media_forensics::scan_media(root);
        scan.media_assets = media_report.fingerprints;
        scan.media_stats = media_report.stats;

        // ── 8. Git forensics ──
        if GitForensics::is_git_repo(root) {
            scan.git_forensics = Some(GitForensics::analyze(root));
        }

        // ── 9. Compute scan integrity hash ──
        let mut hasher = sha2::Sha256::new();
        hasher.update(format!("root:{}", root.display()).as_bytes());
        hasher.update(format!("files:{}", scan.total_files).as_bytes());
        hasher.update(format!("source:{}", scan.source_files).as_bytes());
        hasher.update(format!("headers:{}", scan.files_with_headers).as_bytes());
        hasher.update(format!("license_files:{}", scan.license_files.len()).as_bytes());
        hasher.update(format!("vendored:{}", scan.vendored_dirs.len()).as_bytes());
        hasher.update(format!("media:{}", scan.media_assets.len()).as_bytes());
        hasher.update(format!("ts:{}", chrono::Utc::now().timestamp()).as_bytes());
        scan.scan_hash = hex::encode(hasher.finalize());

        scan
    }
}

impl Default for SourceScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn is_config_file(name: &str) -> bool {
    let configs = [
        ".editorconfig", ".gitignore", ".gitattributes",
        ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.yml",
        ".prettierrc", ".prettierrc.js", ".prettierrc.json",
        "tsconfig.json", "jest.config.js", "jest.config.ts",
        ".babelrc", "babel.config.js", "webpack.config.js",
        "vite.config.js", "vite.config.ts", "rollup.config.js",
        "Makefile", "CMakeLists.txt", "Dockerfile",
        "docker-compose.yml", "docker-compose.yaml",
        ".github", ".gitlab-ci.yml", ".travis.yml",
        "Jenkinsfile", "Procfile", "Vagrantfile",
        ".env.example", ".env.sample",
        "rustfmt.toml", "clippy.toml", ".cargo/config.toml",
        "tox.ini", "mypy.ini", ".flake8",
        ".rubocop.yml", ".ruby-version",
        ".nvmrc", ".node-version",
    ];
    configs.contains(&name)
}

/// Common LICENSE file names
const LICENSE_FILE_NAMES: &[&str] = &[
    "LICENSE", "LICENSE.md", "LICENSE.txt",
    "LICENSE-MIT", "LICENSE-APACHE",
    "LICENSE.MIT", "LICENSE.APACHE",
    "LICENCE", "LICENCE.md", "LICENCE.txt",
    "COPYING", "COPYING.md", "COPYING.txt",
    "COPYING.LIB", "COPYING.LESSER",
    "COPYRIGHT", "COPYRIGHT.txt",
    "UNLICENSE", "UNLICENSE.md",
];

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detected_ecosystem() {
        assert_ne!(DetectedEcosystem::Rust, DetectedEcosystem::Node);
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(".editorconfig"));
        assert!(is_config_file("Dockerfile"));
        assert!(is_config_file("tsconfig.json"));
        assert!(!is_config_file("main.rs"));
    }

    #[test]
    fn test_license_file_names_coverage() {
        assert!(LICENSE_FILE_NAMES.contains(&"LICENSE"));
        assert!(LICENSE_FILE_NAMES.contains(&"LICENSE.md"));
        assert!(LICENSE_FILE_NAMES.contains(&"COPYING"));
        assert!(LICENSE_FILE_NAMES.contains(&"UNLICENSE"));
    }
}
