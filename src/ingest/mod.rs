//! Universal ingestion layer — anything in, scannable content out
//!
//! Skera doesn't care what you give it. A URL, a Docker image, an APK,
//! a firmware blob, a git repo, raw bytes from stdin, even a screenshot.
//! The ingestion layer normalizes ALL inputs into a unified `ScanTarget`
//! that the detection pipeline can process.
//!
//! ## Architecture
//!
//! ```text
//!                    ┌─────────────────────────────┐
//!                    │     Universal Ingestion      │
//!                    │                              │
//!  URL ──────────┐   │  ┌─────────┐  ┌──────────┐  │
//!  File ─────────┤   │  │  Type   │  │ Content  │  │
//!  Docker ───────┤   │  │Detector │→ │Extractor │  │
//!  APK ──────────┤──→│  └─────────┘  └────┬─────┘  │
//!  Git Repo ─────┤   │                    │         │
//!  Stdin ────────┤   │  ┌─────────────────▼──────┐  │
//!  Screenshot ───┘   │  │   Normalized Content   │  │
//!                    │  │  (files + metadata)     │  │
//!                    │  └────────────────────────┘  │
//!                    └─────────────────────────────┘
//!                                 │
//!                                 ▼
//!                    ┌──────────────────────┐
//!                    │  Detection Pipeline  │
//!                    └──────────────────────┘
//! ```

pub mod detector;
pub mod web_crawler;
pub mod docker;
pub mod mobile;
pub mod electron;
pub mod git_repo;
pub mod archive;
pub mod binary;
pub mod wasm;
pub mod stdin;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Input Specification ───────────────────────────────────────────

/// Anything Skera can accept as input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputSpec {
    /// Local file or directory
    LocalPath(PathBuf),

    /// Live website URL — crawl and download all assets
    WebsiteUrl(String),

    /// Single file URL — download just the file
    FileUrl(String),

    /// Git repository URL — clone and scan with history
    GitRepo {
        url: String,
        branch: Option<String>,
        depth: Option<u32>,
    },

    /// Docker image reference — pull, extract layers, scan
    DockerImage(String),

    /// Android APK file
    AndroidApk(PathBuf),

    /// iOS IPA file
    IosIpa(PathBuf),

    /// Electron app (ASAR archive or app directory)
    ElectronApp(PathBuf),

    /// WASM module
    WasmModule(PathBuf),

    /// Archive (ZIP, TAR, RAR, 7z, etc.)
    Archive(PathBuf),

    /// Firmware blob
    Firmware(PathBuf),

    /// Raw content from stdin
    Stdin {
        content: String,
        filename_hint: Option<String>,
    },

    /// Package from a registry (npm, pypi, crates.io, etc.)
    Package(crate::audit::PackageSpec),
}

impl InputSpec {
    /// Auto-detect the input type from a string argument
    ///
    /// This is the smartest parser — it figures out what you mean:
    /// - `/path/to/file.js` → LocalPath
    /// - `https://example.com` → WebsiteUrl
    /// - `https://cdn.example.com/bundle.min.js` → FileUrl
    /// - `https://github.com/user/repo` → GitRepo  
    /// - `docker:image:tag` → DockerImage
    /// - `npm:lodash@4.17.21` → Package
    /// - `-` → Stdin
    pub fn auto_detect(input: &str) -> Result<Self, String> {
        let input = input.trim();

        // Stdin
        if input == "-" {
            return Ok(Self::Stdin {
                content: String::new(),
                filename_hint: None,
            });
        }

        // Package specs (npm:, pypi:, crate:, crx:)
        if let Some(prefix) = input.split(':').next() {
            if matches!(prefix, "npm" | "pypi" | "pip" | "crate" | "cargo" | "crx" | "chrome" | "extension") {
                return Ok(Self::Package(crate::audit::PackageSpec::parse(input)?));
            }
        }

        // Docker image
        if input.starts_with("docker:") {
            return Ok(Self::DockerImage(input.trim_start_matches("docker:").to_string()));
        }

        // URLs
        if input.starts_with("http://") || input.starts_with("https://") {
            return Self::classify_url(input);
        }

        // Git SSH URLs
        if input.starts_with("git@") || input.ends_with(".git") {
            return Ok(Self::GitRepo {
                url: input.to_string(),
                branch: None,
                depth: None,
            });
        }

        // Local path
        let path = PathBuf::from(input);

        // Check file extension for specific types
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                "apk" => return Ok(Self::AndroidApk(path)),
                "ipa" => return Ok(Self::IosIpa(path)),
                "asar" => return Ok(Self::ElectronApp(path)),
                "wasm" => return Ok(Self::WasmModule(path)),
                "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "7z" | "rar" =>
                    return Ok(Self::Archive(path)),
                "bin" | "fw" | "img" | "rom" =>
                    return Ok(Self::Firmware(path)),
                _ => {}
            }
        }

        Ok(Self::LocalPath(path))
    }

    /// Classify a URL into the right input type
    fn classify_url(url: &str) -> Result<Self, String> {
        let lower = url.to_lowercase();

        // GitHub/GitLab/Bitbucket repos
        if (lower.contains("github.com") || lower.contains("gitlab.com") || lower.contains("bitbucket.org"))
            && !lower.contains("/raw/")
            && !lower.contains("/blob/")
            && !lower.ends_with(".js")
            && !lower.ends_with(".css")
        {
            // Count path segments after the domain
            // github.com/user/repo → 2 segments = repo
            // github.com/user/repo/tree/main/src → more segments = specific path
            let path_part = if let Some(idx) = url.find("github.com/") {
                &url[idx + "github.com/".len()..]
            } else if let Some(idx) = url.find("gitlab.com/") {
                &url[idx + "gitlab.com/".len()..]
            } else {
                url
            };

            let segments: Vec<&str> = path_part.split('/').filter(|s| !s.is_empty()).collect();
            if segments.len() <= 2 {
                // This is a repo root
                return Ok(Self::GitRepo {
                    url: url.to_string(),
                    branch: None,
                    depth: Some(1), // shallow clone for scanning
                });
            }
        }

        // Direct file URLs (end with a file extension)
        let path_part = url.split('?').next().unwrap_or(url);
        if let Some(ext) = path_part.rsplit('.').next() {
            let ext_lower = ext.to_lowercase();
            if matches!(
                ext_lower.as_str(),
                "js" | "mjs" | "cjs" | "css" | "ts" | "tsx" | "jsx"
                | "py" | "rs" | "go" | "java" | "c" | "cpp" | "h"
                | "rb" | "php" | "swift" | "kt"
                | "json" | "toml" | "yaml" | "yml" | "xml"
                | "wasm" | "map"
                | "zip" | "tar" | "gz" | "tgz"
                | "apk" | "ipa"
            ) {
                return Ok(Self::FileUrl(url.to_string()));
            }
        }

        // Default: treat as a website to crawl
        Ok(Self::WebsiteUrl(url.to_string()))
    }

    /// Human-readable description of the input
    pub fn description(&self) -> String {
        match self {
            Self::LocalPath(p) => format!("Local: {}", p.display()),
            Self::WebsiteUrl(u) => format!("Website: {}", u),
            Self::FileUrl(u) => format!("File: {}", u),
            Self::GitRepo { url, branch, .. } => {
                format!("Git: {}{}", url, branch.as_ref().map(|b| format!(" ({})", b)).unwrap_or_default())
            }
            Self::DockerImage(i) => format!("Docker: {}", i),
            Self::AndroidApk(p) => format!("APK: {}", p.display()),
            Self::IosIpa(p) => format!("IPA: {}", p.display()),
            Self::ElectronApp(p) => format!("Electron: {}", p.display()),
            Self::WasmModule(p) => format!("WASM: {}", p.display()),
            Self::Archive(p) => format!("Archive: {}", p.display()),
            Self::Firmware(p) => format!("Firmware: {}", p.display()),
            Self::Stdin { filename_hint, .. } => {
                format!("Stdin{}", filename_hint.as_ref().map(|f| format!(" ({})", f)).unwrap_or_default())
            }
            Self::Package(spec) => format!("Package: {}", spec.display_name()),
        }
    }
}

// ─── Normalized Output ─────────────────────────────────────────────

/// The normalized output of ingestion — ready for the detection pipeline
#[derive(Debug, Clone)]
pub struct IngestedContent {
    /// A description of what was ingested
    pub source_description: String,
    /// The input that was ingested
    pub input: InputSpec,
    /// Directory containing extracted/downloaded content
    pub content_dir: PathBuf,
    /// Metadata about the ingested content
    pub metadata: IngestMetadata,
}

/// Metadata about ingested content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestMetadata {
    /// Total files extracted
    pub total_files: usize,
    /// Total bytes
    pub total_bytes: u64,
    /// Content types found
    pub content_types: Vec<String>,
    /// Whether the content was obfuscated/minified
    pub obfuscation_detected: bool,
    /// Source type
    pub source_type: String,
    /// Whether git history is available
    pub has_git_history: bool,
    /// Manifest files found (package.json, Cargo.toml, setup.py, etc.)
    pub manifest_files: Vec<String>,
}

// ─── The Universal Ingestor ────────────────────────────────────────

/// The universal content ingestor
pub struct Ingestor;

impl Ingestor {
    /// Ingest any input — auto-detects type, extracts content, normalizes
    pub async fn ingest(input: InputSpec) -> Result<IngestedContent, String> {
        let source_description = input.description();

        match input {
            InputSpec::LocalPath(ref path) => {
                if !path.exists() {
                    return Err(format!("Path does not exist: {}", path.display()));
                }
                let has_git = path.join(".git").exists();
                let manifests = detect_manifests(path);
                let content_dir = path.clone();
                Ok(IngestedContent {
                    source_description,
                    content_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 0,
                        total_bytes: 0,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "local".to_string(),
                        has_git_history: has_git,
                        manifest_files: manifests,
                    },
                })
            }

            InputSpec::WebsiteUrl(ref url) => {
                let result = web_crawler::crawl(url).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.output_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.files_downloaded,
                        total_bytes: result.total_bytes,
                        content_types: result.content_types,
                        obfuscation_detected: false,
                        source_type: "website".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::GitRepo { ref url, ref branch, depth } => {
                let result = git_repo::clone_and_prepare(url, branch.as_deref(), depth).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.repo_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 0,
                        total_bytes: 0,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "git".to_string(),
                        has_git_history: true,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::DockerImage(ref image) => {
                let result = docker::extract_image(image).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "docker".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::AndroidApk(ref path) => {
                let result = mobile::extract_apk(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: result.content_types,
                        obfuscation_detected: false,
                        source_type: "android".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::IosIpa(ref path) => {
                let result = mobile::extract_ipa(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: result.content_types,
                        obfuscation_detected: false,
                        source_type: "ios".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::ElectronApp(ref path) => {
                let result = electron::extract_asar(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "electron".to_string(),
                        has_git_history: false,
                        manifest_files: result.manifest_files,
                    },
                })
            }

            InputSpec::Archive(ref path) => {
                let result = archive::extract(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "archive".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::WasmModule(ref path) => {
                let result = wasm::decompile(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.output_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 1,
                        total_bytes: result.total_bytes,
                        content_types: vec!["application/wasm".to_string()],
                        obfuscation_detected: false,
                        source_type: "wasm".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::Firmware(ref path) => {
                let result = archive::extract_firmware(path).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.extract_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: result.total_files,
                        total_bytes: result.total_bytes,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "firmware".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::Stdin { ref content, ref filename_hint } => {
                let result = stdin::buffer_stdin(content, filename_hint.as_deref()).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: result.output_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 1,
                        total_bytes: result.total_bytes,
                        content_types: vec![result.detected_language],
                        obfuscation_detected: false,
                        source_type: "stdin".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::FileUrl(ref url) => {
                let fetch_result = crate::audit::url_fetcher::fetch(url).await?;
                Ok(IngestedContent {
                    source_description,
                    content_dir: fetch_result.unpacked_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 1,
                        total_bytes: 0,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: "url".to_string(),
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }

            InputSpec::Package(ref spec) => {
                let fetch_result = match spec {
                    crate::audit::PackageSpec::Npm { name, version } =>
                        crate::audit::npm::fetch(name, version.as_deref()).await?,
                    crate::audit::PackageSpec::PyPi { name, version } =>
                        crate::audit::pypi::fetch(name, version.as_deref()).await?,
                    crate::audit::PackageSpec::CratesIo { name, version } =>
                        crate::audit::crates_io::fetch(name, version.as_deref()).await?,
                    crate::audit::PackageSpec::ChromeExtension { id } =>
                        crate::audit::crx::fetch(id).await?,
                    crate::audit::PackageSpec::Url { url } =>
                        crate::audit::url_fetcher::fetch(url).await?,
                };
                let source = fetch_result.source.clone();
                Ok(IngestedContent {
                    source_description,
                    content_dir: fetch_result.unpacked_dir,
                    input,
                    metadata: IngestMetadata {
                        total_files: 0,
                        total_bytes: 0,
                        content_types: Vec::new(),
                        obfuscation_detected: false,
                        source_type: source,
                        has_git_history: false,
                        manifest_files: Vec::new(),
                    },
                })
            }
        }
    }
}

/// Detect common manifest files in a directory
fn detect_manifests(dir: &std::path::Path) -> Vec<String> {
    let manifest_names = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Cargo.toml",
        "Cargo.lock",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "requirements.txt",
        "Pipfile",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "mix.exs",
        "pubspec.yaml",
        "*.csproj",
        "*.sln",
        "Makefile",
        "CMakeLists.txt",
        "manifest.json",  // Chrome extensions
        "Info.plist",      // iOS
        "AndroidManifest.xml", // Android
    ];

    let mut found = Vec::new();
    for name in &manifest_names {
        if name.starts_with('*') {
            // Glob pattern — skip for now (would need walkdir)
            continue;
        }
        if dir.join(name).exists() {
            found.push(name.to_string());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_detect_local_path() {
        let input = InputSpec::auto_detect("./src/main.rs").unwrap();
        assert!(matches!(input, InputSpec::LocalPath(_)));
    }

    #[test]
    fn test_auto_detect_npm_package() {
        let input = InputSpec::auto_detect("npm:lodash@4.17.21").unwrap();
        assert!(matches!(input, InputSpec::Package(_)));
    }

    #[test]
    fn test_auto_detect_github_repo() {
        let input = InputSpec::auto_detect("https://github.com/user/repo").unwrap();
        assert!(matches!(input, InputSpec::GitRepo { .. }));
    }

    #[test]
    fn test_auto_detect_website() {
        let input = InputSpec::auto_detect("https://example.com").unwrap();
        assert!(matches!(input, InputSpec::WebsiteUrl(_)));
    }

    #[test]
    fn test_auto_detect_js_url() {
        let input = InputSpec::auto_detect("https://cdn.example.com/bundle.min.js").unwrap();
        assert!(matches!(input, InputSpec::FileUrl(_)));
    }

    #[test]
    fn test_auto_detect_docker() {
        let input = InputSpec::auto_detect("docker:nginx:latest").unwrap();
        assert!(matches!(input, InputSpec::DockerImage(_)));
    }

    #[test]
    fn test_auto_detect_apk() {
        let input = InputSpec::auto_detect("app.apk").unwrap();
        assert!(matches!(input, InputSpec::AndroidApk(_)));
    }

    #[test]
    fn test_auto_detect_wasm() {
        let input = InputSpec::auto_detect("module.wasm").unwrap();
        assert!(matches!(input, InputSpec::WasmModule(_)));
    }

    #[test]
    fn test_auto_detect_stdin() {
        let input = InputSpec::auto_detect("-").unwrap();
        assert!(matches!(input, InputSpec::Stdin { .. }));
    }

    #[test]
    fn test_auto_detect_git_ssh() {
        let input = InputSpec::auto_detect("git@github.com:user/repo.git").unwrap();
        assert!(matches!(input, InputSpec::GitRepo { .. }));
    }

    #[test]
    fn test_auto_detect_archive() {
        let input = InputSpec::auto_detect("data.tar.gz").unwrap();
        assert!(matches!(input, InputSpec::Archive(_)));
    }

    #[test]
    fn test_auto_detect_electron() {
        let input = InputSpec::auto_detect("app.asar").unwrap();
        assert!(matches!(input, InputSpec::ElectronApp(_)));
    }

    #[test]
    fn test_auto_detect_crx() {
        let input = InputSpec::auto_detect("crx:joflmkccibkooplaeoineiojhgdpnkep").unwrap();
        assert!(matches!(input, InputSpec::Package(_)));
    }
}
