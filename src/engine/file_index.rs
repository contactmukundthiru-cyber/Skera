//! Single-pass file indexing — walk once, serve many phases
//!
//! Instead of each detection phase calling `WalkDir::new()` independently
//! (6+ redundant tree walks in the original engine), FileIndex walks once
//! and classifies every file by extension, size, and type.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A single indexed file with pre-computed metadata
#[derive(Debug, Clone)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub extension: String,
    pub size: u64,
}

/// File classification for quick phase dispatch
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileCategory {
    SourceCode,
    JavaScript,
    TypeScript,
    LicenseFile,
    ManifestFile,
    BinaryExecutable,
    Font,
    Image,
    Audio,
    Video,
    Document,
    WebAsset,
    Config,
    Archive,
    Other,
}

/// Pre-built index of all files in a scan target — built once, shared by all phases
#[derive(Debug, Clone)]
pub struct FileIndex {
    pub files: Vec<IndexedFile>,
    pub by_category: HashMap<FileCategory, Vec<usize>>,
    pub by_extension: HashMap<String, Vec<usize>>,
    pub total_bytes: u64,
    pub root: PathBuf,
}

impl FileIndex {
    /// Walk the directory tree once and build the complete index
    pub fn build(root: &Path) -> Self {
        let mut files = Vec::new();
        let mut total_bytes = 0u64;

        for entry in WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let ext = entry
                .path()
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            total_bytes += size;
            files.push(IndexedFile {
                path: entry.path().to_path_buf(),
                extension: ext,
                size,
            });
        }

        // Build category + extension indices
        let mut by_category: HashMap<FileCategory, Vec<usize>> = HashMap::new();
        let mut by_extension: HashMap<String, Vec<usize>> = HashMap::new();

        for (idx, file) in files.iter().enumerate() {
            let cat = classify(&file.extension, &file.path);
            by_category.entry(cat).or_default().push(idx);
            if !file.extension.is_empty() {
                by_extension
                    .entry(file.extension.clone())
                    .or_default()
                    .push(idx);
            }
        }

        tracing::info!(
            "FileIndex: {} files, {:.1} MB across {} categories",
            files.len(),
            total_bytes as f64 / 1_048_576.0,
            by_category.len()
        );

        Self {
            files,
            by_category,
            by_extension,
            total_bytes,
            root: root.to_path_buf(),
        }
    }

    /// Get all files in a category
    pub fn category(&self, cat: FileCategory) -> Vec<&IndexedFile> {
        self.by_category
            .get(&cat)
            .map(|ids| ids.iter().map(|&i| &self.files[i]).collect())
            .unwrap_or_default()
    }

    /// Get files matching any of the given extensions
    pub fn extensions(&self, exts: &[&str]) -> Vec<&IndexedFile> {
        exts.iter()
            .flat_map(|ext| {
                self.by_extension
                    .get(&ext.to_lowercase())
                    .map(|ids| ids.iter().map(|&i| &self.files[i]).collect::<Vec<_>>())
                    .unwrap_or_default()
            })
            .collect()
    }

    /// All source code files (including JS/TS)
    pub fn source_code(&self) -> Vec<&IndexedFile> {
        let mut r = self.category(FileCategory::SourceCode);
        r.extend(self.category(FileCategory::JavaScript));
        r.extend(self.category(FileCategory::TypeScript));
        r
    }

    /// All JS/TS files
    pub fn js_ts(&self) -> Vec<&IndexedFile> {
        let mut r = self.category(FileCategory::JavaScript);
        r.extend(self.category(FileCategory::TypeScript));
        r
    }

    /// JS files above a minimum size (for bundle analysis)
    pub fn large_js(&self, min_bytes: u64) -> Vec<&IndexedFile> {
        self.category(FileCategory::JavaScript)
            .into_iter()
            .filter(|f| f.size >= min_bytes)
            .collect()
    }

    /// Source files suitable for fingerprinting (>200 bytes, known code extensions)
    pub fn fingerprintable(&self) -> Vec<&IndexedFile> {
        self.source_code()
            .into_iter()
            .filter(|f| {
                f.size > 200
                    && matches!(
                        f.extension.as_str(),
                        "rs" | "py" | "js" | "ts" | "c" | "cpp" | "h" | "go" | "java" | "rb"
                    )
            })
            .collect()
    }

    /// Source files suitable for cross-language provenance (>500 bytes)
    pub fn provenance_candidates(&self) -> Vec<&IndexedFile> {
        self.source_code()
            .into_iter()
            .filter(|f| {
                f.size > 500
                    && matches!(
                        f.extension.as_str(),
                        "rs" | "go" | "ts" | "java" | "py" | "c" | "cpp" | "h" | "rb"
                    )
            })
            .collect()
    }

    /// License/notice files (max depth 3 from root)
    pub fn license_files(&self) -> Vec<&IndexedFile> {
        self.files
            .iter()
            .filter(|f| {
                let name = f
                    .path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_uppercase();
                (name.contains("LICENSE")
                    || name.contains("LICENCE")
                    || name.contains("COPYING")
                    || name.contains("NOTICE"))
                    && f.path
                        .strip_prefix(&self.root)
                        .map(|rel| rel.components().count() <= 3)
                        .unwrap_or(false)
            })
            .collect()
    }

    /// JS/TS files >2000 bytes (for JS analysis / entropy scanning)
    pub fn js_analysis_candidates(&self) -> Vec<&IndexedFile> {
        self.js_ts()
            .into_iter()
            .filter(|f| f.size > 2000)
            .collect()
    }

    pub fn total_files(&self) -> usize {
        self.files.len()
    }
}

fn classify(ext: &str, path: &Path) -> FileCategory {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_uppercase();

    if filename.contains("LICENSE")
        || filename.contains("LICENCE")
        || filename.contains("COPYING")
        || filename.contains("NOTICE")
    {
        return FileCategory::LicenseFile;
    }

    let is_manifest = matches!(
        filename.as_str(),
        "PACKAGE.JSON"
            | "CARGO.TOML"
            | "GO.MOD"
            | "REQUIREMENTS.TXT"
            | "SETUP.PY"
            | "PYPROJECT.TOML"
            | "GEMFILE"
            | "POM.XML"
            | "BUILD.GRADLE"
            | "PACKAGE-LOCK.JSON"
            | "YARN.LOCK"
            | "CARGO.LOCK"
            | "GO.SUM"
            | "PIPFILE"
            | "PIPFILE.LOCK"
            | "COMPOSER.JSON"
            | "COMPOSER.LOCK"
    );
    if is_manifest {
        return FileCategory::ManifestFile;
    }

    match ext {
        "js" | "mjs" | "cjs" => FileCategory::JavaScript,
        "ts" | "tsx" | "mts" => FileCategory::TypeScript,
        "rs" | "py" | "go" | "c" | "cpp" | "h" | "hpp" | "java" | "rb" | "swift" | "kt"
        | "scala" | "cs" | "php" | "sol" => FileCategory::SourceCode,
        "exe" | "dll" | "so" | "dylib" | "o" | "a" | "wasm" => FileCategory::BinaryExecutable,
        "ttf" | "otf" | "woff" | "woff2" | "eot" => FileCategory::Font,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "svg" | "webp" | "ico" | "tiff" => {
            FileCategory::Image
        }
        "mp3" | "wav" | "flac" | "ogg" | "aac" | "m4a" => FileCategory::Audio,
        "mp4" | "avi" | "mkv" | "mov" | "webm" | "wmv" => FileCategory::Video,
        "pdf" | "doc" | "docx" | "xls" | "xlsx" => FileCategory::Document,
        "html" | "htm" | "css" | "scss" | "less" | "sass" => FileCategory::WebAsset,
        "json" | "yaml" | "yml" | "toml" | "ini" | "cfg" | "xml" => FileCategory::Config,
        "zip" | "tar" | "gz" | "bz2" | "xz" | "7z" | "rar" => FileCategory::Archive,
        _ => FileCategory::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_file_index_classification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("app.js"), "console.log('hi')").unwrap();
        fs::write(dir.path().join("LICENSE"), "MIT License").unwrap();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        fs::create_dir_all(dir.path().join("assets")).unwrap();
        fs::write(dir.path().join("assets/logo.png"), &[0u8; 100]).unwrap();

        let idx = FileIndex::build(dir.path());
        assert_eq!(idx.total_files(), 5);
        assert_eq!(idx.category(FileCategory::SourceCode).len(), 1);
        assert_eq!(idx.category(FileCategory::JavaScript).len(), 1);
        assert_eq!(idx.category(FileCategory::LicenseFile).len(), 1);
        assert_eq!(idx.category(FileCategory::ManifestFile).len(), 1);
        assert_eq!(idx.category(FileCategory::Image).len(), 1);
    }

    #[test]
    fn test_source_code_aggregation() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("app.js"), "x").unwrap();
        fs::write(dir.path().join("index.ts"), "x").unwrap();

        let idx = FileIndex::build(dir.path());
        assert_eq!(idx.source_code().len(), 3);
        assert_eq!(idx.js_ts().len(), 2);
    }
}
