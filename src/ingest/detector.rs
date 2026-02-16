//! Input type detector — identifies content type from magic bytes, headers, metadata
//!
//! Used internally by the ingestor to make smart decisions about content extraction.

/// Detected content type from magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    JavaScript,
    TypeScript,
    Css,
    Html,
    Json,
    Toml,
    Yaml,
    Xml,
    Python,
    Rust,
    Go,
    Java,
    CSource,
    CppSource,
    Ruby,
    Php,
    Swift,
    Kotlin,
    Zip,
    Tar,
    Gzip,
    SevenZip,
    Rar,
    Pdf,
    Png,
    Jpeg,
    Gif,
    Webp,
    Svg,
    Wasm,
    Elf,
    Pe,
    MachO,
    Apk,
    Asar,
    Crx,
    Deb,
    Rpm,
    Dmg,
    Unknown,
}

impl ContentType {
    /// Detect content type from magic bytes
    pub fn from_magic_bytes(bytes: &[u8]) -> Self {
        if bytes.len() < 4 {
            return Self::Unknown;
        }

        match &bytes[..4] {
            // Archives
            [0x50, 0x4B, 0x03, 0x04] => {
                // ZIP — could be APK, CRX, ASAR, or plain ZIP
                // Check for APK-specific content
                Self::Zip
            }
            [0x1F, 0x8B, _, _] => Self::Gzip,
            [0x37, 0x7A, 0xBC, 0xAF] => Self::SevenZip,
            [0x52, 0x61, 0x72, 0x21] => Self::Rar,

            // Binary formats
            [0x7F, 0x45, 0x4C, 0x46] => Self::Elf,     // ELF
            [0x4D, 0x5A, _, _] => Self::Pe,              // PE (Windows EXE/DLL)
            [0xFE, 0xED, 0xFA, 0xCE] |
            [0xFE, 0xED, 0xFA, 0xCF] |
            [0xCE, 0xFA, 0xED, 0xFE] |
            [0xCF, 0xFA, 0xED, 0xFE] => Self::MachO,    // Mach-O

            // WASM
            [0x00, 0x61, 0x73, 0x6D] => Self::Wasm,     // \0asm

            // Images
            [0x89, 0x50, 0x4E, 0x47] => Self::Png,      // PNG
            [0xFF, 0xD8, 0xFF, _] => Self::Jpeg,         // JPEG
            [0x47, 0x49, 0x46, 0x38] => Self::Gif,       // GIF
            [0x52, 0x49, 0x46, 0x46] => Self::Webp,      // RIFF (WebP)

            // PDF
            [0x25, 0x50, 0x44, 0x46] => Self::Pdf,       // %PDF

            // CRX (Chrome extension)
            [0x43, 0x72, 0x32, 0x34] |                   // Cr24 (CRX2)
            [0x43, 0x72, 0x78, 0x33] => Self::Crx,       // Crx3

            // Debian package
            [0x21, 0x3C, 0x61, 0x72] => Self::Deb,       // !<ar

            // Tar (check for ustar at offset 257)
            _ => {
                if bytes.len() > 261 && &bytes[257..262] == b"ustar" {
                    Self::Tar
                } else {
                    Self::Unknown
                }
            }
        }
    }

    /// Detect content type from file extension
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "js" | "mjs" | "cjs" => Self::JavaScript,
            "ts" | "tsx" | "mts" => Self::TypeScript,
            "css" | "scss" | "sass" | "less" => Self::Css,
            "html" | "htm" => Self::Html,
            "json" => Self::Json,
            "toml" => Self::Toml,
            "yaml" | "yml" => Self::Yaml,
            "xml" => Self::Xml,
            "py" | "pyw" | "pyi" => Self::Python,
            "rs" => Self::Rust,
            "go" => Self::Go,
            "java" => Self::Java,
            "c" | "h" => Self::CSource,
            "cpp" | "cc" | "cxx" | "hpp" | "hxx" => Self::CppSource,
            "rb" | "rake" => Self::Ruby,
            "php" => Self::Php,
            "swift" => Self::Swift,
            "kt" | "kts" => Self::Kotlin,
            "zip" => Self::Zip,
            "tar" => Self::Tar,
            "gz" | "tgz" => Self::Gzip,
            "7z" => Self::SevenZip,
            "rar" => Self::Rar,
            "pdf" => Self::Pdf,
            "png" => Self::Png,
            "jpg" | "jpeg" => Self::Jpeg,
            "gif" => Self::Gif,
            "webp" => Self::Webp,
            "svg" => Self::Svg,
            "wasm" => Self::Wasm,
            "exe" | "dll" | "sys" => Self::Pe,
            "so" | "o" => Self::Elf,
            "dylib" => Self::MachO,
            "apk" => Self::Apk,
            "asar" => Self::Asar,
            "crx" => Self::Crx,
            "deb" => Self::Deb,
            "rpm" => Self::Rpm,
            "dmg" => Self::Dmg,
            _ => Self::Unknown,
        }
    }

    /// Is this a text/source file?
    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Self::JavaScript | Self::TypeScript | Self::Css | Self::Html
            | Self::Json | Self::Toml | Self::Yaml | Self::Xml
            | Self::Python | Self::Rust | Self::Go | Self::Java
            | Self::CSource | Self::CppSource | Self::Ruby | Self::Php
            | Self::Swift | Self::Kotlin | Self::Svg
        )
    }

    /// Is this a binary/compiled file?
    pub fn is_binary(&self) -> bool {
        matches!(self, Self::Elf | Self::Pe | Self::MachO | Self::Wasm)
    }

    /// Is this an archive?
    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            Self::Zip | Self::Tar | Self::Gzip | Self::SevenZip | Self::Rar
            | Self::Apk | Self::Asar | Self::Crx | Self::Deb | Self::Rpm
        )
    }
}
