//! Internet-scale package auditing — fetch and scan any package from any registry
//!
//! The differentiator. `skera audit npm:lodash@4.17.21` downloads the package
//! from its registry, unpacks it, and runs the full Skera detection pipeline.
//!
//! ## Supported Package Sources
//!
//! - **npm**: `npm:package@version` — downloads from registry.npmjs.org
//! - **PyPI**: `pypi:package@version` — downloads from pypi.org
//! - **crates.io**: `crate:package@version` — downloads from crates.io
//! - **Chrome Web Store**: `crx:extension-id` — downloads .crx from CWS
//! - **URL**: `url:https://example.com/file.js` — arbitrary URL download
//!
//! ## Architecture
//!
//! Each fetcher downloads the package to a temp directory, unpacks it,
//! and returns the path for Skera to scan normally.

pub mod npm;
pub mod pypi;
pub mod crates_io;
pub mod crx;
pub mod url_fetcher;

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// A package specifier parsed from the CLI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PackageSpec {
    /// npm:package@version
    Npm { name: String, version: Option<String> },
    /// pypi:package@version
    PyPi { name: String, version: Option<String> },
    /// crate:package@version
    CratesIo { name: String, version: Option<String> },
    /// crx:extension-id
    ChromeExtension { id: String },
    /// url:https://...
    Url { url: String },
}

impl PackageSpec {
    /// Parse a package specifier string like "npm:lodash@4.17.21"
    pub fn parse(spec: &str) -> Result<Self, String> {
        let (prefix, rest) = spec
            .split_once(':')
            .ok_or_else(|| format!("Invalid package spec '{}' — expected format: npm:package@version", spec))?;

        match prefix {
            "npm" => {
                let (name, version) = parse_name_version(rest);
                Ok(Self::Npm { name, version })
            }
            "pypi" | "pip" => {
                let (name, version) = parse_name_version(rest);
                Ok(Self::PyPi { name, version })
            }
            "crate" | "cargo" => {
                let (name, version) = parse_name_version(rest);
                Ok(Self::CratesIo { name, version })
            }
            "crx" | "chrome" | "extension" => {
                Ok(Self::ChromeExtension { id: rest.to_string() })
            }
            "url" | "http" | "https" => {
                let url = if prefix == "url" {
                    rest.to_string()
                } else {
                    // Reconstruct: "https:..." → "https://..."
                    format!("{}:{}", prefix, rest)
                };
                Ok(Self::Url { url })
            }
            _ => Err(format!("Unknown package source '{}' — supported: npm, pypi, crate, crx, url", prefix)),
        }
    }

    /// Human-readable display name
    pub fn display_name(&self) -> String {
        match self {
            Self::Npm { name, version } => format!("npm:{}{}", name, version.as_ref().map(|v| format!("@{}", v)).unwrap_or_default()),
            Self::PyPi { name, version } => format!("pypi:{}{}", name, version.as_ref().map(|v| format!("@{}", v)).unwrap_or_default()),
            Self::CratesIo { name, version } => format!("crate:{}{}", name, version.as_ref().map(|v| format!("@{}", v)).unwrap_or_default()),
            Self::ChromeExtension { id } => format!("crx:{}", id),
            Self::Url { url } => format!("url:{}", url),
        }
    }
}

/// Result of fetching a package
#[derive(Debug)]
pub struct FetchResult {
    /// Where the unpacked files are
    pub unpacked_dir: PathBuf,
    /// Package name
    pub name: String,
    /// Package version
    pub version: Option<String>,
    /// Registry source
    pub source: String,
    /// Temp directory handle (cleanup on drop)
    pub _temp_dir: tempfile::TempDir,
}

/// Parse "name@version" → (name, Some(version)) or (name, None)
fn parse_name_version(s: &str) -> (String, Option<String>) {
    if let Some(at_pos) = s.rfind('@') {
        if at_pos > 0 {
            let name = s[..at_pos].to_string();
            let version = s[at_pos + 1..].to_string();
            if !version.is_empty() {
                return (name, Some(version));
            }
        }
    }
    (s.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_npm() {
        let spec = PackageSpec::parse("npm:lodash@4.17.21").unwrap();
        match spec {
            PackageSpec::Npm { name, version } => {
                assert_eq!(name, "lodash");
                assert_eq!(version, Some("4.17.21".to_string()));
            }
            _ => panic!("Expected npm package spec"),
        }
    }

    #[test]
    fn test_parse_npm_no_version() {
        let spec = PackageSpec::parse("npm:react").unwrap();
        match spec {
            PackageSpec::Npm { name, version } => {
                assert_eq!(name, "react");
                assert_eq!(version, None);
            }
            _ => panic!("Expected npm package spec"),
        }
    }

    #[test]
    fn test_parse_scoped_npm() {
        let spec = PackageSpec::parse("npm:@babel/core@7.24.0").unwrap();
        match spec {
            PackageSpec::Npm { name, version } => {
                assert_eq!(name, "@babel/core");
                assert_eq!(version, Some("7.24.0".to_string()));
            }
            _ => panic!("Expected npm package spec"),
        }
    }

    #[test]
    fn test_parse_crx() {
        let spec = PackageSpec::parse("crx:joflmkccibkooplaeoineiojhgdpnkep").unwrap();
        match spec {
            PackageSpec::ChromeExtension { id } => {
                assert_eq!(id, "joflmkccibkooplaeoineiojhgdpnkep");
            }
            _ => panic!("Expected chrome extension spec"),
        }
    }

    #[test]
    fn test_parse_url() {
        let spec = PackageSpec::parse("url:https://cdn.jquery.com/jquery-3.7.1.min.js").unwrap();
        match spec {
            PackageSpec::Url { url } => {
                assert_eq!(url, "https://cdn.jquery.com/jquery-3.7.1.min.js");
            }
            _ => panic!("Expected URL spec"),
        }
    }
}
