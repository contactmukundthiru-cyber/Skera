//! WebAssembly binary forensics — extract dependencies, strings, and license
//! violations from compiled WASM binaries.
//!
//! ## Why This Matters
//!
//! Companies hide code in WASM to avoid audit. Go binaries compiled to WASM
//! retain function names, package paths, and string tables because the Go
//! runtime needs them for reflection and garbage collection. This module
//! extracts that metadata and cross-references it against known license
//! obligations.
//!
//! ## Capabilities
//!
//! 1. **String extraction** — pulls all ASCII/UTF-8 strings ≥ N chars
//! 2. **Go dependency detection** — finds `github.com/org/repo` paths
//! 3. **Function name recovery** — extracts `main.*`, `pkg.*` symbols
//! 4. **License obligation check** — flags dependencies missing attribution
//! 5. **Endpoint discovery** — finds hardcoded URLs, domains, API keys

use std::collections::{HashMap, HashSet};
use std::path::Path;
use serde::{Deserialize, Serialize};
use regex::Regex;

use super::{Violation, ViolationType, Severity};
use crate::license::LicenseId;

// ─── Configuration ─────────────────────────────────────────────────

const MIN_STRING_LENGTH: usize = 8;
const GO_PACKAGE_PATTERN: &str = r"github\.com/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+";
const URL_PATTERN: &str = r"https?://[a-zA-Z0-9\.\-]+(?:/[a-zA-Z0-9\.\-/]*)?" ;
const FUNC_PATTERN: &str = r"main\.[a-zA-Z][a-zA-Z0-9_\.]*";

// ─── Known Go Package Licenses ─────────────────────────────────────

/// Known license information for common Go packages
fn known_go_licenses() -> HashMap<&'static str, (&'static str, &'static str)> {
    let mut m = HashMap::new();
    // (package_prefix, (license, attribution_requirement))
    m.insert("github.com/google/uuid", ("BSD-3-Clause", "Requires copyright notice and license text"));
    m.insert("github.com/quic-go/quic-go", ("MIT", "Requires copyright notice and license text"));
    m.insert("github.com/rs/zerolog", ("MIT", "Requires copyright notice and license text"));
    m.insert("github.com/mattn/go-isatty", ("MIT", "Requires copyright notice and license text"));
    m.insert("github.com/gorilla/websocket", ("BSD-3-Clause", "Requires copyright notice"));
    m.insert("github.com/gorilla/mux", ("BSD-3-Clause", "Requires copyright notice"));
    m.insert("github.com/sirupsen/logrus", ("MIT", "Requires copyright notice"));
    m.insert("github.com/stretchr/testify", ("MIT", "Requires copyright notice"));
    m.insert("github.com/spf13/cobra", ("Apache-2.0", "Requires NOTICE file"));
    m.insert("github.com/spf13/viper", ("MIT", "Requires copyright notice"));
    m.insert("github.com/gin-gonic/gin", ("MIT", "Requires copyright notice"));
    m.insert("github.com/go-chi/chi", ("MIT", "Requires copyright notice"));
    m.insert("github.com/prometheus/client_golang", ("Apache-2.0", "Requires NOTICE file"));
    m.insert("github.com/hashicorp/consul", ("MPL-2.0", "Weak copyleft — modified files must be open-sourced"));
    m.insert("github.com/hashicorp/vault", ("MPL-2.0", "Weak copyleft"));
    m.insert("github.com/lib/pq", ("MIT", "Requires copyright notice"));
    m.insert("github.com/go-sql-driver/mysql", ("MPL-2.0", "Weak copyleft"));
    m.insert("github.com/dgrijalva/jwt-go", ("MIT", "Requires copyright notice"));
    m.insert("github.com/golang-jwt/jwt", ("MIT", "Requires copyright notice"));
    m
}

// ─── Data Structures ───────────────────────────────────────────────

/// Complete forensic report for a WASM binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmForensicReport {
    /// Path to the analyzed binary
    pub file_path: String,
    /// Size in bytes
    pub file_size: u64,
    /// Detected compiler/language
    pub compiler: WasmCompiler,
    /// All extracted strings (filtered for relevance)
    pub strings: Vec<ExtractedString>,
    /// Detected Go dependencies
    pub go_dependencies: Vec<GoDependency>,
    /// Detected function names
    pub functions: Vec<String>,
    /// Discovered endpoints (URLs, domains)
    pub endpoints: Vec<Endpoint>,
    /// License violations found
    pub violations: Vec<Violation>,
    /// Summary statistics
    pub stats: WasmStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WasmCompiler {
    Go,
    Rust,
    Emscripten,
    AssemblyScript,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub value: String,
    pub offset: usize,
    pub category: StringCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringCategory {
    PackagePath,
    FunctionName,
    Url,
    ApiKey,
    LicenseText,
    ErrorMessage,
    Domain,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoDependency {
    pub package: String,
    pub known_license: Option<String>,
    pub attribution_required: bool,
    pub attribution_found: bool,
    pub sub_packages: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub endpoint_type: EndpointType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EndpointType {
    Api,
    DataCollection,
    SpeedTest,
    Config,
    Telemetry,
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WasmStats {
    pub total_strings: usize,
    pub go_packages: usize,
    pub functions_found: usize,
    pub endpoints_found: usize,
    pub violations_found: usize,
    pub missing_attributions: usize,
}

// ─── The Scanner ───────────────────────────────────────────────────

/// WebAssembly binary forensics scanner
pub struct WasmForensicScanner {
    min_string_length: usize,
    known_licenses: HashMap<&'static str, (&'static str, &'static str)>,
    sensitive_domains: Vec<&'static str>,
}

impl WasmForensicScanner {
    pub fn new() -> Self {
        Self {
            min_string_length: MIN_STRING_LENGTH,
            known_licenses: known_go_licenses(),
            sensitive_domains: vec![
                "catchon.com",
                "lightspeedsystems.com",
                "securly.com",
                "goguardian.com",
                "gaggle.net",
                "bark.us",
                "impero.com",
                "relay.school",
            ],
        }
    }

    /// Analyze a WASM binary file
    pub fn analyze_file(&self, path: &Path) -> Result<WasmForensicReport, std::io::Error> {
        let data = std::fs::read(path)?;
        let file_size = data.len() as u64;
        
        // Detect the compiler
        let compiler = self.detect_compiler(&data);
        
        // Extract all strings
        let all_strings = self.extract_strings(&data);
        
        // Categorize strings
        let categorized = self.categorize_strings(&all_strings);
        
        // Extract Go dependencies
        let go_deps = self.extract_go_dependencies(&all_strings);
        
        // Extract function names
        let functions = self.extract_functions(&all_strings);
        
        // Discover endpoints
        let endpoints = self.discover_endpoints(&all_strings);
        
        // Check for violations
        let violations = self.check_violations(path, &go_deps, &categorized);
        
        let stats = WasmStats {
            total_strings: categorized.len(),
            go_packages: go_deps.len(),
            functions_found: functions.len(),
            endpoints_found: endpoints.len(),
            violations_found: violations.len(),
            missing_attributions: go_deps.iter()
                .filter(|d| d.attribution_required && !d.attribution_found)
                .count(),
        };
        
        Ok(WasmForensicReport {
            file_path: path.display().to_string(),
            file_size,
            compiler,
            strings: categorized,
            go_dependencies: go_deps,
            functions,
            endpoints,
            violations,
            stats,
        })
    }

    /// Detect which compiler produced this WASM binary
    fn detect_compiler(&self, data: &[u8]) -> WasmCompiler {
        let text = String::from_utf8_lossy(data);
        
        if text.contains("Go build") || text.contains("runtime.wasmExit")
            || text.contains("syscall/js") || text.contains("github.com/")
        {
            WasmCompiler::Go
        } else if text.contains("__wbindgen") || text.contains("wasm-bindgen") {
            WasmCompiler::Rust
        } else if text.contains("emscripten") || text.contains("_emscripten_") {
            WasmCompiler::Emscripten
        } else if text.contains("~lib/rt") || text.contains("assemblyscript") {
            WasmCompiler::AssemblyScript
        } else {
            WasmCompiler::Unknown
        }
    }

    /// Extract all printable strings of minimum length from binary
    fn extract_strings(&self, data: &[u8]) -> Vec<(String, usize)> {
        let mut strings = Vec::new();
        let mut current = String::new();
        let mut start_offset = 0;

        for (i, &byte) in data.iter().enumerate() {
            if byte >= 0x20 && byte <= 0x7E {
                if current.is_empty() {
                    start_offset = i;
                }
                current.push(byte as char);
            } else {
                if current.len() >= self.min_string_length {
                    strings.push((current.clone(), start_offset));
                }
                current.clear();
            }
        }
        
        // Don't forget the last string
        if current.len() >= self.min_string_length {
            strings.push((current, start_offset));
        }

        strings
    }

    /// Categorize extracted strings
    fn categorize_strings(&self, raw: &[(String, usize)]) -> Vec<ExtractedString> {
        let url_re = Regex::new(URL_PATTERN).unwrap();
        let pkg_re = Regex::new(GO_PACKAGE_PATTERN).unwrap();
        let func_re = Regex::new(FUNC_PATTERN).unwrap();

        raw.iter().map(|(s, offset)| {
            let category = if pkg_re.is_match(s) {
                StringCategory::PackagePath
            } else if func_re.is_match(s) {
                StringCategory::FunctionName
            } else if url_re.is_match(s) {
                StringCategory::Url
            } else if s.contains("LICENSE") || s.contains("Copyright") || s.contains("license") {
                StringCategory::LicenseText
            } else if s.contains("error") || s.contains("Error") || s.contains("panic") {
                StringCategory::ErrorMessage
            } else if s.contains(".com") || s.contains(".io") || s.contains(".app") {
                StringCategory::Domain
            } else if s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
                StringCategory::ApiKey
            } else {
                StringCategory::Other
            };

            ExtractedString {
                value: s.clone(),
                offset: *offset,
                category,
            }
        }).collect()
    }

    /// Extract Go package dependencies from string table
    fn extract_go_dependencies(&self, raw: &[(String, usize)]) -> Vec<GoDependency> {
        let pkg_re = Regex::new(GO_PACKAGE_PATTERN).unwrap();
        let mut seen: HashSet<String> = HashSet::new();
        let mut deps: HashMap<String, Vec<String>> = HashMap::new();

        for (s, _) in raw {
            for m in pkg_re.find_iter(s) {
                let full_path = m.as_str().to_string();
                // Extract the base package (org/repo)
                let parts: Vec<&str> = full_path.splitn(4, '/').collect();
                if parts.len() >= 3 {
                    let base = format!("{}/{}/{}", parts[0], parts[1], parts[2]);
                    if !seen.contains(&full_path) {
                        seen.insert(full_path.clone());
                        deps.entry(base).or_default().push(full_path);
                    }
                }
            }
        }

        deps.into_iter().map(|(base, sub_pkgs)| {
            let license_info = self.known_licenses.iter()
                .find(|(k, _)| base.starts_with(*k))
                .map(|(_, v)| v);

            GoDependency {
                package: base,
                known_license: license_info.map(|(l, _)| l.to_string()),
                attribution_required: license_info.map_or(true, |(l, _)| {
                    // All open source licenses require at minimum copyright notice
                    !l.contains("Unlicense") && !l.contains("CC0")
                }),
                attribution_found: false, // Will be checked against project files
                sub_packages: sub_pkgs,
            }
        }).collect()
    }

    /// Extract function names (useful for understanding binary purpose)
    fn extract_functions(&self, raw: &[(String, usize)]) -> Vec<String> {
        let func_re = Regex::new(FUNC_PATTERN).unwrap();
        let mut funcs: HashSet<String> = HashSet::new();

        for (s, _) in raw {
            for m in func_re.find_iter(s) {
                funcs.insert(m.as_str().to_string());
            }
        }

        let mut result: Vec<String> = funcs.into_iter().collect();
        result.sort();
        result
    }

    /// Discover network endpoints hardcoded in the binary
    fn discover_endpoints(&self, raw: &[(String, usize)]) -> Vec<Endpoint> {
        let url_re = Regex::new(URL_PATTERN).unwrap();
        let mut seen: HashSet<String> = HashSet::new();
        let mut endpoints = Vec::new();

        for (s, _) in raw {
            for m in url_re.find_iter(s) {
                let url = m.as_str().to_string();
                if !seen.contains(&url) {
                    seen.insert(url.clone());
                    let etype = self.classify_endpoint(&url);
                    endpoints.push(Endpoint {
                        url,
                        endpoint_type: etype,
                    });
                }
            }
        }

        // Also check for bare domain references
        for domain in &self.sensitive_domains {
            for (s, _) in raw {
                if s.contains(domain) && !seen.contains(*domain) {
                    seen.insert(domain.to_string());
                    endpoints.push(Endpoint {
                        url: domain.to_string(),
                        endpoint_type: EndpointType::DataCollection,
                    });
                }
            }
        }

        endpoints
    }

    fn classify_endpoint(&self, url: &str) -> EndpointType {
        let lower = url.to_lowercase();
        if lower.contains("speedtest") || lower.contains("speed-test") {
            EndpointType::SpeedTest
        } else if lower.contains("config") || lower.contains("settings") {
            EndpointType::Config
        } else if lower.contains("telemetry") || lower.contains("analytics") {
            EndpointType::Telemetry
        } else if lower.contains("receive") || lower.contains("collect") || lower.contains("catcher") {
            EndpointType::DataCollection
        } else if lower.contains("api") {
            EndpointType::Api
        } else {
            EndpointType::Unknown
        }
    }

    /// Check for license violations
    fn check_violations(
        &self,
        binary_path: &Path,
        go_deps: &[GoDependency],
        _strings: &[ExtractedString],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        let parent = binary_path.parent().unwrap_or(Path::new("."));

        // Check if there's a LICENSE, NOTICE, or THIRD_PARTY file alongside the binary
        let has_license = parent.join("LICENSE").exists()
            || parent.join("LICENSE.md").exists()
            || parent.join("LICENSE.txt").exists();
        let has_notice = parent.join("NOTICE").exists()
            || parent.join("NOTICE.md").exists()
            || parent.join("NOTICE.txt").exists();
        let has_third_party = parent.join("THIRD_PARTY_NOTICES").exists()
            || parent.join("THIRD_PARTY_NOTICES.md").exists()
            || parent.join("THIRD_PARTY_NOTICES.txt").exists()
            || parent.join("THIRD-PARTY-NOTICES").exists();

        // Flag each dependency missing attribution
        for dep in go_deps {
            if !dep.attribution_required {
                continue;
            }

            // Skip the project's own packages
            if dep.package.contains("Lightspeed-Systems")
                || dep.package.contains("securly")
                || dep.package.contains("catchon")
            {
                continue;
            }

            if !has_license && !has_notice && !has_third_party {
                let license_str = dep.known_license.as_deref().unwrap_or("Unknown");
                violations.push(Violation {
                    violation_type: ViolationType::MissingAttribution,
                    severity: Severity::High,
                    confidence: 0.9,
                    description: format!(
                        "Go dependency '{}' ({}) embedded in WASM binary without required attribution. \
                         No LICENSE, NOTICE, or THIRD_PARTY_NOTICES file found.",
                        dep.package, license_str
                    ),
                    files: vec![binary_path.to_path_buf()],
                    licenses: vec![LicenseId::new(license_str)],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: None,
                });
            }

            // Apache-2.0 requires NOTICE file specifically
            if dep.known_license.as_deref() == Some("Apache-2.0") && !has_notice {
                violations.push(Violation {
                    violation_type: ViolationType::MissingNoticeFile,
                    severity: Severity::High,
                    confidence: 0.95,
                    description: format!(
                        "Go dependency '{}' is Apache-2.0 licensed and requires a NOTICE file, \
                         which was not found.",
                        dep.package
                    ),
                    files: vec![binary_path.to_path_buf()],
                    licenses: vec![LicenseId::new("Apache-2.0")],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        // Flag opaque WASM binary without any source/license documentation
        if !has_license && !has_third_party && !go_deps.is_empty() {
            violations.push(Violation {
                violation_type: ViolationType::OpaqueDistribution,
                severity: Severity::Critical,
                confidence: 0.95,
                description: format!(
                    "WASM binary contains {} embedded Go dependencies but provides no license \
                     documentation. This is an opaque distribution that cannot be audited for \
                     license compliance without binary analysis.",
                    go_deps.len()
                ),
                files: vec![binary_path.to_path_buf()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![],
                claimed_license: None,
                actual_license: None,
            });
        }

        violations
    }
}

impl Default for WasmForensicScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmForensicReport {
    /// Render as Markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        
        md.push_str(&format!("# WASM Binary Forensic Report\n\n"));
        md.push_str(&format!("**File:** `{}`\n", self.file_path));
        md.push_str(&format!("**Size:** {} bytes ({:.1} MB)\n", self.file_size, self.file_size as f64 / 1_048_576.0));
        md.push_str(&format!("**Compiler:** {:?}\n\n", self.compiler));

        if !self.go_dependencies.is_empty() {
            md.push_str("## Go Dependencies\n\n");
            md.push_str("| Package | License | Attribution Required | Found |\n");
            md.push_str("|---------|---------|---------------------|-------|\n");
            for dep in &self.go_dependencies {
                md.push_str(&format!(
                    "| `{}` | {} | {} | {} |\n",
                    dep.package,
                    dep.known_license.as_deref().unwrap_or("Unknown"),
                    if dep.attribution_required { "Yes" } else { "No" },
                    if dep.attribution_found { "✅" } else { "❌" },
                ));
            }
            md.push_str("\n");
        }

        if !self.endpoints.is_empty() {
            md.push_str("## Discovered Endpoints\n\n");
            md.push_str("| URL | Type |\n");
            md.push_str("|-----|------|\n");
            for ep in &self.endpoints {
                md.push_str(&format!("| `{}` | {:?} |\n", ep.url, ep.endpoint_type));
            }
            md.push_str("\n");
        }

        if !self.functions.is_empty() {
            md.push_str("## Recovered Function Names\n\n");
            for f in &self.functions {
                md.push_str(&format!("- `{}`\n", f));
            }
            md.push_str("\n");
        }

        if !self.violations.is_empty() {
            md.push_str("## Violations\n\n");
            for v in &self.violations {
                md.push_str(&format!("### {:?} — {:?}\n\n", v.severity, v.violation_type));
                md.push_str(&format!("{}\n\n", v.description));
            }
        }

        md.push_str(&format!("## Statistics\n\n"));
        md.push_str(&format!("- Total strings extracted: {}\n", self.stats.total_strings));
        md.push_str(&format!("- Go packages found: {}\n", self.stats.go_packages));
        md.push_str(&format!("- Functions recovered: {}\n", self.stats.functions_found));
        md.push_str(&format!("- Endpoints discovered: {}\n", self.stats.endpoints_found));
        md.push_str(&format!("- Violations: {}\n", self.stats.violations_found));
        md.push_str(&format!("- Missing attributions: {}\n", self.stats.missing_attributions));

        md
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_extraction() {
        let scanner = WasmForensicScanner::new();
        let data = b"junk\x00\x00github.com/google/uuid\x00\x00more junk\x00\x00short\x00\x00";
        let strings = scanner.extract_strings(data);
        assert!(strings.iter().any(|(s, _)| s.contains("github.com/google/uuid")));
        assert!(!strings.iter().any(|(s, _)| s == "short")); // too short
    }

    #[test]
    fn test_go_dependency_detection() {
        let scanner = WasmForensicScanner::new();
        let raw = vec![
            ("github.com/google/uuid".to_string(), 0),
            ("github.com/quic-go/quic-go/internal/wire".to_string(), 100),
            ("github.com/rs/zerolog".to_string(), 200),
            ("not a package path at all".to_string(), 300),
        ];
        let deps = scanner.extract_go_dependencies(&raw);
        assert!(deps.iter().any(|d| d.package.contains("google/uuid")));
        assert!(deps.iter().any(|d| d.package.contains("quic-go")));
        assert!(deps.iter().any(|d| d.package.contains("rs/zerolog")));
    }

    #[test]
    fn test_compiler_detection_go() {
        let scanner = WasmForensicScanner::new();
        let data = b"some binary data runtime.wasmExit more data";
        let compiler = scanner.detect_compiler(data);
        assert!(matches!(compiler, WasmCompiler::Go));
    }

    #[test]
    fn test_compiler_detection_rust() {
        let scanner = WasmForensicScanner::new();
        let data = b"some binary data __wbindgen_placeholder__ more";
        let compiler = scanner.detect_compiler(data);
        assert!(matches!(compiler, WasmCompiler::Rust));
    }

    #[test]
    fn test_endpoint_classification() {
        let scanner = WasmForensicScanner::new();
        assert!(matches!(
            scanner.classify_endpoint("https://agent.catchon.com/catcher/api/receive"),
            EndpointType::DataCollection
        ));
        assert!(matches!(
            scanner.classify_endpoint("https://insight-speedtest.lightspeedsystems.app"),
            EndpointType::SpeedTest
        ));
        assert!(matches!(
            scanner.classify_endpoint("https://agent.catchon.com/agentconfig/v2"),
            EndpointType::Config
        ));
    }
}
