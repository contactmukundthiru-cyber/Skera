//! YARA pattern engine — rule-based adversarial scanning
//!
//! YARA is the industry standard for pattern matching in forensics and malware
//! research. We use YARA-X (the Rust rewrite by VirusTotal) for:
//!
//! 1. **Copyright watermark detection** — rules that match copyright strings,
//!    proprietary identifiers, and embedded watermarks in binaries.
//!
//! 2. **Obfuscation detection** — rules that flag known obfuscation patterns
//!    (eval/atob chains, hex-encoded strings, packer signatures).
//!
//! 3. **License marker scanning** — SPDX headers, license URLs, legal text
//!    fragments embedded in compiled or bundled code.
//!
//! 4. **Commercial font detection** — proprietary font binary signatures
//!    that indicate unlicensed commercial font usage.
//!
//! YARA rules are loaded from external `.yar` files for extensibility.
//! This module is behind the `yara` feature flag since yara-x is heavy.

#[cfg(feature = "yara")]
pub mod engine {
    use serde::{Deserialize, Serialize};
    use std::path::Path;

    /// Result of a YARA scan against a single file
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct YaraScanResult {
        /// File that was scanned
        pub file_path: std::path::PathBuf,
        /// All rule matches
        pub matches: Vec<YaraMatch>,
        /// Total rules evaluated
        pub rules_evaluated: usize,
        /// Scan duration in microseconds
        pub duration_us: u64,
    }

    /// A single YARA rule match
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct YaraMatch {
        /// Rule identifier
        pub rule_name: String,
        /// Rule namespace / category
        pub namespace: String,
        /// Tags applied to the rule
        pub tags: Vec<String>,
        /// Metadata from the rule
        pub metadata: Vec<(String, String)>,
        /// Matched strings with their offsets
        pub matched_strings: Vec<YaraStringMatch>,
    }

    /// A matched string within a YARA rule
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct YaraStringMatch {
        /// Identifier of the string in the rule
        pub identifier: String,
        /// Byte offset where the match was found
        pub offset: usize,
        /// Length of the match
        pub length: usize,
        /// Preview of the matched content (first 100 bytes)
        pub preview: String,
    }

    /// YARA scanner that loads and compiles rules
    pub struct YaraScanner {
        /// Compiled rules
        rules: yara_x::Rules,
        /// Number of rules loaded
        rule_count: usize,
    }

    impl YaraScanner {
        /// Create a scanner from a YARA rules directory.
        /// All `.yar` and `.yara` files will be compiled.
        pub fn from_directory(rules_dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
            let mut compiler = yara_x::Compiler::new();

            let mut rule_count = 0;
            if rules_dir.is_dir() {
                for entry in walkdir::WalkDir::new(rules_dir)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|ext| ext.to_str())
                            .map(|ext| ext == "yar" || ext == "yara")
                            .unwrap_or(false)
                    })
                {
                    let source = std::fs::read_to_string(entry.path())?;
                    compiler.add_source(source.as_str())?;
                    rule_count += 1;
                    tracing::debug!("Loaded YARA rules from: {:?}", entry.path());
                }
            }

            let rules = compiler.build();
            tracing::info!("Compiled {} YARA rule files", rule_count);

            Ok(Self { rules, rule_count })
        }

        /// Create a scanner from inline YARA rule source.
        pub fn from_source(source: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let mut compiler = yara_x::Compiler::new();
            compiler.add_source(source)?;
            let rules = compiler.build();
            Ok(Self { rules, rule_count: 1 })
        }

        /// Scan a byte slice against all compiled rules.
        pub fn scan_bytes(&self, data: &[u8]) -> YaraScanResult {
            let start = std::time::Instant::now();

            let mut scanner = yara_x::Scanner::new(&self.rules);
            let scan_results = scanner.scan(data);

            let mut matches = Vec::new();

            if let Ok(results) = scan_results {
                for rule in results.matching_rules() {
                    let mut matched_strings = Vec::new();
                    for pattern in rule.patterns() {
                        for m in pattern.matches() {
                            let offset = m.range().start;
                            let length = m.range().len();
                            let preview_end = (offset + length).min(data.len());
                            let preview_bytes = &data[offset..preview_end.min(offset + 100)];
                            let preview = String::from_utf8_lossy(preview_bytes).to_string();

                            matched_strings.push(YaraStringMatch {
                                identifier: pattern.identifier().to_string(),
                                offset,
                                length,
                                preview,
                            });
                        }
                    }

                    let metadata: Vec<(String, String)> = rule
                        .metadata()
                        .map(|m| (m.identifier().to_string(), format!("{:?}", m.value())))
                        .collect();

                    let tags: Vec<String> = rule.tags().map(|t| t.identifier().to_string()).collect();

                    matches.push(YaraMatch {
                        rule_name: rule.identifier().to_string(),
                        namespace: rule.namespace().to_string(),
                        tags,
                        metadata,
                        matched_strings,
                    });
                }
            }

            YaraScanResult {
                file_path: std::path::PathBuf::new(),
                matches,
                rules_evaluated: self.rule_count,
                duration_us: start.elapsed().as_micros() as u64,
            }
        }

        /// Scan a file against all compiled rules.
        pub fn scan_file(&self, path: &Path) -> Result<YaraScanResult, std::io::Error> {
            let data = std::fs::read(path)?;
            let mut result = self.scan_bytes(&data);
            result.file_path = path.to_path_buf();
            Ok(result)
        }

        /// Scan an entire directory recursively.
        pub fn scan_directory(&self, dir: &Path) -> Vec<YaraScanResult> {
            walkdir::WalkDir::new(dir)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter_map(|e| self.scan_file(e.path()).ok())
                .filter(|r| !r.matches.is_empty())
                .collect()
        }

        /// Get the number of compiled rules.
        pub fn rule_count(&self) -> usize {
            self.rule_count
        }
    }
}

// ─── Built-in YARA Rule Templates ──────────────────────────────────

/// Built-in YARA rules for copyright and license scanning.
/// These are embedded at compile time and can be extended with external files.
pub const BUILTIN_COPYRIGHT_RULES: &str = r#"
rule copyright_notice {
    meta:
        description = "Detects copyright notices in code"
        category = "copyright"
        severity = "info"
    strings:
        $c1 = /[Cc]opyright\s+(\(c\)\s+)?\d{4}/ ascii wide
        $c2 = "All rights reserved" ascii nocase
        $c3 = "All Rights Reserved" ascii
        $c4 = /©\s*\d{4}/ ascii wide
        $c5 = /SPDX-License-Identifier:\s*\S+/ ascii
    condition:
        any of them
}

rule license_header_mit {
    meta:
        description = "MIT License text"
        category = "license"
        license_type = "MIT"
        severity = "info"
    strings:
        $m1 = "Permission is hereby granted, free of charge" ascii nocase
        $m2 = "to deal in the Software without restriction" ascii nocase
        $m3 = "THE SOFTWARE IS PROVIDED \"AS IS\"" ascii nocase
    condition:
        2 of them
}

rule license_header_gpl {
    meta:
        description = "GPL License text"
        category = "license"
        license_type = "GPL"
        severity = "high"
    strings:
        $g1 = "GNU General Public License" ascii nocase
        $g2 = "either version 2 of the License, or" ascii nocase
        $g3 = "Free Software Foundation" ascii nocase
        $g4 = "is free software" ascii nocase
    condition:
        2 of them
}

rule license_header_apache {
    meta:
        description = "Apache License text"
        category = "license"
        license_type = "Apache-2.0"
        severity = "info"
    strings:
        $a1 = "Licensed under the Apache License" ascii nocase
        $a2 = "Version 2.0" ascii
        $a3 = "http://www.apache.org/licenses/" ascii
    condition:
        2 of them
}

rule obfuscation_eval_chain {
    meta:
        description = "Obfuscated eval/atob chain — possible code hiding"
        category = "obfuscation"
        severity = "critical"
    strings:
        $e1 = "eval(atob(" ascii
        $e2 = "eval(unescape(" ascii
        $e3 = "eval(String.fromCharCode(" ascii
        $e4 = "Function(atob(" ascii
        $e5 = "new Function(unescape(" ascii
    condition:
        any of them
}

rule commercial_font_binary {
    meta:
        description = "Commercial font binary signatures"
        category = "asset"
        severity = "high"
    strings:
        $proxima = "ProximaNova" ascii wide
        $gotham = "Gotham-" ascii wide
        $avenir = "AvenirNext" ascii wide
        $helvetica = "HelveticaNeue" ascii wide
        $futura = "FuturaPT" ascii wide
        $circular = "CircularStd" ascii wide
        $gilroy = "Gilroy-" ascii wide
    condition:
        any of them
}

rule stripped_copyright {
    meta:
        description = "Signs of stripped copyright — minified code without attribution"
        category = "copyright"
        severity = "high"
    strings:
        $minified = /[a-z]\.[a-z]\([a-z],[a-z]\)/ ascii
        $no_copyright = "Copyright" ascii nocase
        $no_license = "License" ascii nocase
    condition:
        $minified and not ($no_copyright or $no_license)
}
"#;

// ─── Stub when feature disabled ────────────────────────────────────

/// Check if YARA support is available.
pub fn yara_available() -> bool {
    cfg!(feature = "yara")
}
