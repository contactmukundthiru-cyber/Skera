//! ScanCode Toolkit bridge — leverages ScanCode's 1000+ license templates
//!
//! Shells out to the `scancode` CLI (if installed) and parses its JSON output.
//! Falls back gracefully to askalono-based detection if ScanCode is not available.
//!
//! ## Why
//!
//! ScanCode toolkit achieves near 100% accuracy on license text identification
//! with 1000+ license templates, inverted index matching, and multiple sequence
//! alignment. This is 2x our askalono coverage.
//!
//! ## Usage
//!
//! Feature-gated: only compiled when the `scancode` feature is enabled, but
//! gracefully handles the missing binary at runtime regardless.

use crate::license::LicenseId;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

/// Result from a ScanCode scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCodeResult {
    /// Files analyzed
    pub files: Vec<ScanCodeFile>,
    /// Whether ScanCode was available
    pub scancode_available: bool,
    /// ScanCode version used
    pub scancode_version: Option<String>,
}

/// A single file analyzed by ScanCode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCodeFile {
    /// File path
    pub path: String,
    /// Licenses detected
    pub licenses: Vec<ScanCodeLicense>,
    /// Copyrights detected
    pub copyrights: Vec<ScanCodeCopyright>,
}

/// A license detected by ScanCode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCodeLicense {
    /// SPDX identifier
    pub spdx_id: String,
    /// License name
    pub name: String,
    /// Detection score (0-100)
    pub score: f64,
    /// Start line in the file
    pub start_line: usize,
    /// End line in the file
    pub end_line: usize,
    /// Detection method
    pub detection_method: String,
    /// Matched text
    pub matched_text: Option<String>,
}

/// A copyright detected by ScanCode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCodeCopyright {
    /// Copyright statement
    pub statement: String,
    /// Holder
    pub holder: String,
    /// Start line
    pub start_line: usize,
}

/// Bridge to ScanCode toolkit
pub struct ScanCodeBridge;

impl ScanCodeBridge {
    /// Check if ScanCode is installed
    pub fn is_available() -> bool {
        Command::new("scancode")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Get ScanCode version
    pub fn version() -> Option<String> {
        Command::new("scancode")
            .arg("--version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }

    /// Run ScanCode against a file or directory
    pub fn scan(path: &Path) -> Result<ScanCodeResult, String> {
        if !Self::is_available() {
            return Ok(ScanCodeResult {
                files: Vec::new(),
                scancode_available: false,
                scancode_version: None,
            });
        }

        let temp_output = std::env::temp_dir().join("skera_scancode_output.json");

        let output = Command::new("scancode")
            .args([
                "--license",
                "--copyright",
                "--json-pp",
                temp_output.to_str().unwrap_or("output.json"),
                "--quiet",
                "--timeout",
                "120",
            ])
            .arg(path.to_str().unwrap_or("."))
            .output()
            .map_err(|e| format!("Failed to run scancode: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("ScanCode failed: {}", stderr));
        }

        // Parse the JSON output
        let json_str = std::fs::read_to_string(&temp_output)
            .map_err(|e| format!("Failed to read scancode output: {}", e))?;

        // Clean up temp file
        let _ = std::fs::remove_file(&temp_output);

        Self::parse_output(&json_str)
    }

    /// Parse ScanCode JSON output
    fn parse_output(json_str: &str) -> Result<ScanCodeResult, String> {
        let parsed: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| format!("JSON parse error: {}", e))?;

        let mut files = Vec::new();

        if let Some(file_array) = parsed.get("files").and_then(|f| f.as_array()) {
            for file_val in file_array {
                let path = file_val
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();

                let mut licenses = Vec::new();
                if let Some(lic_array) = file_val
                    .get("license_detections")
                    .and_then(|l| l.as_array())
                {
                    for lic in lic_array {
                        if let Some(matches) = lic.get("matches").and_then(|m| m.as_array()) {
                            for m in matches {
                                licenses.push(ScanCodeLicense {
                                    spdx_id: m
                                        .get("license_expression_spdx")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    name: m
                                        .get("rule_identifier")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    score: m
                                        .get("score")
                                        .and_then(|s| s.as_f64())
                                        .unwrap_or(0.0),
                                    start_line: m
                                        .get("start_line")
                                        .and_then(|s| s.as_u64())
                                        .unwrap_or(0)
                                        as usize,
                                    end_line: m
                                        .get("end_line")
                                        .and_then(|s| s.as_u64())
                                        .unwrap_or(0)
                                        as usize,
                                    detection_method: m
                                        .get("matcher")
                                        .and_then(|s| s.as_str())
                                        .unwrap_or("unknown")
                                        .to_string(),
                                    matched_text: m
                                        .get("matched_text")
                                        .and_then(|s| s.as_str())
                                        .map(|s| s.to_string()),
                                });
                            }
                        }
                    }
                }

                let mut copyrights = Vec::new();
                if let Some(copy_array) =
                    file_val.get("copyrights").and_then(|c| c.as_array())
                {
                    for c in copy_array {
                        copyrights.push(ScanCodeCopyright {
                            statement: c
                                .get("copyright")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string(),
                            holder: c
                                .get("holders")
                                .and_then(|h| h.as_array())
                                .and_then(|a| a.first())
                                .and_then(|h| h.get("holder"))
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string(),
                            start_line: c
                                .get("start_line")
                                .and_then(|s| s.as_u64())
                                .unwrap_or(0)
                                as usize,
                        });
                    }
                }

                files.push(ScanCodeFile {
                    path,
                    licenses,
                    copyrights,
                });
            }
        }

        Ok(ScanCodeResult {
            files,
            scancode_available: true,
            scancode_version: Self::version(),
        })
    }

    /// Convert ScanCode results to Skera LicenseId
    pub fn to_license_ids(result: &ScanCodeResult) -> Vec<(String, LicenseId, f64)> {
        let mut ids = Vec::new();
        for file in &result.files {
            for lic in &file.licenses {
                if lic.score >= 50.0 && !lic.spdx_id.is_empty() {
                    ids.push((
                        file.path.clone(),
                        LicenseId::new(&lic.spdx_id),
                        lic.score / 100.0,
                    ));
                }
            }
        }
        ids
    }
}
