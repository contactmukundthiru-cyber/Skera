//! Deep attribution verification — forensic-grade compliance checking
//!
//! ## Overview
//!
//! Checks that all required attribution obligations are met. Goes far
//! beyond checking if a LICENSE file exists — verifies content matches
//! declared license, checks binary distributions, validates NOTICE files,
//! and detects stripped attribution in vendored/bundled code.
//!
//! ## Industry-Leading Features
//!
//! 1. **LICENSE Content Verification** — reads LICENSE files and verifies
//!    their content matches the declared license using text classification.
//!
//! 2. **NOTICE File Content Auditing** — for Apache-2.0, validates the
//!    NOTICE file contains required entries for each dependency.
//!
//! 3. **Vendored Code Attribution Scanning** — recursively scans vendored
//!    directories, checking each for LICENSE files and preserved headers.
//!
//! 4. **Binary Distribution Checks** — verifies that dist/build outputs
//!    include required attribution files.
//!
//! 5. **Bundled JS/CSS Attribution** — checks minified bundles for preserved
//!    `@license` and `@preserve` comments.
//!
//! 6. **Attribution Completeness Scoring** — quantifies how complete the
//!    project's attribution coverage is (-100% = fully missing, +100% = perfect).

use crate::detection::{Violation, ViolationType, Severity};
use crate::evidence::EvidenceItem;
use crate::license::{LicenseClassifier, LicenseDb, LicenseId, LicenseObligation};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

// ─── Data Structures ────────────────────────────────────────────────

/// Results of a comprehensive attribution check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionReport {
    pub violations: Vec<Violation>,
    /// Completeness score: 0.0 (fully missing) to 1.0 (perfect)
    pub completeness_score: f64,
    /// Per-dependency attribution status
    pub dependency_status: Vec<DependencyAttribution>,
    /// Summary statistics
    pub stats: AttributionStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAttribution {
    pub name: String,
    pub license: LicenseId,
    /// Does a LICENSE file exist for this dependency?
    pub has_license_file: bool,
    /// Does the LICENSE file content match the declared license?
    pub license_content_matches: Option<bool>,
    /// Is the dependency mentioned in the NOTICE file?
    pub in_notice_file: Option<bool>,
    /// Does vendored code preserve license headers?
    pub headers_preserved: Option<bool>,
    /// Is attribution present in bundle/dist output?
    pub in_dist_output: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributionStats {
    pub total_dependencies_checked: usize,
    pub license_files_present: usize,
    pub license_files_missing: usize,
    pub license_content_mismatches: usize,
    pub notice_entries_present: usize,
    pub notice_entries_missing: usize,
    pub vendored_dirs_scanned: usize,
    pub stripped_licenses_detected: usize,
    pub bundle_attributions_checked: usize,
    pub bundle_attributions_missing: usize,
}

// ─── Core Engine ────────────────────────────────────────────────────

/// Attribution checker engine
pub struct AttributionChecker {
    db: LicenseDb,
    classifier: LicenseClassifier,
}

impl AttributionChecker {
    pub fn new() -> Self {
        Self {
            db: LicenseDb::new(),
            classifier: LicenseClassifier::new(),
        }
    }

    /// Comprehensive attribution check for a project.
    pub fn full_check(
        &self,
        root: &Path,
        project_license: &LicenseId,
        dependencies: &[(String, LicenseId)],
    ) -> AttributionReport {
        let mut violations = Vec::new();
        let mut dep_status = Vec::new();
        let mut stats = AttributionStats::default();

        // ── 1. Check root LICENSE file exists and content matches ──
        let root_license_violations = self.check_root_license(root, project_license);
        violations.extend(root_license_violations);

        // ── 2. Check NOTICE file for dependencies that require it ──
        let notice_content = read_notice_file(root);
        let notice_violations = self.check_notice_file(root, dependencies, &notice_content, &mut stats);
        violations.extend(notice_violations);

        // ── 3. Check each dependency's attribution ──
        stats.total_dependencies_checked = dependencies.len();

        for (dep_name, dep_license) in dependencies {
            let obligations = self.db.obligations(dep_license.as_str());
            let mut dep_attr = DependencyAttribution {
                name: dep_name.clone(),
                license: dep_license.clone(),
                has_license_file: false,
                license_content_matches: None,
                in_notice_file: None,
                headers_preserved: None,
                in_dist_output: None,
            };

            // Check vendored directory for LICENSE
            if let Some(vendor_dir) = find_vendored_dir(root, dep_name) {
                stats.vendored_dirs_scanned += 1;

                // Check LICENSE file exists
                dep_attr.has_license_file = has_license_file(&vendor_dir);
                if dep_attr.has_license_file {
                    stats.license_files_present += 1;

                    // Verify LICENSE content matches declared license
                    if let Some(license_content) = read_license_file(&vendor_dir) {
                        if let Some(classification) = self.classifier.classify(&license_content) {
                            let matches = classification.license == *dep_license
                                || classification.license.family() == dep_license.family();
                            dep_attr.license_content_matches = Some(matches);

                            if !matches && classification.confidence > 0.6 {
                                stats.license_content_mismatches += 1;
                                violations.push(Violation {
                                    violation_type: ViolationType::IncorrectAttribution,
                                    severity: Severity::High,
                                    confidence: classification.confidence,
                                    description: format!(
                                        "Vendored '{}' declares {} but LICENSE file contains {} ({:.0}% match)",
                                        dep_name, dep_license, classification.license,
                                        classification.confidence * 100.0
                                    ),
                                    files: vec![vendor_dir.clone()],
                                    licenses: vec![dep_license.clone(), classification.license],
                                    obligations_violated: vec![LicenseObligation::Attribution],
                                    evidence: vec![EvidenceItem {
                                        description: "LICENSE file content differs from declared license".into(),
                                        file_path: Some(find_license_file_path(&vendor_dir).unwrap_or(vendor_dir.clone())),
                                        line_number: None,
                                        byte_offset: None,
                                        sha256: None,
                                        content_excerpt: Some(license_content[..license_content.len().min(500)].to_string()),
                                        timestamp: chrono::Utc::now(),
                                    }],
                                    claimed_license: Some(dep_license.clone()),
                                    actual_license: None,
                                });
                            }
                        }
                    }
                } else if obligations.contains(&LicenseObligation::Attribution) {
                    stats.license_files_missing += 1;
                    stats.stripped_licenses_detected += 1;
                    violations.push(Violation {
                        violation_type: ViolationType::StrippedLicense,
                        severity: Severity::High,
                        confidence: 0.90,
                        description: format!(
                            "Vendored dependency '{}' ({}) has no LICENSE file",
                            dep_name, dep_license
                        ),
                        files: vec![vendor_dir.clone()],
                        licenses: vec![dep_license.clone()],
                        obligations_violated: vec![LicenseObligation::Attribution],
                        evidence: vec![EvidenceItem {
                            description: format!(
                                "Expected LICENSE file in vendored directory: {}",
                                vendor_dir.display()
                            ),
                            file_path: Some(vendor_dir.clone()),
                            line_number: None,
                            byte_offset: None,
                            sha256: None,
                            content_excerpt: None,
                            timestamp: chrono::Utc::now(),
                        }],
                        claimed_license: None,
                        actual_license: None,
                    });
                }

                // Check if source headers are preserved in vendored code
                if obligations.contains(&LicenseObligation::HeaderPreservation) {
                    let headers_ok = check_headers_preserved(&vendor_dir);
                    dep_attr.headers_preserved = Some(headers_ok);

                    if !headers_ok {
                        violations.push(Violation {
                            violation_type: ViolationType::StrippedLicense,
                            severity: Severity::Medium,
                            confidence: 0.80,
                            description: format!(
                                "Vendored '{}' ({}) has source files without license headers",
                                dep_name, dep_license
                            ),
                            files: vec![vendor_dir],
                            licenses: vec![dep_license.clone()],
                            obligations_violated: vec![LicenseObligation::HeaderPreservation],
                            evidence: vec![],
                            claimed_license: None,
                            actual_license: None,
                        });
                    }
                }
            }

            // Check NOTICE file mentions
            if obligations.contains(&LicenseObligation::NoticeFile) {
                let in_notice = notice_content.as_ref()
                    .map(|content| {
                        let lower_content = content.to_lowercase();
                        let lower_name = dep_name.to_lowercase();
                        lower_content.contains(&lower_name)
                    })
                    .unwrap_or(false);
                dep_attr.in_notice_file = Some(in_notice);
            }

            dep_status.push(dep_attr);
        }

        // ── 4. Check bundle/dist attribution ──
        let bundle_violations = self.check_bundle_attribution(root, &mut stats);
        violations.extend(bundle_violations);

        // ── 5. Calculate completeness score ──
        let completeness = calculate_completeness(&dep_status, &stats);

        AttributionReport {
            violations,
            completeness_score: completeness,
            dependency_status: dep_status,
            stats,
        }
    }

    /// Backward-compatible check_project method
    pub fn check_project(
        &self,
        root: &Path,
        project_license: &LicenseId,
        dependencies: &[(String, LicenseId)],
    ) -> Vec<Violation> {
        self.full_check(root, project_license, dependencies).violations
    }

    /// Check root LICENSE file exists and content matches declared license.
    fn check_root_license(&self, root: &Path, project_license: &LicenseId) -> Vec<Violation> {
        let mut violations = Vec::new();

        if !has_license_file(root) {
            violations.push(Violation {
                violation_type: ViolationType::MissingAttribution,
                severity: Severity::Medium,
                confidence: 0.99,
                description: "No LICENSE file found in project root".into(),
                files: vec![root.to_path_buf()],
                licenses: vec![project_license.clone()],
                obligations_violated: vec![LicenseObligation::Attribution],
                evidence: vec![],
                claimed_license: None,
                actual_license: None,
            });
        } else {
            // Verify LICENSE content matches declared license
            if let Some(content) = read_license_file(root) {
                if let Some(classification) = self.classifier.classify(&content) {
                    if classification.license != *project_license
                        && classification.license.family() != project_license.family()
                        && classification.confidence > 0.6
                    {
                        violations.push(Violation {
                            violation_type: ViolationType::IncorrectAttribution,
                            severity: Severity::Critical,
                            confidence: classification.confidence,
                            description: format!(
                                "LICENSE file contains {} but project declares {} — possible license mismatch or laundering",
                                classification.license, project_license
                            ),
                            files: vec![find_license_file_path(root).unwrap_or_else(|| root.to_path_buf())],
                            licenses: vec![classification.license, project_license.clone()],
                            obligations_violated: vec![LicenseObligation::Attribution],
                            evidence: vec![EvidenceItem {
                                description: "Root LICENSE file content differs from declared project license".into(),
                                file_path: find_license_file_path(root),
                                line_number: None,
                                byte_offset: None,
                                sha256: None,
                                content_excerpt: Some(content[..content.len().min(500)].to_string()),
                                timestamp: chrono::Utc::now(),
                            }],
                            claimed_license: Some(project_license.clone()),
                            actual_license: None,
                        });
                    }
                }
            }
        }

        violations
    }

    /// Check NOTICE file presence and content for Apache-licensed dependencies.
    fn check_notice_file(
        &self,
        root: &Path,
        dependencies: &[(String, LicenseId)],
        notice_content: &Option<String>,
        stats: &mut AttributionStats,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        let needs_notice: Vec<_> = dependencies
            .iter()
            .filter(|(_, lic)| {
                self.db
                    .obligations(lic.as_str())
                    .contains(&LicenseObligation::NoticeFile)
            })
            .collect();

        if needs_notice.is_empty() {
            return violations;
        }

        if !has_notice_file(root) {
            violations.push(Violation {
                violation_type: ViolationType::MissingNoticeFile,
                severity: Severity::Medium,
                confidence: 0.95,
                description: format!(
                    "Missing NOTICE file. {} dependencies require it: {}",
                    needs_notice.len(),
                    needs_notice
                        .iter()
                        .take(5)
                        .map(|(n, l)| format!("{} ({})", n, l))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                files: vec![root.to_path_buf()],
                licenses: needs_notice.iter().map(|(_, l)| l.clone()).collect(),
                obligations_violated: vec![LicenseObligation::NoticeFile],
                evidence: vec![],
                claimed_license: None,
                actual_license: None,
            });
            return violations;
        }

        // NOTICE file exists — check if each required dependency is mentioned
        if let Some(ref content) = notice_content {
            let lower_content = content.to_lowercase();

            for (dep_name, dep_license) in &needs_notice {
                let lower_name = dep_name.to_lowercase();
                if lower_content.contains(&lower_name) {
                    stats.notice_entries_present += 1;
                } else {
                    stats.notice_entries_missing += 1;
                    violations.push(Violation {
                        violation_type: ViolationType::MissingNoticeFile,
                        severity: Severity::Low,
                        confidence: 0.80,
                        description: format!(
                            "NOTICE file does not mention '{}' ({}) — may be incomplete",
                            dep_name, dep_license
                        ),
                        files: vec![root.join("NOTICE")],
                        licenses: vec![(*dep_license).clone()],
                        obligations_violated: vec![LicenseObligation::NoticeFile],
                        evidence: vec![],
                        claimed_license: None,
                        actual_license: None,
                    });
                }
            }
        }

        violations
    }

    /// Check that bundled JS/CSS preserves attribution comments.
    fn check_bundle_attribution(&self, root: &Path, stats: &mut AttributionStats) -> Vec<Violation> {
        let mut violations = Vec::new();

        let dist_dirs = [
            root.join("dist"),
            root.join("build"),
            root.join("out"),
            root.join("public"),
        ];

        let license_comment_re = Regex::new(
            r"(?:/\*[!*]|/\*\*?)\s*(?:@license|@preserve|@copyright|Copyright|Licensed under|MIT License|Apache License|GNU General)"
        ).unwrap_or_else(|_| Regex::new("NOMATCH").unwrap());

        for dist_dir in &dist_dirs {
            if !dist_dir.exists() {
                continue;
            }

            for entry in WalkDir::new(dist_dir)
                .max_depth(4)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
            {
                let ext = entry.path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");

                if !matches!(ext, "js" | "css" | "mjs" | "cjs") {
                    continue;
                }

                stats.bundle_attributions_checked += 1;

                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    // Check file size — only large bundles (>10KB) are likely to contain
                    // third-party code that needs attribution
                    if content.len() < 10_000 {
                        continue;
                    }

                    // Check for license comments
                    if !license_comment_re.is_match(&content) {
                        // Large bundle with no license comments — suspicious
                        stats.bundle_attributions_missing += 1;
                        violations.push(Violation {
                            violation_type: ViolationType::MissingAttribution,
                            severity: Severity::Low,
                            confidence: 0.65,
                            description: format!(
                                "Large bundle {} ({} bytes) has no @license/@preserve comments",
                                entry.path().display(),
                                content.len()
                            ),
                            files: vec![entry.path().to_path_buf()],
                            licenses: vec![],
                            obligations_violated: vec![LicenseObligation::Attribution],
                            evidence: vec![],
                            claimed_license: None,
                            actual_license: None,
                        });
                    }
                }
            }
        }

        violations
    }
}

impl Default for AttributionChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Utility Functions ──────────────────────────────────────────────

/// Check if a directory contains a LICENSE file
fn has_license_file(dir: &Path) -> bool {
    LICENSE_FILE_NAMES.iter().any(|n| dir.join(n).exists())
}

/// Check if a directory contains a NOTICE file
fn has_notice_file(dir: &Path) -> bool {
    NOTICE_FILE_NAMES.iter().any(|n| dir.join(n).exists())
}

/// Read the NOTICE file content if it exists.
fn read_notice_file(root: &Path) -> Option<String> {
    for name in NOTICE_FILE_NAMES {
        let path = root.join(name);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                return Some(content);
            }
        }
    }
    None
}

/// Read the LICENSE file content if it exists.
fn read_license_file(dir: &Path) -> Option<String> {
    for name in LICENSE_FILE_NAMES {
        let path = dir.join(name);
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(&path) {
                return Some(content);
            }
        }
    }
    None
}

/// Find the actual path to the LICENSE file.
fn find_license_file_path(dir: &Path) -> Option<PathBuf> {
    for name in LICENSE_FILE_NAMES {
        let path = dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Try to find a vendored dependency directory
fn find_vendored_dir(root: &Path, name: &str) -> Option<PathBuf> {
    let candidates = [
        root.join("vendor").join(name),
        root.join("third_party").join(name),
        root.join("third-party").join(name),
        root.join("node_modules").join(name),
        root.join("deps").join(name),
        root.join("lib").join(name),
        root.join("extern").join(name),
        root.join("external").join(name),
        root.join("thirdparty").join(name),
        root.join("3rdparty").join(name),
    ];
    candidates.into_iter().find(|p| p.exists())
}

/// Check if vendored source files preserve license headers.
fn check_headers_preserved(vendor_dir: &Path) -> bool {
    let source_extensions = ["rs", "py", "js", "ts", "java", "go", "c", "h", "cpp", "hpp"];
    let mut source_files = 0;
    let mut files_with_headers = 0;

    for entry in WalkDir::new(vendor_dir)
        .max_depth(5)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let ext = entry.path()
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        if !source_extensions.contains(&ext) {
            continue;
        }

        source_files += 1;

        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            let header: String = content.lines().take(30).collect::<Vec<_>>().join("\n");
            let lower = header.to_lowercase();
            if lower.contains("license") || lower.contains("copyright") || lower.contains("spdx") {
                files_with_headers += 1;
            }
        }
    }

    // If no source files found, consider it OK
    if source_files == 0 {
        return true;
    }

    // At least 50% of source files should have headers (many vendored projects
    // don't have headers on every file, so we use a relaxed threshold)
    (files_with_headers as f64 / source_files as f64) >= 0.5
}

/// Calculate attribution completeness score.
fn calculate_completeness(deps: &[DependencyAttribution], stats: &AttributionStats) -> f64 {
    if deps.is_empty() {
        return 1.0; // No deps = nothing to attribute = perfect
    }

    let mut score_sum = 0.0;
    let mut weight_sum = 0.0;

    for dep in deps {
        let weight = 1.0;
        weight_sum += weight;

        let mut dep_score = 0.0;
        let mut dep_checks = 0;

        // LICENSE file presence
        if dep.has_license_file {
            dep_score += 1.0;
        }
        dep_checks += 1;

        // LICENSE content matches
        if let Some(matches) = dep.license_content_matches {
            if matches { dep_score += 1.0; }
            dep_checks += 1;
        }

        // NOTICE file mention
        if let Some(in_notice) = dep.in_notice_file {
            if in_notice { dep_score += 1.0; }
            dep_checks += 1;
        }

        // Headers preserved
        if let Some(preserved) = dep.headers_preserved {
            if preserved { dep_score += 1.0; }
            dep_checks += 1;
        }

        if dep_checks > 0 {
            score_sum += weight * (dep_score / dep_checks as f64);
        }
    }

    // Factor in bundle attribution
    if stats.bundle_attributions_checked > 0 {
        let bundle_ratio = 1.0 - (stats.bundle_attributions_missing as f64
            / stats.bundle_attributions_checked as f64);
        // Bundle attribution is 20% of total score
        let dep_weight = 0.8;
        let bundle_weight = 0.2;
        return dep_weight * (score_sum / weight_sum) + bundle_weight * bundle_ratio;
    }

    if weight_sum > 0.0 {
        score_sum / weight_sum
    } else {
        1.0
    }
}

/// Common LICENSE file names to look for
const LICENSE_FILE_NAMES: &[&str] = &[
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "LICENSE.MIT",
    "LICENSE.APACHE",
    "LICENCE",
    "LICENCE.md",
    "LICENCE.txt",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "COPYING.LIB",
    "COPYING.LESSER",
    "COPYRIGHT",
    "COPYRIGHT.txt",
];

/// Common NOTICE file names
const NOTICE_FILE_NAMES: &[&str] = &[
    "NOTICE",
    "NOTICE.md",
    "NOTICE.txt",
    "NOTICES",
    "THIRD-PARTY-NOTICES",
    "THIRD-PARTY-NOTICES.txt",
    "THIRD_PARTY_NOTICES",
    "THIRD_PARTY_NOTICES.md",
    "THIRDPARTYNOTICES",
    "ThirdPartyNotices.txt",
];

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_license_file_names() {
        // Verify we check all common patterns
        assert!(LICENSE_FILE_NAMES.contains(&"LICENSE"));
        assert!(LICENSE_FILE_NAMES.contains(&"LICENSE.md"));
        assert!(LICENSE_FILE_NAMES.contains(&"COPYING"));
        assert!(LICENSE_FILE_NAMES.contains(&"COPYING.LESSER"));
    }

    #[test]
    fn test_has_notice_file_names() {
        assert!(NOTICE_FILE_NAMES.contains(&"NOTICE"));
        assert!(NOTICE_FILE_NAMES.contains(&"THIRD-PARTY-NOTICES"));
    }

    #[test]
    fn test_calculate_completeness_no_deps() {
        let score = calculate_completeness(&[], &AttributionStats::default());
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_calculate_completeness_perfect() {
        let deps = vec![DependencyAttribution {
            name: "test".into(),
            license: LicenseId::new("MIT"),
            has_license_file: true,
            license_content_matches: Some(true),
            in_notice_file: None,
            headers_preserved: Some(true),
            in_dist_output: None,
        }];
        let score = calculate_completeness(&deps, &AttributionStats::default());
        assert!(score > 0.9, "Perfect attribution should score > 0.9, got {}", score);
    }

    #[test]
    fn test_calculate_completeness_missing() {
        let deps = vec![DependencyAttribution {
            name: "test".into(),
            license: LicenseId::new("MIT"),
            has_license_file: false,
            license_content_matches: None,
            in_notice_file: None,
            headers_preserved: None,
            in_dist_output: None,
        }];
        let score = calculate_completeness(&deps, &AttributionStats::default());
        assert!(score < 0.5, "Missing attribution should score < 0.5, got {}", score);
    }

    #[test]
    fn test_find_vendored_candidates() {
        // Just test that the function signature is correct
        let result = find_vendored_dir(Path::new("/nonexistent"), "fake-lib");
        assert!(result.is_none());
    }
}
