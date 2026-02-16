//! JavaScript bundle forensics — piracy detection in minified bundles
//!
//! Identifies third-party libraries embedded (and potentially relicensed) inside
//! minified JS bundles. Works by:
//!
//! 1. **String fingerprinting** — unique error messages, API names, internal
//!    identifiers that survive minification
//! 2. **Structural pattern matching** — algorithm signatures (SHA-1 constants,
//!    crypto round values, IIFE patterns) that survive variable renaming
//! 3. **Version marker extraction** — version strings, build dates, known hashes
//! 4. **Copyright claim analysis** — extract all copyright notices and detect
//!    conflicts with identified third-party code
//! 5. **Byte composition mapping** — decompose a bundle into original vs.
//!    third-party code with byte ranges
//!
//! Designed for forensic-grade evidence that can be cited in legal proceedings
//! and academic papers.

use crate::detection::{Severity, Violation, ViolationType};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::js_analysis;
use super::js_signatures;
use super::deobfuscation::{JsDeobfuscator, DeobfuscationResult};

// ─── Known Library Signatures ──────────────────────────────────────

/// A signature that identifies a specific third-party library
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibrarySignature {
    /// Library name (e.g. "jQuery")
    pub name: String,
    /// Canonical author/copyright holder
    pub author: String,
    /// License SPDX identifier
    pub license: String,
    /// License family for obligation checking
    pub license_family: LicenseFamily,
    /// String fingerprints that survive minification
    pub string_fingerprints: Vec<StringFingerprint>,
    /// Structural patterns (algorithm constants, etc.)
    pub structural_patterns: Vec<StructuralPattern>,
    /// Version detection patterns
    pub version_patterns: Vec<VersionPattern>,
    /// Minimum number of fingerprints required for a positive match
    pub min_fingerprint_hits: usize,
    /// Expected copyright notice text (to check if stripped)
    pub expected_copyright: String,
    /// URL to canonical source for verification
    pub canonical_source: String,
    /// Commercial use restrictions
    pub commercial_restriction: Option<String>,
}

/// How restrictive is the license?
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseFamily {
    /// MIT, BSD, ISC — require attribution only
    Permissive,
    /// Apache 2.0 — require NOTICE file
    PermissiveNotice,
    /// LGPL — linking restrictions
    WeakCopyleft,
    /// GPL — full copyleft
    StrongCopyleft,
    /// Prosperity, PolyForm, etc. — commercial use restricted
    CommercialRestricted,
    /// SSPL, BSL — source-available but not open-source
    SourceAvailable,
    /// Proprietary — no redistribution
    Proprietary,
}

/// A string that uniquely identifies a library even after minification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringFingerprint {
    /// The string to search for (exact match)
    pub pattern: String,
    /// What this string represents
    pub description: String,
    /// Confidence that this string uniquely identifies the library (0.0-1.0)
    pub confidence: f64,
    /// Whether this is a version-specific fingerprint
    pub version_specific: bool,
}

/// A structural pattern — algorithm constants, magic numbers, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralPattern {
    /// Pattern type
    pub kind: StructuralPatternKind,
    /// The pattern value
    pub value: String,
    /// What this pattern represents
    pub description: String,
    /// Confidence
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructuralPatternKind {
    /// Cryptographic constant (e.g. SHA-1 initial values)
    CryptoConstant,
    /// Algorithm-specific magic number
    MagicNumber,
    /// Module system pattern (CommonJS, AMD, IIFE)
    ModulePattern,
    /// Error message or internal string
    InternalString,
    /// Binary/hex constant
    HexConstant,
}

/// Pattern to extract version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionPattern {
    /// Regex to match (captured group 1 = version)
    pub regex: String,
    /// Description
    pub description: String,
}

// ─── Detection Results ─────────────────────────────────────────────

/// A detected library inside a bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedLibrary {
    /// Library name
    pub name: String,
    /// Detected version (if determinable)
    pub version: Option<String>,
    /// True license of this library
    pub true_license: String,
    /// License family
    pub license_family: LicenseFamily,
    /// Author/copyright holder
    pub author: String,
    /// Confidence of detection (0.0-1.0)
    pub confidence: f64,
    /// Which fingerprints matched
    pub matched_fingerprints: Vec<FingerprintMatch>,
    /// Approximate byte range in the bundle
    pub byte_range: Option<(usize, usize)>,
    /// Approximate percentage of the bundle
    pub percentage_of_bundle: f64,
    /// Whether the original copyright notice was found
    pub copyright_preserved: bool,
    /// Whether a LICENSE/NOTICE file accompanies the bundle
    pub attribution_file_present: bool,
    /// Commercial use restriction (if any)
    pub commercial_restriction: Option<String>,
}

/// A fingerprint that matched
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMatch {
    /// The fingerprint pattern that matched
    pub pattern: String,
    /// Byte offset where it was found
    pub byte_offset: usize,
    /// Line number (if applicable)
    pub line_number: Option<usize>,
    /// Description
    pub description: String,
    /// Confidence
    pub confidence: f64,
}

/// A copyright claim found in the bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyrightClaim {
    /// The raw copyright text
    pub text: String,
    /// Claimed holder
    pub holder: String,
    /// Claimed year(s)
    pub year: Option<String>,
    /// "All rights reserved" assertion
    pub all_rights_reserved: bool,
    /// Byte offset
    pub byte_offset: usize,
    /// Line number
    pub line_number: usize,
}

/// Complete forensic analysis of a JS bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleForensicReport {
    /// File analyzed
    pub file_path: PathBuf,
    /// SHA-256 hash of the file
    pub file_sha256: String,
    /// Total file size in bytes
    pub file_size: usize,
    /// Libraries detected
    pub detected_libraries: Vec<DetectedLibrary>,
    /// Copyright claims found in the file
    pub copyright_claims: Vec<CopyrightClaim>,
    /// License violations detected
    pub violations: Vec<Violation>,
    /// Estimated percentage of third-party code
    pub third_party_percentage: f64,
    /// Estimated percentage of original code
    pub original_percentage: f64,
    /// Overall integrity assessment
    pub integrity_assessment: IntegrityAssessment,
    /// Advanced analysis results (entropy, obfuscation, fonts, etc.)
    pub analysis: Option<js_analysis::FileAnalysis>,
    /// De-obfuscation results (if applicable)
    pub deobfuscation: Option<DeobfuscationResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityAssessment {
    /// No issues found
    Clean,
    /// Minor attribution issues
    AttributionIssues,
    /// Serious license violations
    LicenseViolation,
    /// Systematic copyright fraud (stripped notices + false claims)
    CopyrightFraud,
}

// ─── The Scanner Engine ────────────────────────────────────────────

/// JavaScript bundle forensics scanner
pub struct JsBundleScanner {
    /// Known library signatures
    signatures: Vec<LibrarySignature>,
}

impl JsBundleScanner {
    /// Create a new scanner with signatures loaded from the TOML database.
    /// All signatures come from `data/signatures/*.toml` — NO hardcoding.
    pub fn new() -> Self {
        Self {
            signatures: js_signatures::signature_database().to_vec(),
        }
    }

    /// Create a scanner with custom signatures
    pub fn with_signatures(signatures: Vec<LibrarySignature>) -> Self {
        Self { signatures }
    }

    /// Add a custom signature to the database
    pub fn add_signature(&mut self, sig: LibrarySignature) {
        self.signatures.push(sig);
    }

    /// Analyze a single JS file for embedded third-party code
    pub fn analyze_file(&self, path: &Path) -> Result<BundleForensicReport, std::io::Error> {
        let original_content = std::fs::read_to_string(path)?;
        let raw_bytes = std::fs::read(path)?;
        let sha256 = hex::encode(Sha256::digest(&raw_bytes));

        // Phase 0: De-obfuscation — recover original strings before fingerprinting
        let deobfuscator = JsDeobfuscator::new();
        let deob_result = deobfuscator.deobfuscate(&original_content);
        let content = if !deob_result.transformations.is_empty() {
            tracing::info!(
                "De-obfuscated {} — {} transformations, obfuscation score: {:.2}",
                path.display(),
                deob_result.transformations.len(),
                deob_result.obfuscation_score
            );
            deob_result.cleaned.clone()
        } else {
            original_content.clone()
        };

        let mut report = BundleForensicReport {
            file_path: path.to_path_buf(),
            file_sha256: sha256,
            file_size: raw_bytes.len(),
            detected_libraries: Vec::new(),
            copyright_claims: Vec::new(),
            violations: Vec::new(),
            third_party_percentage: 0.0,
            original_percentage: 100.0,
            integrity_assessment: IntegrityAssessment::Clean,
            analysis: None,
            deobfuscation: if !deob_result.transformations.is_empty() {
                Some(deob_result)
            } else {
                None
            },
        };

        // Phase 1: Extract copyright claims from ORIGINAL content (before de-obfuscation)
        // Copyright claims should be captured as-is for evidence
        report.copyright_claims = self.extract_copyright_claims(&original_content);

        // Phase 2: Detect embedded libraries
        for sig in &self.signatures {
            if let Some(detected) = self.detect_library(&content, &raw_bytes, sig, path) {
                report.detected_libraries.push(detected);
            }
        }

        // Phase 3: Check for attribution files alongside the bundle
        let bundle_dir = path.parent().unwrap_or(Path::new("."));
        let has_attribution = self.check_attribution_files(bundle_dir);
        for lib in &mut report.detected_libraries {
            lib.attribution_file_present = has_attribution;
        }

        // Phase 4: Generate violations
        report.violations = self.generate_violations(&report);

        // Phase 5: Compute composition
        let total_third_party: f64 = report
            .detected_libraries
            .iter()
            .map(|l| l.percentage_of_bundle)
            .sum();
        report.third_party_percentage = total_third_party.min(100.0);
        report.original_percentage = (100.0 - total_third_party).max(0.0);

        // Phase 6: Integrity assessment
        report.integrity_assessment = self.assess_integrity(&report);

        // Phase 7: Advanced analysis (entropy, fonts, obfuscation, minifier)
        report.analysis = Some(js_analysis::full_analysis(&content));

        Ok(report)
    }

    /// Analyze all JS files in a directory (e.g., an unpacked Chrome extension)
    pub fn analyze_directory(&self, dir: &Path) -> Result<Vec<BundleForensicReport>, std::io::Error> {
        let mut reports = Vec::new();

        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| {
                        matches!(ext, "js" | "mjs" | "cjs" | "css" | "htm" | "html")
                    })
                    .unwrap_or(false)
            })
        {
            match self.analyze_file(entry.path()) {
                Ok(report) => reports.push(report),
                Err(e) => {
                    tracing::warn!("Failed to analyze {}: {}", entry.path().display(), e);
                }
            }
        }

        Ok(reports)
    }

    // ─── Internal Methods ──────────────────────────────────────────

    /// Detect a specific library in a bundle
    fn detect_library(
        &self,
        content: &str,
        raw_bytes: &[u8],
        sig: &LibrarySignature,
        _file_path: &Path,
    ) -> Option<DetectedLibrary> {
        let mut matches = Vec::new();

        // Check string fingerprints
        for fp in &sig.string_fingerprints {
            if let Some(offset) = content.find(&fp.pattern) {
                let line_number = content[..offset].matches('\n').count() + 1;
                matches.push(FingerprintMatch {
                    pattern: fp.pattern.clone(),
                    byte_offset: offset,
                    line_number: Some(line_number),
                    description: fp.description.clone(),
                    confidence: fp.confidence,
                });
            }
        }

        // Check structural patterns
        for sp in &sig.structural_patterns {
            if let Some(offset) = content.find(&sp.value) {
                matches.push(FingerprintMatch {
                    pattern: sp.value.clone(),
                    byte_offset: offset,
                    line_number: None,
                    description: sp.description.clone(),
                    confidence: sp.confidence,
                });
            }
        }

        // Need enough fingerprints for a positive match
        if matches.len() < sig.min_fingerprint_hits {
            return None;
        }

        // Calculate overall confidence
        let max_confidence = matches
            .iter()
            .map(|m| m.confidence)
            .fold(0.0f64, f64::max);
        let avg_confidence: f64 =
            matches.iter().map(|m| m.confidence).sum::<f64>() / matches.len() as f64;
        let confidence = (max_confidence * 0.6 + avg_confidence * 0.4).min(1.0);

        // Detect version
        let version = self.detect_version(content, sig);

        // Check if original copyright is preserved
        let copyright_preserved = content.contains(&sig.expected_copyright)
            || content.contains(&sig.author);

        // Estimate byte range and percentage
        let (byte_range, percentage) =
            self.estimate_byte_range(content, raw_bytes.len(), &matches, sig);

        Some(DetectedLibrary {
            name: sig.name.clone(),
            version,
            true_license: sig.license.clone(),
            license_family: sig.license_family,
            author: sig.author.clone(),
            confidence,
            matched_fingerprints: matches,
            byte_range,
            percentage_of_bundle: percentage,
            copyright_preserved,
            attribution_file_present: false,
            commercial_restriction: sig.commercial_restriction.clone(),
        })
    }

    /// Detect the version of a library from its content
    fn detect_version(&self, content: &str, sig: &LibrarySignature) -> Option<String> {
        for vp in &sig.version_patterns {
            if let Ok(re) = regex::Regex::new(&vp.regex) {
                if let Some(caps) = re.captures(content) {
                    if let Some(version) = caps.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }
        None
    }

    /// Estimate the byte range occupied by a library
    fn estimate_byte_range(
        &self,
        content: &str,
        total_size: usize,
        matches: &[FingerprintMatch],
        _sig: &LibrarySignature,
    ) -> (Option<(usize, usize)>, f64) {
        if matches.is_empty() {
            return (None, 0.0);
        }

        let min_offset = matches.iter().map(|m| m.byte_offset).min().unwrap_or(0);
        let max_offset = matches.iter().map(|m| m.byte_offset).max().unwrap_or(0);

        // Extend to likely boundaries (start of function scope, etc.)
        // Look backward from min_offset to find a likely boundary
        let start = content[..min_offset]
            .rfind("var ")
            .or_else(|| content[..min_offset].rfind("function"))
            .or_else(|| content[..min_offset].rfind("(function"))
            .unwrap_or(min_offset);

        // Look forward from max_offset to find likely end
        let search_end = (max_offset + 5000).min(content.len());
        let end = content[max_offset..search_end]
            .find(";var ")
            .or_else(|| content[max_offset..search_end].find("}).call"))
            .or_else(|| content[max_offset..search_end].find("})("))
            .map(|i| max_offset + i)
            .unwrap_or(max_offset + 1000);

        let range_size = end.saturating_sub(start);
        let percentage = (range_size as f64 / total_size as f64) * 100.0;

        (Some((start, end)), percentage)
    }

    /// Extract all copyright claims from the content
    fn extract_copyright_claims(&self, content: &str) -> Vec<CopyrightClaim> {
        let mut claims = Vec::new();
        let copyright_re = regex::Regex::new(
            r"(?i)(?:copyright|©|\(c\))\s*(?:(\d{4}(?:\s*[-–,]\s*\d{4})?)?\s*,?\s*)([^*/\n\r]{3,80})"
        ).unwrap();
        let all_rights_re = regex::Regex::new(r"(?i)all\s+rights\s+reserved").unwrap();

        for (line_idx, line) in content.lines().enumerate() {
            for cap in copyright_re.captures_iter(line) {
                let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
                let year = cap.get(1).map(|m| m.as_str().to_string());
                let holder = cap
                    .get(2)
                    .map(|m| m.as_str().trim().trim_end_matches('.').to_string())
                    .unwrap_or_default();

                let byte_offset = content[..content.len().min(
                    content
                        .lines()
                        .take(line_idx)
                        .map(|l| l.len() + 1)
                        .sum::<usize>(),
                )]
                .len();

                let all_rights = all_rights_re.is_match(line);

                claims.push(CopyrightClaim {
                    text: full_match.to_string(),
                    holder,
                    year,
                    all_rights_reserved: all_rights,
                    byte_offset,
                    line_number: line_idx + 1,
                });
            }
        }

        claims
    }

    /// Check if attribution files exist alongside the bundle
    fn check_attribution_files(&self, dir: &Path) -> bool {
        let names = [
            "LICENSE",
            "LICENSE.md",
            "LICENSE.txt",
            "NOTICE",
            "NOTICE.md",
            "NOTICE.txt",
            "ATTRIBUTION",
            "ATTRIBUTION.md",
            "THIRD_PARTY",
            "THIRD_PARTY.md",
            "THIRD_PARTY_NOTICES",
            "THIRD_PARTY_NOTICES.md",
            "CREDITS",
            "CREDITS.md",
            "COPYING",
        ];
        names.iter().any(|n| dir.join(n).exists())
    }

    /// Generate violations from detected libraries and copyright claims
    fn generate_violations(&self, report: &BundleForensicReport) -> Vec<Violation> {
        let mut violations = Vec::new();

        for lib in &report.detected_libraries {
            // V1: Copyright notice stripped
            if !lib.copyright_preserved {
                violations.push(Violation {
                    violation_type: ViolationType::StrippedLicense,
                    severity: Severity::High,
                    confidence: lib.confidence,
                    description: format!(
                        "{} ({}) embedded in {} — original copyright '{}' STRIPPED",
                        lib.name,
                        lib.true_license,
                        report.file_path.display(),
                        lib.author
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![LicenseId::new(&lib.true_license)],
                    obligations_violated: vec![],
                    evidence: lib
                        .matched_fingerprints
                        .iter()
                        .map(|fp| EvidenceItem {
                            description: format!(
                                "Library identified by: {} (at byte {})",
                                fp.description, fp.byte_offset
                            ),
                            file_path: Some(report.file_path.clone()),
                            line_number: fp.line_number,
                            byte_offset: Some(fp.byte_offset as u64),
                            sha256: None,
                            content_excerpt: Some(fp.pattern.clone()),
                            timestamp: chrono::Utc::now(),
                        })
                        .collect(),
                    claimed_license: None,
                    actual_license: Some(LicenseId::new(&lib.true_license)),
                });
            }

            // V2: No attribution file
            if !lib.attribution_file_present
                && (lib.license_family == LicenseFamily::Permissive
                    || lib.license_family == LicenseFamily::PermissiveNotice)
            {
                violations.push(Violation {
                    violation_type: ViolationType::MissingAttribution,
                    severity: Severity::High,
                    confidence: lib.confidence,
                    description: format!(
                        "{} ({}) requires attribution — NO LICENSE/NOTICE/ATTRIBUTION file found in package",
                        lib.name, lib.true_license
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![LicenseId::new(&lib.true_license)],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: Some(LicenseId::new(&lib.true_license)),
                });
            }

            // V3: Commercial restriction violated
            if let Some(ref restriction) = lib.commercial_restriction {
                violations.push(Violation {
                    violation_type: ViolationType::CommercialUseViolation,
                    severity: Severity::Critical,
                    confidence: lib.confidence,
                    description: format!(
                        "{} ({}) — COMMERCIAL USE PROHIBITED: {}",
                        lib.name, lib.true_license, restriction
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: vec![LicenseId::new(&lib.true_license)],
                    obligations_violated: vec![],
                    evidence: vec![],
                    claimed_license: None,
                    actual_license: Some(LicenseId::new(&lib.true_license)),
                });
            }

            // V4: False copyright claim — "All rights reserved" on third-party code
            let false_claims: Vec<_> = report
                .copyright_claims
                .iter()
                .filter(|c| {
                    c.all_rights_reserved
                        && !c.holder.contains(&lib.author)
                        && c.holder.len() > 2
                })
                .collect();

            if !false_claims.is_empty() && !lib.copyright_preserved {
                for claim in &false_claims {
                    violations.push(Violation {
                        violation_type: ViolationType::LicenseTextTampering,
                        severity: Severity::Critical,
                        confidence: lib.confidence * 0.95,
                        description: format!(
                            "FALSE COPYRIGHT CLAIM: '{}' asserts 'All rights reserved' over {} code ({}, by {}). \
                             Original copyright stripped and replaced. Potential DMCA §1202 violation.",
                            claim.holder,
                            lib.name,
                            lib.true_license,
                            lib.author
                        ),
                        files: vec![report.file_path.clone()],
                        licenses: vec![LicenseId::new(&lib.true_license)],
                        obligations_violated: vec![],
                        evidence: vec![
                            EvidenceItem {
                                description: format!(
                                    "False claim at line {}: '{}'",
                                    claim.line_number, claim.text
                                ),
                                file_path: Some(report.file_path.clone()),
                                line_number: Some(claim.line_number),
                                byte_offset: Some(claim.byte_offset as u64),
                                sha256: None,
                                content_excerpt: Some(claim.text.clone()),
                                timestamp: chrono::Utc::now(),
                            },
                        ],
                        claimed_license: None,
                        actual_license: Some(LicenseId::new(&lib.true_license)),
                    });
                }
            }
        }

        // V5: "All rights reserved" on a file with ANY third-party code
        if !report.detected_libraries.is_empty() {
            let blanket_claims: Vec<_> = report
                .copyright_claims
                .iter()
                .filter(|c| c.all_rights_reserved)
                .collect();

            if !blanket_claims.is_empty() {
                let lib_names: Vec<_> = report
                    .detected_libraries
                    .iter()
                    .map(|l| format!("{} ({})", l.name, l.true_license))
                    .collect();

                violations.push(Violation {
                    violation_type: ViolationType::LicenseTextTampering,
                    severity: Severity::Critical,
                    confidence: 0.99,
                    description: format!(
                        "BLANKET FALSE COPYRIGHT: File contains {} third-party libraries [{}] \
                         but claims 'All rights reserved' — provably false legal assertion. \
                         {:.1}% of the file is third-party code.",
                        report.detected_libraries.len(),
                        lib_names.join(", "),
                        report.third_party_percentage,
                    ),
                    files: vec![report.file_path.clone()],
                    licenses: report
                        .detected_libraries
                        .iter()
                        .map(|l| LicenseId::new(&l.true_license))
                        .collect(),
                    obligations_violated: vec![],
                    evidence: blanket_claims
                        .iter()
                        .map(|c| EvidenceItem {
                            description: format!("False claim: '{}'", c.text),
                            file_path: Some(report.file_path.clone()),
                            line_number: Some(c.line_number),
                            byte_offset: Some(c.byte_offset as u64),
                            sha256: None,
                            content_excerpt: Some(c.text.clone()),
                            timestamp: chrono::Utc::now(),
                        })
                        .collect(),
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        violations
    }

    /// Assess overall integrity
    fn assess_integrity(&self, report: &BundleForensicReport) -> IntegrityAssessment {
        let has_false_claims = report
            .copyright_claims
            .iter()
            .any(|c| c.all_rights_reserved);
        let has_stripped = report
            .detected_libraries
            .iter()
            .any(|l| !l.copyright_preserved);
        let has_commercial_violation = report
            .detected_libraries
            .iter()
            .any(|l| l.commercial_restriction.is_some());

        if has_false_claims && has_stripped {
            IntegrityAssessment::CopyrightFraud
        } else if has_commercial_violation || has_stripped {
            IntegrityAssessment::LicenseViolation
        } else if !report.detected_libraries.is_empty()
            && report
                .detected_libraries
                .iter()
                .any(|l| !l.attribution_file_present)
        {
            IntegrityAssessment::AttributionIssues
        } else {
            IntegrityAssessment::Clean
        }
    }
}

impl Default for JsBundleScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Signature Database ────────────────────────────────────────────
//
// ALL signatures are now loaded from TOML data files:
//   data/signatures/libraries.toml  — 55+ JS library fingerprints
//   data/signatures/assets.toml     — fonts, CSS frameworks, icon sets
//
// To add a new signature, edit those TOML files. Zero Rust changes needed.
// See js_signatures.rs for the loader and schema documentation.

// ─── Report Formatting ─────────────────────────────────────────────

impl BundleForensicReport {
    /// Render as Markdown
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str(&format!("# JS Bundle Forensic Report: `{}`\n\n",
            self.file_path.file_name().unwrap_or_default().to_string_lossy()));
        md.push_str(&format!("**SHA-256**: `{}`  \n", self.file_sha256));
        md.push_str(&format!("**Size**: {} bytes  \n", self.file_size));
        md.push_str(&format!("**Integrity**: {:?}  \n", self.integrity_assessment));
        md.push_str(&format!("**Composition**: {:.1}% third-party, {:.1}% original  \n\n",
            self.third_party_percentage, self.original_percentage));
        if let Some(ref a) = self.analysis {
            md.push_str(&format!("**Entropy**: {:.2} bits/byte  \n", a.entropy));
            md.push_str(&format!("**Obfuscation**: {:.0}%  \n", a.obfuscation.score * 100.0));
            if let Some(ref m) = a.minifier {
                md.push_str(&format!("**Minifier**: {} ({:.0}%)  \n", m.name, m.confidence * 100.0));
            }
            if !a.font_references.is_empty() {
                md.push_str(&format!("**Font References**: {}  \n", a.font_references.len()));
            }
            md.push('\n');
        }
        md.push_str("## Copyright Claims Found\n\n");
        md.push_str("| Line | Holder | Year | All Rights Reserved |\n");
        md.push_str("|------|--------|------|--------------------|\\n");
        for c in &self.copyright_claims {
            md.push_str(&format!("| {} | {} | {} | {} |\n",
                c.line_number, c.holder, c.year.as_deref().unwrap_or("—"),
                if c.all_rights_reserved { "✅ YES" } else { "❌ No" }));
        }
        md.push('\n');
        md.push_str("## Detected Third-Party Libraries\n\n");
        for lib in &self.detected_libraries {
            md.push_str(&format!("### {} {}\n\n", lib.name,
                lib.version.as_deref().map(|v| format!("v{}", v)).unwrap_or_default()));
            md.push_str(&format!("- **License**: {} | **Author**: {} | **Confidence**: {:.1}%\n",
                lib.true_license, lib.author, lib.confidence * 100.0));
            md.push_str(&format!("- **Copyright**: {} | **Attribution**: {}\n",
                if lib.copyright_preserved { "✅" } else { "❌ STRIPPED" },
                if lib.attribution_file_present { "✅" } else { "❌ MISSING" }));
            md.push_str(&format!("- **Bundle %**: {:.1}%\n", lib.percentage_of_bundle));
            if let Some(ref r) = lib.commercial_restriction {
                md.push_str(&format!("- **⚠️ RESTRICTION**: {}\n", r));
            }
            if let Some((s, e)) = lib.byte_range {
                md.push_str(&format!("- **Bytes**: {}-{} ({} bytes)\n", s, e, e - s));
            }
            md.push_str("\n| Pattern | Location | Description | Confidence |\n");
            md.push_str("|---------|----------|-------------|------------|\n");
            for fp in &lib.matched_fingerprints {
                let loc = fp.line_number.map(|l| format!("L{}", l))
                    .unwrap_or_else(|| format!("@{}", fp.byte_offset));
                let pat = if fp.pattern.len() > 40 { format!("{}...", &fp.pattern[..40]) }
                    else { fp.pattern.clone() };
                md.push_str(&format!("| `{}` | {} | {} | {:.0}% |\n",
                    pat, loc, fp.description, fp.confidence * 100.0));
            }
            md.push('\n');
        }
        if !self.violations.is_empty() {
            md.push_str("## License Violations\n\n");
            md.push_str(&format!("**Total: {} violations**\n\n", self.violations.len()));
            for (i, v) in self.violations.iter().enumerate() {
                md.push_str(&format!("### V{}: {:?} — {:?}\n\n{}\n\n",
                    i + 1, v.severity, v.violation_type, v.description));
                for e in &v.evidence {
                    if let Some(ref ex) = e.content_excerpt {
                        md.push_str(&format!("> Evidence: `{}` ({})\n\n", ex, e.description));
                    }
                }
            }
        }
        md
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toml_signatures_loaded() {
        let scanner = JsBundleScanner::new();
        assert!(scanner.signatures.len() > 30,
            "Expected 30+ TOML sigs, got {}", scanner.signatures.len());
    }

    #[test]
    fn test_jquery_detection() {
        let scanner = JsBundleScanner::new();
        let content = "/* Copyright 2025 SomeCompany, Inc. All rights reserved. */\n\
            function init(){if(typeof window===\"undefined\")throw new Error(\"jQuery requires a window with a document\");\n\
            var $=jQuery.noConflict(true);$.fn.init.prototype=jQuery.fn;\n";
        let claims = scanner.extract_copyright_claims(content);
        assert!(!claims.is_empty());
        for sig in &scanner.signatures {
            if sig.name == "jQuery" {
                let d = scanner.detect_library(content, content.as_bytes(), sig, Path::new("t.js"));
                assert!(d.is_some(), "jQuery should be detected");
            }
        }
    }

    #[test]
    fn test_cryptojs_detection() {
        let scanner = JsBundleScanner::new();
        let content = "/* Copyright 2025 SomeCompany */\n\
            var CryptoJS={};var WordArray={},BufferedBlockAlgorithm={},EvpKDF={},\n\
            SerializableCipher={},PasswordBasedCipher={};\n";
        for sig in &scanner.signatures {
            if sig.name == "CryptoJS" {
                let d = scanner.detect_library(content, content.as_bytes(), sig, Path::new("t.js"));
                assert!(d.is_some(), "CryptoJS should be detected");
            }
        }
    }

    #[test]
    fn test_fuzzyset_detection() {
        let scanner = JsBundleScanner::new();
        let content = "var FuzzySet=function(){\"use strict\";return function(e,t,n,r){var o={};\n\
            o.gramSizeLower=n||2;o.gramSizeUpper=r||3;o.useLevenshtein=t!==false;\n";
        for sig in &scanner.signatures {
            if sig.name == "FuzzySet.js" {
                let d = scanner.detect_library(content, content.as_bytes(), sig, Path::new("t.js"));
                assert!(d.is_some(), "FuzzySet.js should be detected");
                assert!(d.unwrap().commercial_restriction.is_some());
            }
        }
    }

    #[test]
    fn test_react_detection() {
        let scanner = JsBundleScanner::new();
        let content = "var React={};React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED={};\n\
            var x=\"react.element\";var y=\"react.fragment\";\n";
        for sig in &scanner.signatures {
            if sig.name == "React" {
                let d = scanner.detect_library(content, content.as_bytes(), sig, Path::new("t.js"));
                assert!(d.is_some(), "React should be detected");
            }
        }
    }
}


