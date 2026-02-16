//! License text classifier
//!
//! Identifies license types from raw text content using multi-strategy
//! matching: SPDX headers, canonical text fingerprinting, fuzzy matching,
//! and structural analysis.

use super::{LicenseDb, LicenseId};
use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};

/// Result of classifying a piece of text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Most likely license
    pub license: LicenseId,
    /// Confidence score 0.0 - 1.0
    pub confidence: f64,
    /// Which detection method produced this match
    pub method: ClassificationMethod,
    /// Matched patterns or text excerpts
    pub evidence: Vec<String>,
    /// Alternative candidates
    pub alternatives: Vec<(LicenseId, f64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassificationMethod {
    /// Exact SPDX identifier found in text
    SpdxIdentifier,
    /// Matched canonical header patterns
    HeaderPattern,
    /// Fuzzy text similarity against known license texts
    FuzzyMatch,
    /// Structural analysis (clause presence/absence)
    StructuralAnalysis,
    /// Package manifest metadata (package.json, Cargo.toml, etc.)
    ManifestMetadata,
}

/// License classifier engine
pub struct LicenseClassifier {
    db: LicenseDb,
    spdx_matcher: AhoCorasick,
    header_matcher: AhoCorasick,
    spdx_ids: Vec<String>,
    header_license_map: Vec<(usize, usize)>, // (pattern_idx, license_idx)
}

impl LicenseClassifier {
    pub fn new() -> Self {
        let db = LicenseDb::new();
        let all = db.all();

        // Build SPDX identifier matcher
        let spdx_patterns: Vec<String> = all
            .iter()
            .flat_map(|l| l.spdx_patterns.iter().cloned())
            .collect();
        let spdx_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&spdx_patterns)
            .expect("Failed to build SPDX matcher");

        // Build header pattern matcher with mapping back to license
        let mut header_patterns = Vec::new();
        let mut header_license_map = Vec::new();
        for (li, license) in all.iter().enumerate() {
            for pattern in &license.header_patterns {
                header_license_map.push((header_patterns.len(), li));
                header_patterns.push(pattern.clone());
            }
        }
        let header_matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&header_patterns)
            .expect("Failed to build header matcher");

        Self {
            spdx_ids: spdx_patterns,
            db,
            spdx_matcher,
            header_matcher,
            header_license_map,
        }
    }

    /// Classify license text — returns the best match
    pub fn classify(&self, text: &str) -> Option<ClassificationResult> {
        let mut candidates: Vec<ClassificationResult> = Vec::new();

        // Strategy 1: SPDX identifier scan (highest confidence)
        if let Some(result) = self.detect_spdx_identifier(text) {
            candidates.push(result);
        }

        // Strategy 2: Header pattern matching
        candidates.extend(self.detect_header_patterns(text));

        // Strategy 3: Structural clause analysis
        if let Some(result) = self.detect_structural(text) {
            candidates.push(result);
        }

        // Return highest confidence match
        candidates.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        if let Some(mut best) = candidates.first().cloned() {
            // Attach alternatives
            best.alternatives = candidates
                .iter()
                .skip(1)
                .map(|c| (c.license.clone(), c.confidence))
                .collect();
            Some(best)
        } else {
            None
        }
    }

    /// Classify a package manifest (package.json, Cargo.toml, etc.)
    pub fn classify_manifest(&self, content: &str) -> Option<ClassificationResult> {
        // Check for "license" field in JSON
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
            if let Some(license) = json.get("license").and_then(|v| v.as_str()) {
                return Some(ClassificationResult {
                    license: LicenseId::new(license),
                    confidence: 0.95,
                    method: ClassificationMethod::ManifestMetadata,
                    evidence: vec![format!("package.json license field: \"{}\"", license)],
                    alternatives: vec![],
                });
            }
        }

        // Check for TOML license field
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("license")
                && (trimmed.contains('=') || trimmed.contains(':'))
            {
                let value = trimmed
                    .split(['=', ':'])
                    .nth(1)
                    .map(|v| v.trim().trim_matches('"').trim_matches('\''))
                    .unwrap_or("");
                if !value.is_empty() {
                    return Some(ClassificationResult {
                        license: LicenseId::new(value),
                        confidence: 0.90,
                        method: ClassificationMethod::ManifestMetadata,
                        evidence: vec![format!("Manifest license field: \"{}\"", value)],
                        alternatives: vec![],
                    });
                }
            }
        }

        None
    }

    /// Detect SPDX identifier in text (e.g., "SPDX-License-Identifier: MIT")
    fn detect_spdx_identifier(&self, text: &str) -> Option<ClassificationResult> {
        // First check for explicit SPDX header
        for line in text.lines().take(50) {
            let trimmed = line.trim();
            if let Some(rest) = trimmed
                .strip_prefix("SPDX-License-Identifier:")
                .or_else(|| trimmed.strip_prefix("# SPDX-License-Identifier:"))
                .or_else(|| trimmed.strip_prefix("// SPDX-License-Identifier:"))
                .or_else(|| trimmed.strip_prefix("/* SPDX-License-Identifier:"))
                .or_else(|| trimmed.strip_prefix("* SPDX-License-Identifier:"))
            {
                let id = rest.trim().trim_end_matches("*/").trim();
                if !id.is_empty() {
                    return Some(ClassificationResult {
                        license: LicenseId::new(id),
                        confidence: 0.99,
                        method: ClassificationMethod::SpdxIdentifier,
                        evidence: vec![trimmed.to_string()],
                        alternatives: vec![],
                    });
                }
            }
        }

        // Fall back to Aho-Corasick search for known SPDX IDs
        let mut matches: Vec<(String, usize)> = Vec::new();
        for mat in self.spdx_matcher.find_iter(text) {
            let id = &self.spdx_ids[mat.pattern().as_usize()];
            if let Some(entry) = matches.iter_mut().find(|(m, _)| m == id) {
                entry.1 += 1;
            } else {
                matches.push((id.clone(), 1));
            }
        }

        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches.first().map(|(id, count)| ClassificationResult {
            license: LicenseId::new(id),
            confidence: (0.7 + (*count as f64 * 0.05)).min(0.95),
            method: ClassificationMethod::SpdxIdentifier,
            evidence: vec![format!("SPDX ID '{}' found {} times", id, count)],
            alternatives: vec![],
        })
    }

    /// Detect license from header patterns
    fn detect_header_patterns(&self, text: &str) -> Vec<ClassificationResult> {
        let mut license_hits: std::collections::HashMap<usize, Vec<String>> =
            std::collections::HashMap::new();

        for mat in self.header_matcher.find_iter(text) {
            let pattern_idx = mat.pattern().as_usize();
            // Find which license this pattern belongs to
            for &(pi, li) in &self.header_license_map {
                if pi == pattern_idx {
                    license_hits
                        .entry(li)
                        .or_default()
                        .push(text[mat.start()..mat.end()].to_string());
                }
            }
        }

        let all_licenses = self.db.all();
        license_hits
            .into_iter()
            .map(|(li, evidence)| {
                let license = &all_licenses[li];
                let total_patterns = license.header_patterns.len();
                let hit_ratio = evidence.len() as f64 / total_patterns as f64;
                ClassificationResult {
                    license: license.id.clone(),
                    confidence: (0.5 + hit_ratio * 0.4).min(0.90),
                    method: ClassificationMethod::HeaderPattern,
                    evidence,
                    alternatives: vec![],
                }
            })
            .collect()
    }

    /// Structural analysis — detect license from clause presence
    fn detect_structural(&self, text: &str) -> Option<ClassificationResult> {
        let lower = text.to_lowercase();

        // Key structural indicators
        let has_patent_clause = lower.contains("patent") && lower.contains("grant");
        let has_copyleft = lower.contains("derivative work")
            && (lower.contains("same license") || lower.contains("same terms"));
        let has_network_clause = lower.contains("interact with it remotely")
            || lower.contains("network server")
            || lower.contains("over a computer network");
        let has_attribution = lower.contains("copyright notice")
            && lower.contains("permission notice");
        let has_no_warranty = lower.contains("as is")
            && lower.contains("without warranty");

        // Score-based classification
        if has_network_clause && has_copyleft {
            Some(ClassificationResult {
                license: LicenseId::new("AGPL-3.0-only"),
                confidence: 0.75,
                method: ClassificationMethod::StructuralAnalysis,
                evidence: vec![
                    "Network interaction clause detected".into(),
                    "Copyleft/derivative work clause detected".into(),
                ],
                alternatives: vec![],
            })
        } else if has_copyleft && has_patent_clause {
            Some(ClassificationResult {
                license: LicenseId::new("GPL-3.0-only"),
                confidence: 0.70,
                method: ClassificationMethod::StructuralAnalysis,
                evidence: vec![
                    "Copyleft clause detected".into(),
                    "Patent grant clause detected".into(),
                ],
                alternatives: vec![],
            })
        } else if has_copyleft && !has_patent_clause {
            Some(ClassificationResult {
                license: LicenseId::new("GPL-2.0-only"),
                confidence: 0.65,
                method: ClassificationMethod::StructuralAnalysis,
                evidence: vec!["Copyleft clause without patent grant".into()],
                alternatives: vec![],
            })
        } else if has_patent_clause && has_attribution && !has_copyleft {
            Some(ClassificationResult {
                license: LicenseId::new("Apache-2.0"),
                confidence: 0.70,
                method: ClassificationMethod::StructuralAnalysis,
                evidence: vec![
                    "Patent grant clause detected".into(),
                    "Attribution requirement detected".into(),
                ],
                alternatives: vec![],
            })
        } else if has_attribution && has_no_warranty && !has_copyleft && !has_patent_clause {
            Some(ClassificationResult {
                license: LicenseId::new("MIT"),
                confidence: 0.60,
                method: ClassificationMethod::StructuralAnalysis,
                evidence: vec![
                    "Attribution + no warranty, no copyleft/patent".into(),
                ],
                alternatives: vec![(LicenseId::new("BSD-2-Clause"), 0.55)],
            })
        } else {
            None
        }
    }
}

impl Default for LicenseClassifier {
    fn default() -> Self {
        Self::new()
    }
}
