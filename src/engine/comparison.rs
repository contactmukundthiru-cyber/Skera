//! Two-target forensic comparison engine
//!
//! `skera compare <original> <suspect>` — the core forensic differentiator.
//! Runs both scans, then cross-references fingerprints, snippets, headers,
//! and structural patterns to produce a provenance diff report.

use crate::detection::similarity;
use crate::detection::snippet_matcher::SnippetMatcher;
use crate::detection::structural_fingerprint;
use crate::license::LicenseId;
use crate::SkeraResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Result of comparing two codebases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub original: String,
    pub suspect: String,
    pub matches: Vec<CodeMatch>,
    pub stripped_headers: Vec<StrippedHeader>,
    pub structural_matches: Vec<StructuralMatch>,
    pub overall_similarity: f64,
    pub verdict: ComparisonVerdict,
}

/// A matched code fragment between original and suspect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMatch {
    pub original_file: PathBuf,
    pub suspect_file: PathBuf,
    pub similarity: f64,
    pub match_type: MatchType,
    pub original_license: Option<LicenseId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchType {
    ExactHash,
    FuzzyHash,
    StructuralFingerprint,
    SnippetMatch,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExactHash => write!(f, "Exact Hash"),
            Self::FuzzyHash => write!(f, "Fuzzy Hash"),
            Self::StructuralFingerprint => write!(f, "Structural Fingerprint"),
            Self::SnippetMatch => write!(f, "Snippet Match"),
        }
    }
}

/// A license header present in original but missing in suspect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrippedHeader {
    pub original_file: PathBuf,
    pub suspect_file: PathBuf,
    pub original_header: String,
    pub license: Option<LicenseId>,
}

/// A structural (AST-level) match between files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralMatch {
    pub original_file: PathBuf,
    pub suspect_file: PathBuf,
    pub cfg_similarity: f64,
    pub api_overlap: f64,
    pub kgram_similarity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonVerdict {
    /// No significant code overlap
    Clean,
    /// Some overlap, likely coincidental
    LowRisk,
    /// Significant overlap, requires investigation
    Suspicious,
    /// Clear derivation with license violations
    LikelyInfringement,
    /// Definitive code theft with stripped attribution
    DefiniteInfringement,
}

impl std::fmt::Display for ComparisonVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "Clean — no significant overlap"),
            Self::LowRisk => write!(f, "Low Risk — minor overlap, likely coincidental"),
            Self::Suspicious => write!(f, "Suspicious — significant overlap, investigation required"),
            Self::LikelyInfringement => write!(f, "Likely Infringement — clear derivation with license violations"),
            Self::DefiniteInfringement => write!(f, "Definite Infringement — code theft with stripped attribution"),
        }
    }
}

/// The comparison engine
pub struct ComparisonEngine {
    #[allow(dead_code)]
    snippet_matcher: SnippetMatcher,
}

impl ComparisonEngine {
    pub fn new() -> Self {
        Self {
            snippet_matcher: SnippetMatcher::new(),
        }
    }

    /// Compare an original codebase against a suspect codebase
    pub fn compare(
        &self,
        original_dir: &Path,
        suspect_dir: &Path,
    ) -> SkeraResult<ComparisonReport> {
        tracing::info!(
            "Comparing {} (original) vs {} (suspect)",
            original_dir.display(),
            suspect_dir.display()
        );

        let mut matches: Vec<CodeMatch> = Vec::new();
        let mut stripped: Vec<StrippedHeader> = Vec::new();
        let mut structural: Vec<StructuralMatch> = Vec::new();

        // Build fingerprint maps for both sides
        let original_fps = self.build_fingerprint_map(original_dir);
        let suspect_fps = self.build_fingerprint_map(suspect_dir);

        // Cross-reference fingerprints (exact blake3 match)
        let mut exact_original: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut exact_suspect: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        for (ofp_hash, ofp_info) in &original_fps {
            if let Some(sfp_info) = suspect_fps.get(ofp_hash) {
                matches.push(CodeMatch {
                    original_file: ofp_info.path.clone(),
                    suspect_file: sfp_info.path.clone(),
                    similarity: 1.0,
                    match_type: MatchType::ExactHash,
                    original_license: ofp_info.license.clone(),
                });
                exact_original.insert(ofp_info.path.clone());
                exact_suspect.insert(sfp_info.path.clone());
            }
        }

        // TLSH + ssdeep fuzzy hash matching (catches cosmetic modifications)
        let code_exts = ["rs", "py", "js", "ts", "c", "cpp", "h", "go", "java", "rb"];
        let orig_files: Vec<PathBuf> = collect_source_files(original_dir, &code_exts);
        let sus_files: Vec<PathBuf> = collect_source_files(suspect_dir, &code_exts);

        // Build forensic hash profiles for files not already exact-matched
        let orig_profiles: Vec<(PathBuf, similarity::ForensicHashProfile, Option<LicenseId>)> =
            orig_files.iter()
                .filter(|f| !exact_original.contains(*f))
                .filter_map(|f| {
                    similarity::compute_profile_from_file(f).ok().map(|p| {
                        let lic = std::fs::read(f).ok()
                            .and_then(|c| extract_license_id_from_bytes(&c));
                        (f.clone(), p, lic)
                    })
                })
                .collect();
        let sus_profiles: Vec<(PathBuf, similarity::ForensicHashProfile)> =
            sus_files.iter()
                .filter(|f| !exact_suspect.contains(*f))
                .filter_map(|f| {
                    similarity::compute_profile_from_file(f).ok().map(|p| (f.clone(), p))
                })
                .collect();

        for (o_path, o_profile, o_license) in &orig_profiles {
            for (s_path, s_profile) in &sus_profiles {
                let result = similarity::compare_profiles(o_profile, s_profile);
                if result.combined_score > 0.5 {
                    matches.push(CodeMatch {
                        original_file: o_path.clone(),
                        suspect_file: s_path.clone(),
                        similarity: result.combined_score,
                        match_type: MatchType::FuzzyHash,
                        original_license: o_license.clone(),
                    });
                }
            }
        }

        // Structural fingerprint comparison for deeper analysis

        for of in &orig_files {
            let o_content = match std::fs::read_to_string(of) {
                Ok(c) if c.len() > 200 => c,
                _ => continue,
            };

            let o_sfp = structural_fingerprint::extract_fingerprint(&o_content);
            if o_sfp.cfg_signature.len() < 10 {
                continue;
            }

            let o_header = extract_license_header(&o_content);

            for sf in &sus_files {
                let s_content = match std::fs::read_to_string(sf) {
                    Ok(c) if c.len() > 200 => c,
                    _ => continue,
                };

                let s_sfp = structural_fingerprint::extract_fingerprint(&s_content);
                if s_sfp.cfg_signature.len() < 10 {
                    continue;
                }

                // Use the proper multi-dimensional comparison function
                let sim = structural_fingerprint::compare_fingerprints(&o_sfp, &s_sfp);

                if sim.combined_score > 0.5 {
                    structural.push(StructuralMatch {
                        original_file: of.clone(),
                        suspect_file: sf.clone(),
                        cfg_similarity: sim.cfg_similarity,
                        api_overlap: sim.api_overlap,
                        kgram_similarity: sim.kgram_similarity,
                    });

                    // Check if license header was stripped
                    if let Some(ref header) = o_header {
                        let s_header = extract_license_header(&s_content);
                        if s_header.is_none() {
                            stripped.push(StrippedHeader {
                                original_file: of.clone(),
                                suspect_file: sf.clone(),
                                original_header: header.clone(),
                                license: None,
                            });
                        }
                    }
                }
            }
        }

        // Calculate overall similarity
        let total_orig = orig_files.len().max(1) as f64;
        let match_count = (matches.len() + structural.len()) as f64;
        let overall_similarity = (match_count / total_orig).min(1.0);

        // Determine verdict
        let verdict = if overall_similarity > 0.8 && !stripped.is_empty() {
            ComparisonVerdict::DefiniteInfringement
        } else if overall_similarity > 0.6 || !stripped.is_empty() {
            ComparisonVerdict::LikelyInfringement
        } else if overall_similarity > 0.3 {
            ComparisonVerdict::Suspicious
        } else if overall_similarity > 0.1 {
            ComparisonVerdict::LowRisk
        } else {
            ComparisonVerdict::Clean
        };

        Ok(ComparisonReport {
            original: original_dir.display().to_string(),
            suspect: suspect_dir.display().to_string(),
            matches,
            stripped_headers: stripped,
            structural_matches: structural,
            overall_similarity,
            verdict,
        })
    }

    fn build_fingerprint_map(&self, dir: &Path) -> HashMap<String, FpInfo> {
        let mut map = HashMap::new();
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(content) = std::fs::read(entry.path()) {
                let hash = blake3::hash(&content).to_hex().to_string();
                let license = extract_license_id_from_bytes(&content);
                map.insert(
                    hash,
                    FpInfo {
                        path: entry.path().to_path_buf(),
                        license,
                    },
                );
            }
        }
        map
    }
}

struct FpInfo {
    path: PathBuf,
    license: Option<LicenseId>,
}

fn collect_source_files(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().is_file()
                && e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| exts.contains(&x))
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn extract_license_header(content: &str) -> Option<String> {
    let header_lines: Vec<&str> = content
        .lines()
        .take(15)
        .filter(|l| {
            let lower = l.to_lowercase();
            lower.contains("license") || lower.contains("copyright") || lower.contains("spdx")
        })
        .collect();

    if header_lines.is_empty() {
        None
    } else {
        Some(header_lines.join("\n"))
    }
}

fn extract_license_id_from_bytes(content: &[u8]) -> Option<LicenseId> {
    let text = std::str::from_utf8(content).ok()?;
    for line in text.lines().take(10) {
        if line.contains("SPDX-License-Identifier:") {
            let id = line.split("SPDX-License-Identifier:").nth(1)?.trim();
            return Some(LicenseId::new(id));
        }
    }
    None
}

