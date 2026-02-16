//! Forensic similarity engine — TLSH + ssdeep dual-channel matching
//!
//! Two independent similarity channels that complement SHA-256 exact matching:
//!
//! 1. **TLSH** (Trend Micro Locality Sensitive Hashing) — if two files are 90%
//!    similar, their TLSH hashes will be very close. Detects structural similarity
//!    even after variable renaming, whitespace changes, and minor edits.
//!
//! 2. **ssdeep** (Context Triggered Piecewise Hashing) — the forensic standard.
//!    Identifies code blocks that have been slightly tweaked but are still
//!    identifiable as a specific copyrighted work. Courts understand ssdeep.
//!
//! Together they form an "impossible to escape" similarity layer: if someone
//! takes jQuery, renames variables, changes whitespace, and reorders some
//! functions, SHA-256 will miss it but TLSH + ssdeep will both flag it.

use serde::{Deserialize, Serialize};
use std::path::Path;

// ─── Types ─────────────────────────────────────────────────────────

/// A complete forensic hash profile for a file or code block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicHashProfile {
    /// SHA-256 exact hash
    pub sha256: String,
    /// TLSH locality-sensitive hash (None if content too short, <50 bytes)
    pub tlsh: Option<String>,
    /// ssdeep fuzzy hash
    pub ssdeep: Option<String>,
    /// Size of the input in bytes
    pub size: usize,
}

/// Result of comparing two forensic hash profiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityResult {
    /// TLSH distance (0 = identical, <100 = very similar, <200 = similar)
    pub tlsh_distance: Option<u32>,
    /// ssdeep match score (0-100, higher = more similar)
    pub ssdeep_score: Option<u32>,
    /// Combined similarity score (0.0-1.0)
    pub combined_score: f64,
    /// Human-readable assessment
    pub assessment: SimilarityAssessment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SimilarityAssessment {
    /// Near-identical (likely same file with minor formatting changes)
    NearIdentical,
    /// Highly similar (likely derived from same source)
    HighlySimilar,
    /// Moderately similar (shares significant code sections)
    ModeratelySimilar,
    /// Low similarity (some shared patterns)
    LowSimilarity,
    /// No meaningful similarity
    Distinct,
}

impl std::fmt::Display for SimilarityAssessment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NearIdentical => write!(f, "NEAR-IDENTICAL"),
            Self::HighlySimilar => write!(f, "HIGHLY SIMILAR"),
            Self::ModeratelySimilar => write!(f, "MODERATELY SIMILAR"),
            Self::LowSimilarity => write!(f, "LOW SIMILARITY"),
            Self::Distinct => write!(f, "DISTINCT"),
        }
    }
}

/// A reference hash entry for comparing against known libraries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceHash {
    /// Library name (e.g. "jQuery 3.6.0")
    pub name: String,
    /// TLSH hash of the canonical version
    pub tlsh: Option<String>,
    /// ssdeep hash of the canonical version
    pub ssdeep: Option<String>,
    /// License SPDX identifier
    pub license: String,
    /// Author / copyright holder
    pub author: String,
}

// ─── Core Functions ────────────────────────────────────────────────

/// Compute a full forensic hash profile for a byte slice.
pub fn compute_profile(data: &[u8]) -> ForensicHashProfile {
    use sha2::{Digest, Sha256};

    let sha256 = hex::encode(Sha256::digest(data));
    let tlsh = compute_tlsh(data);
    let ssdeep = compute_ssdeep(data);

    ForensicHashProfile {
        sha256,
        tlsh,
        ssdeep,
        size: data.len(),
    }
}

/// Compute a forensic hash profile from a file path.
pub fn compute_profile_from_file(path: &Path) -> Result<ForensicHashProfile, std::io::Error> {
    let data = std::fs::read(path)?;
    Ok(compute_profile(&data))
}

/// Compare two forensic hash profiles.
pub fn compare_profiles(a: &ForensicHashProfile, b: &ForensicHashProfile) -> SimilarityResult {
    // Exact match shortcut
    if a.sha256 == b.sha256 {
        return SimilarityResult {
            tlsh_distance: Some(0),
            ssdeep_score: Some(100),
            combined_score: 1.0,
            assessment: SimilarityAssessment::NearIdentical,
        };
    }

    let tlsh_distance = compare_tlsh(a.tlsh.as_deref(), b.tlsh.as_deref());
    let ssdeep_score = compare_ssdeep(a.ssdeep.as_deref(), b.ssdeep.as_deref());

    // Combine scores: normalize TLSH distance to 0.0-1.0 similarity
    let tlsh_similarity = tlsh_distance
        .map(|d| (1.0 - (d as f64 / 500.0).min(1.0)).max(0.0));
    let ssdeep_similarity = ssdeep_score
        .map(|s| s as f64 / 100.0);

    // Weighted combination: favor the stronger signal
    let combined = match (tlsh_similarity, ssdeep_similarity) {
        (Some(t), Some(s)) => {
            // Use the higher score to avoid false negatives
            // Weight: 60% max, 40% average
            let max_score = t.max(s);
            let avg_score = (t + s) / 2.0;
            max_score * 0.6 + avg_score * 0.4
        }
        (Some(t), None) => t,
        (None, Some(s)) => s,
        (None, None) => 0.0,
    };

    let assessment = if combined > 0.95 {
        SimilarityAssessment::NearIdentical
    } else if combined > 0.75 {
        SimilarityAssessment::HighlySimilar
    } else if combined > 0.50 {
        SimilarityAssessment::ModeratelySimilar
    } else if combined > 0.25 {
        SimilarityAssessment::LowSimilarity
    } else {
        SimilarityAssessment::Distinct
    };

    SimilarityResult {
        tlsh_distance,
        ssdeep_score,
        combined_score: combined,
        assessment,
    }
}

/// Compare a file against a database of reference hashes.
/// Returns all matches above the similarity threshold, sorted by score.
pub fn find_similar(
    profile: &ForensicHashProfile,
    references: &[ReferenceHash],
    min_score: f64,
) -> Vec<(ReferenceHash, SimilarityResult)> {
    let mut matches: Vec<_> = references
        .iter()
        .filter_map(|reference| {
            let ref_profile = ForensicHashProfile {
                sha256: String::new(), // Not used for similarity comparison
                tlsh: reference.tlsh.clone(),
                ssdeep: reference.ssdeep.clone(),
                size: 0,
            };
            let result = compare_profiles(profile, &ref_profile);
            if result.combined_score >= min_score {
                Some((reference.clone(), result))
            } else {
                None
            }
        })
        .collect();

    // Sort by combined score descending
    matches.sort_by(|a, b| b.1.combined_score.partial_cmp(&a.1.combined_score).unwrap());
    matches
}

// ─── TLSH Implementation ───────────────────────────────────────────

/// Compute TLSH hash for a byte slice.
/// Returns None if the input is too short (TLSH needs ≥50 bytes).
fn compute_tlsh(data: &[u8]) -> Option<String> {
    // TLSH requires sufficient data to build meaningful locality hash
    if data.len() < 50 {
        return None;
    }

    tlsh::hash_buf(data)
        .ok()
        .map(|hash| hash.to_string())
}

/// Compare two TLSH hashes. Returns distance (0 = identical).
fn compare_tlsh(a: Option<&str>, b: Option<&str>) -> Option<u32> {
    let (a_str, b_str) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };

    // tlsh::compare takes &str references directly and returns Result<u32, ...>
    tlsh::compare(a_str, b_str).ok()
}

// ─── ssdeep Implementation ─────────────────────────────────────────

/// Compute ssdeep fuzzy hash for a byte slice.
fn compute_ssdeep(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    Some(fuzzyhash::FuzzyHash::new(data).to_string())
}

/// Compare two ssdeep hashes. Returns match score (0-100).
fn compare_ssdeep(a: Option<&str>, b: Option<&str>) -> Option<u32> {
    let (a_str, b_str) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        _ => return None,
    };

    // fuzzyhash doesn't implement FromStr, so we need to create from bytes
    // and compare using compare_to
    let hash_a = fuzzyhash::FuzzyHash::new(a_str.as_bytes());
    let hash_b = fuzzyhash::FuzzyHash::new(b_str.as_bytes());

    hash_a.compare_to(&hash_b).map(|v| v as u32)
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_profile() {
        let data = b"Hello, this is a test of the forensic hash profile computation.";
        let profile = compute_profile(data);
        assert!(!profile.sha256.is_empty());
        assert_eq!(profile.size, data.len());
    }

    #[test]
    fn test_identical_comparison() {
        let data = b"This is a significantly long test string that should be enough for TLSH to generate a hash value from the content bytes provided here.";
        let p1 = compute_profile(data);
        let p2 = compute_profile(data);
        let r = compare_profiles(&p1, &p2);
        assert_eq!(r.assessment, SimilarityAssessment::NearIdentical);
        assert_eq!(r.combined_score, 1.0);
    }

    #[test]
    fn test_distinct_comparison() {
        let data1 = b"function jQuery(selector) { return new jQuery.fn.init(selector); }".repeat(10);
        let data2 = b"import tensorflow as tf; model = tf.keras.Sequential()".repeat(10);
        let p1 = compute_profile(&data1);
        let p2 = compute_profile(&data2);
        let r = compare_profiles(&p1, &p2);
        // These should be very different
        assert!(r.combined_score < 0.7);
    }

    #[test]
    fn test_ssdeep_generation() {
        let data = b"This is a test of ssdeep fuzzy hashing functionality.";
        let hash = compute_ssdeep(data);
        assert!(hash.is_some(), "ssdeep should produce a hash");
    }

    #[test]
    fn test_empty_input() {
        let data = b"";
        let profile = compute_profile(data);
        assert!(profile.tlsh.is_none());
        assert!(profile.ssdeep.is_none());
    }
}
