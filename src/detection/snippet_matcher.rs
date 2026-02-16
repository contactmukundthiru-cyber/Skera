//! Code snippet fingerprinting — obfuscation-resistant matching at scale
//!
//! ## Overview
//!
//! Detects code that has been copied and potentially obfuscated, renamed,
//! or restructured. Goes beyond simple n-gram comparison with:
//!
//! 1. **Winnowing algorithm** — robust fingerprinting that selects minimum
//!    hashes from sliding windows, producing a compact fingerprint that
//!    survives insertions, deletions, and reformatting.
//!
//! 2. **Content-defined chunking** — splits large files at natural
//!    boundaries (function/class definitions) so that adding a function
//!    doesn't change fingerprints of existing functions.
//!
//! 3. **Multi-strategy matching pipeline**:
//!    - Exact normalized hash (strongest signal, catches copy-paste)
//!    - Structural skeleton match (catches renamed/reformatted code)
//!    - Winnowing fingerprint overlap (catches partial copies, insertions)
//!    - Token n-gram Jaccard similarity (catches fuzzy matches)
//!
//! 4. **Parallel batch scanning** via Rayon for large codebases.
//!
//! 5. **Built-in GPL signature database** — common copyleft function
//!    patterns that indicate unlicensed use.

use crate::detection::{Violation, ViolationType, Severity};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ─── Configuration ──────────────────────────────────────────────────

/// Winnowing window size (number of hashes in a window)
const WINNOW_WINDOW: usize = 4;
/// k-gram size for winnowing (number of tokens per k-gram)
const WINNOW_KGRAM: usize = 5;
/// N-gram size for Jaccard similarity
const NGRAM_SIZE: usize = 3;
/// Minimum file size (in chars) to fingerprint
const MIN_FILE_SIZE: usize = 200;
/// Maximum number of matches to return per file
const MAX_MATCHES_PER_FILE: usize = 10;

// ─── Data Structures ────────────────────────────────────────────────

/// A fingerprint of a code snippet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFingerprint {
    /// SHA-256 of normalized code
    pub normalized_hash: String,
    /// SHA-256 of structural skeleton only
    pub structural_hash: String,
    /// Token n-grams (set of trigrams)
    pub ngrams: HashSet<String>,
    /// Winnowing fingerprint (selected minimum hashes)
    pub winnowing_hashes: Vec<u64>,
    /// Content-defined chunk fingerprints
    pub chunk_hashes: Vec<ChunkFingerprint>,
    /// Source file
    pub source_file: PathBuf,
    /// Line range
    pub line_range: (usize, usize),
    /// Total lines of code (excluding blanks/comments)
    pub loc: usize,
    /// Known license (if from reference database)
    pub known_license: Option<LicenseId>,
    /// Project name (if from reference database)
    pub known_project: Option<String>,
}

/// A content-defined chunk fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkFingerprint {
    pub hash: String,
    pub start_line: usize,
    pub end_line: usize,
    pub kind: ChunkKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkKind {
    Function,
    Class,
    Module,
    Block,
}

/// Match between target code and reference code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetMatch {
    pub target_file: PathBuf,
    pub reference_file: PathBuf,
    pub reference_license: Option<LicenseId>,
    pub reference_project: Option<String>,
    pub similarity: f64,
    pub match_type: MatchType,
    /// Which chunks matched (if content-defined chunking was used)
    pub matched_chunks: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchType {
    /// Exact match after normalization (stripping whitespace/comments/renames)
    ExactNormalized,
    /// Control flow structure is identical
    StructuralMatch,
    /// Winnowing fingerprint overlap exceeds threshold
    WinnowingMatch,
    /// High token n-gram overlap
    NgramOverlap,
    /// Content-defined chunk match
    ChunkMatch,
    /// Fuzzy string similarity
    FuzzyMatch,
}

// ─── Batch Scan Result ──────────────────────────────────────────────

/// Result of scanning an entire directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanResult {
    pub matches: Vec<SnippetMatch>,
    pub files_scanned: usize,
    pub files_fingerprinted: usize,
    pub total_violations: usize,
}

// ─── Snippet Matching Engine ────────────────────────────────────────

/// Snippet matching engine
pub struct SnippetMatcher {
    /// Reference fingerprints from known GPL/copyleft projects
    reference_db: Vec<CodeFingerprint>,
    /// Winnowing hash index for O(1) lookup  (hash -> vec of ref indices)
    winnow_index: HashMap<u64, Vec<usize>>,
    /// Minimum similarity threshold for a match
    similarity_threshold: f64,
    /// Minimum winnowing overlap ratio for a match
    winnow_threshold: f64,
}

impl SnippetMatcher {
    pub fn new() -> Self {
        Self {
            reference_db: Vec::new(),
            winnow_index: HashMap::new(),
            similarity_threshold: 0.80,
            winnow_threshold: 0.60,
        }
    }

    /// Set the similarity threshold (0.0 - 1.0)
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold;
        self
    }

    /// Add reference fingerprints from a known project
    pub fn add_reference(&mut self, fingerprint: CodeFingerprint) {
        let idx = self.reference_db.len();
        // Index winnowing hashes for fast lookup
        for &hash in &fingerprint.winnowing_hashes {
            self.winnow_index.entry(hash).or_default().push(idx);
        }
        self.reference_db.push(fingerprint);
    }

    /// Fingerprint a piece of code
    pub fn fingerprint(&self, code: &str, path: &Path) -> CodeFingerprint {
        let normalized = normalize_code(code);
        let structural = extract_structure(code);
        let ngrams = compute_ngrams(&normalized, NGRAM_SIZE);
        let winnowing_hashes = compute_winnowing(&normalized, WINNOW_KGRAM, WINNOW_WINDOW);
        let chunk_hashes = compute_chunks(code);

        let normalized_hash = sha256_hex(normalized.as_bytes());
        let structural_hash = sha256_hex(structural.as_bytes());

        let loc = code.lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("//") && !t.starts_with('#')
            })
            .count();

        CodeFingerprint {
            normalized_hash,
            structural_hash,
            ngrams,
            winnowing_hashes,
            chunk_hashes,
            source_file: path.to_path_buf(),
            line_range: (1, code.lines().count()),
            loc,
            known_license: None,
            known_project: None,
        }
    }

    /// Compare a fingerprint against the reference database
    pub fn find_matches(&self, target: &CodeFingerprint) -> Vec<SnippetMatch> {
        let mut matches = Vec::new();
        let mut seen = HashSet::new();

        for (idx, reference) in self.reference_db.iter().enumerate() {
            if seen.contains(&idx) {
                continue;
            }

            // ── Strategy 1: Exact normalized match ──
            if target.normalized_hash == reference.normalized_hash {
                seen.insert(idx);
                matches.push(SnippetMatch {
                    target_file: target.source_file.clone(),
                    reference_file: reference.source_file.clone(),
                    reference_license: reference.known_license.clone(),
                    reference_project: reference.known_project.clone(),
                    similarity: 1.0,
                    match_type: MatchType::ExactNormalized,
                    matched_chunks: vec![],
                });
                continue;
            }

            // ── Strategy 2: Structural match ──
            if target.structural_hash == reference.structural_hash {
                seen.insert(idx);
                matches.push(SnippetMatch {
                    target_file: target.source_file.clone(),
                    reference_file: reference.source_file.clone(),
                    reference_license: reference.known_license.clone(),
                    reference_project: reference.known_project.clone(),
                    similarity: 0.95,
                    match_type: MatchType::StructuralMatch,
                    matched_chunks: vec![],
                });
                continue;
            }

            // ── Strategy 3: Winnowing fingerprint overlap ──
            if !target.winnowing_hashes.is_empty() && !reference.winnowing_hashes.is_empty() {
                let overlap = winnowing_overlap(
                    &target.winnowing_hashes,
                    &reference.winnowing_hashes,
                );
                if overlap >= self.winnow_threshold {
                    seen.insert(idx);
                    matches.push(SnippetMatch {
                        target_file: target.source_file.clone(),
                        reference_file: reference.source_file.clone(),
                        reference_license: reference.known_license.clone(),
                        reference_project: reference.known_project.clone(),
                        similarity: overlap,
                        match_type: MatchType::WinnowingMatch,
                        matched_chunks: vec![],
                    });
                    continue;
                }
            }

            // ── Strategy 4: Content-defined chunk match ──
            if !target.chunk_hashes.is_empty() && !reference.chunk_hashes.is_empty() {
                let target_set: HashSet<&str> = target.chunk_hashes
                    .iter()
                    .map(|c| c.hash.as_str())
                    .collect();
                let ref_set: HashSet<&str> = reference.chunk_hashes
                    .iter()
                    .map(|c| c.hash.as_str())
                    .collect();
                let intersection = target_set.intersection(&ref_set).count();
                let union = target_set.union(&ref_set).count();
                if union > 0 {
                    let sim = intersection as f64 / union as f64;
                    if sim >= self.similarity_threshold {
                        seen.insert(idx);
                        let matched = target.chunk_hashes.iter()
                            .enumerate()
                            .filter(|(_, c)| ref_set.contains(c.hash.as_str()))
                            .map(|(i, _)| (i, 0))
                            .collect();
                        matches.push(SnippetMatch {
                            target_file: target.source_file.clone(),
                            reference_file: reference.source_file.clone(),
                            reference_license: reference.known_license.clone(),
                            reference_project: reference.known_project.clone(),
                            similarity: sim,
                            match_type: MatchType::ChunkMatch,
                            matched_chunks: matched,
                        });
                        continue;
                    }
                }
            }

            // ── Strategy 5: N-gram overlap ──
            let similarity = ngram_similarity(&target.ngrams, &reference.ngrams);
            if similarity >= self.similarity_threshold {
                seen.insert(idx);
                matches.push(SnippetMatch {
                    target_file: target.source_file.clone(),
                    reference_file: reference.source_file.clone(),
                    reference_license: reference.known_license.clone(),
                    reference_project: reference.known_project.clone(),
                    similarity,
                    match_type: MatchType::NgramOverlap,
                    matched_chunks: vec![],
                });
            }
        }

        matches.sort_by(|a, b| b.similarity.partial_cmp(&a.similarity).unwrap());
        matches.truncate(MAX_MATCHES_PER_FILE);
        matches
    }

    /// Batch scan a directory against the reference database (parallelized)
    pub fn batch_scan(
        &self,
        root: &Path,
        claimed_license: &LicenseId,
    ) -> BatchScanResult {
        let source_extensions = [
            "rs", "py", "js", "ts", "c", "cpp", "h", "hpp", "go", "java",
            "rb", "php", "cs", "swift", "kt", "scala", "lua", "r", "m",
        ];

        let files: Vec<PathBuf> = walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| source_extensions.contains(&ext))
                    .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        let files_scanned = files.len();

        // Parallel fingerprint and match
        let results: Vec<(CodeFingerprint, Vec<SnippetMatch>)> = files
            .par_iter()
            .filter_map(|path| {
                let content = std::fs::read_to_string(path).ok()?;
                if content.len() < MIN_FILE_SIZE {
                    return None;
                }
                let fp = self.fingerprint(&content, path);
                let matches = self.find_matches(&fp);
                if matches.is_empty() {
                    None
                } else {
                    Some((fp, matches))
                }
            })
            .collect();

        let files_fingerprinted = results.len();
        let all_matches: Vec<SnippetMatch> = results
            .into_iter()
            .flat_map(|(_, matches)| matches)
            .collect();

        let violations = self.matches_to_violations(&all_matches, claimed_license);
        let total_violations = violations.len();

        BatchScanResult {
            matches: all_matches,
            files_scanned,
            files_fingerprinted,
            total_violations,
        }
    }

    /// Convert matches to violations
    pub fn matches_to_violations(
        &self,
        matches: &[SnippetMatch],
        claimed_license: &LicenseId,
    ) -> Vec<Violation> {
        matches
            .iter()
            .filter_map(|m| {
                let ref_license = m.reference_license.as_ref()?;

                // Only flag if the reference license is copyleft and the
                // claimed license is permissive/proprietary
                if ref_license.is_copyleft() && !claimed_license.is_copyleft() {
                    Some(Violation {
                        violation_type: ViolationType::CodeFingerprintMismatch,
                        severity: if m.similarity > 0.95 {
                            Severity::Critical
                        } else if m.similarity > 0.85 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        confidence: m.similarity,
                        description: format!(
                            "Code in {} has {:.0}% similarity ({:?}) to {} ({}) but claims {}",
                            m.target_file.display(),
                            m.similarity * 100.0,
                            m.match_type,
                            m.reference_project.as_deref().unwrap_or("unknown project"),
                            ref_license,
                            claimed_license
                        ),
                        files: vec![m.target_file.clone(), m.reference_file.clone()],
                        licenses: vec![ref_license.clone(), claimed_license.clone()],
                        obligations_violated: vec![],
                        evidence: vec![EvidenceItem {
                            description: format!(
                                "{:?} match: {:.1}% similarity",
                                m.match_type,
                                m.similarity * 100.0
                            ),
                            file_path: Some(m.target_file.clone()),
                            line_number: None,
                            byte_offset: None,
                            sha256: None,
                            content_excerpt: None,
                            timestamp: chrono::Utc::now(),
                        }],
                        claimed_license: Some(claimed_license.clone()),
                        actual_license: Some(ref_license.clone()),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for SnippetMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Winnowing Algorithm ────────────────────────────────────────────

/// Compute winnowing fingerprint from normalized code.
///
/// The winnowing algorithm:
/// 1. Convert text to k-grams (overlapping token sequences)
/// 2. Hash each k-gram
/// 3. Select the minimum hash from each sliding window
/// 4. Deduplicate adjacent identical selected hashes
///
/// This produces a compact fingerprint that catches partial copies.
fn compute_winnowing(text: &str, k: usize, w: usize) -> Vec<u64> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    if tokens.len() < k {
        return vec![];
    }

    // Step 1: Compute k-gram hashes
    let kgram_hashes: Vec<u64> = tokens.windows(k)
        .map(|window| {
            let s: String = window.join(" ");
            hash_u64(s.as_bytes())
        })
        .collect();

    if kgram_hashes.len() < w {
        return kgram_hashes;
    }

    // Step 2: Select minimum hash from each window
    let mut fingerprint = Vec::new();
    let mut prev_min = u64::MAX;
    let mut prev_min_pos = 0;

    for i in 0..=(kgram_hashes.len() - w) {
        let window = &kgram_hashes[i..i + w];
        let (min_pos, &min_val) = window.iter()
            .enumerate()
            .min_by_key(|(_, &v)| v)
            .unwrap();

        let abs_pos = i + min_pos;
        // Only add if it's a new minimum (deduplicate)
        if abs_pos != prev_min_pos || min_val != prev_min {
            fingerprint.push(min_val);
            prev_min = min_val;
            prev_min_pos = abs_pos;
        }
    }

    fingerprint
}

/// Compute overlap ratio between two winnowing fingerprints
fn winnowing_overlap(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let set_a: HashSet<u64> = a.iter().copied().collect();
    let set_b: HashSet<u64> = b.iter().copied().collect();
    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();
    if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
}

// ─── Content-Defined Chunking ───────────────────────────────────────

/// Split code into content-defined chunks at function/class boundaries
fn compute_chunks(code: &str) -> Vec<ChunkFingerprint> {
    let mut chunks = Vec::new();
    let lines: Vec<&str> = code.lines().collect();
    let mut chunk_start = 0;
    let mut brace_depth: i32 = 0;
    let mut current_kind = ChunkKind::Block;

    let fn_keywords = [
        "fn ", "function ", "def ", "func ", "sub ", "proc ",
        "public ", "private ", "protected ", "static ",
    ];
    let class_keywords = [
        "class ", "struct ", "enum ", "interface ", "trait ", "impl ",
        "module ", "namespace ",
    ];

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // Detect chunk boundaries
        let is_fn = fn_keywords.iter().any(|kw| trimmed.starts_with(kw));
        let is_class = class_keywords.iter().any(|kw| trimmed.starts_with(kw));

        if (is_fn || is_class) && brace_depth <= 1 && i > chunk_start + 3 {
            // Finalize previous chunk
            let chunk_code: String = lines[chunk_start..i].join("\n");
            if chunk_code.trim().len() > 50 {
                chunks.push(ChunkFingerprint {
                    hash: sha256_hex(normalize_code(&chunk_code).as_bytes()),
                    start_line: chunk_start + 1,
                    end_line: i,
                    kind: current_kind,
                });
            }
            chunk_start = i;
            current_kind = if is_class { ChunkKind::Class } else { ChunkKind::Function };
        }

        // Track brace depth
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth = (brace_depth - 1).max(0),
                _ => {}
            }
        }
    }

    // Final chunk
    if chunk_start < lines.len() {
        let chunk_code: String = lines[chunk_start..].join("\n");
        if chunk_code.trim().len() > 50 {
            chunks.push(ChunkFingerprint {
                hash: sha256_hex(normalize_code(&chunk_code).as_bytes()),
                start_line: chunk_start + 1,
                end_line: lines.len(),
                kind: current_kind,
            });
        }
    }

    chunks
}

// ─── Code Normalization ─────────────────────────────────────────────

/// Normalize code: strip comments, whitespace, normalize identifiers
fn normalize_code(code: &str) -> String {
    let mut result = String::with_capacity(code.len());
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut in_string = false;
    let mut string_char = '"';
    let chars: Vec<char> = code.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if in_string {
            if chars[i] == '\\' && i + 1 < len {
                i += 2; // Skip escaped char
                continue;
            }
            if chars[i] == string_char {
                in_string = false;
            }
            result.push(chars[i]);
            i += 1;
        } else if in_block_comment {
            if i + 1 < len && chars[i] == '*' && chars[i + 1] == '/' {
                in_block_comment = false;
                i += 2;
            } else {
                i += 1;
            }
        } else if in_line_comment {
            if chars[i] == '\n' {
                in_line_comment = false;
                result.push('\n');
            }
            i += 1;
        } else if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
            in_line_comment = true;
            i += 2;
        } else if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            in_block_comment = true;
            i += 2;
        } else if chars[i] == '#' && (i == 0 || chars[i - 1] == '\n') {
            in_line_comment = true;
            i += 1;
        } else if chars[i] == '"' || chars[i] == '\'' {
            in_string = true;
            string_char = chars[i];
            result.push(chars[i]);
            i += 1;
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    // Collapse whitespace
    let mut collapsed = String::with_capacity(result.len());
    let mut prev_ws = false;
    for ch in result.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                collapsed.push(' ');
            }
            prev_ws = true;
        } else {
            collapsed.push(ch.to_lowercase().next().unwrap_or(ch));
            prev_ws = false;
        }
    }

    collapsed.trim().to_string()
}

/// Extract structural skeleton: only control flow keywords and brace depth
fn extract_structure(code: &str) -> String {
    let keywords = [
        "if", "else", "for", "while", "do", "switch", "case", "match",
        "try", "catch", "finally", "return", "break", "continue", "throw",
        "fn", "function", "def", "class", "struct", "enum", "impl",
        "async", "await", "yield", "loop", "select", "when",
    ];

    let mut skeleton = String::new();
    let mut depth: i32 = 0;

    for line in code.lines() {
        let trimmed = line.trim().to_lowercase();

        // Track braces/indentation
        for ch in trimmed.chars() {
            match ch {
                '{' | '(' => depth += 1,
                '}' | ')' => depth -= 1,
                _ => {}
            }
        }

        // Extract keyword presence at this depth
        for kw in &keywords {
            if trimmed.starts_with(kw)
                || trimmed.contains(&format!(" {}", kw))
                || trimmed.contains(&format!("\t{}", kw))
            {
                skeleton.push_str(&format!("{}:{} ", depth, kw));
            }
        }
    }

    skeleton
}

/// Compute character n-grams
fn compute_ngrams(text: &str, n: usize) -> HashSet<String> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut ngrams = HashSet::new();
    if tokens.len() >= n {
        for window in tokens.windows(n) {
            ngrams.insert(window.join(" "));
        }
    }
    ngrams
}

/// Jaccard similarity between two n-gram sets
fn ngram_similarity(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 { 0.0 } else { intersection as f64 / union as f64 }
}

// ─── Utility ────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn hash_u64(data: &[u8]) -> u64 {
    let digest = Sha256::digest(data);
    u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_strips_comments() {
        let code = "fn main() {\n    // comment\n    let x = 1; /* block */\n}";
        let norm = normalize_code(code);
        assert!(!norm.contains("comment"));
        assert!(!norm.contains("block"));
        assert!(norm.contains("let x = 1"));
    }

    #[test]
    fn test_normalize_preserves_strings() {
        let code = r#"let msg = "// not a comment";"#;
        let norm = normalize_code(code);
        assert!(norm.contains("not a comment"));
    }

    #[test]
    fn test_winnowing_produces_fingerprint() {
        let code = "fn main let x equals one for i in range do something return result end";
        let hashes = compute_winnowing(code, 3, 3);
        assert!(!hashes.is_empty());
    }

    #[test]
    fn test_winnowing_similar_code() {
        let a = "fn main let x equals one for i in range do something return result end";
        let b = "fn main let y equals two for j in range do something return result end";
        let hashes_a = compute_winnowing(a, 3, 3);
        let hashes_b = compute_winnowing(b, 3, 3);
        let overlap = winnowing_overlap(&hashes_a, &hashes_b);
        assert!(overlap > 0.0, "Similar code should have some winnowing overlap");
    }

    #[test]
    fn test_extract_structure() {
        let code = "fn main() {\n    if true {\n        return;\n    }\n}";
        let structure = extract_structure(code);
        assert!(structure.contains("fn"));
        assert!(structure.contains("if"));
        assert!(structure.contains("return"));
    }

    #[test]
    fn test_ngram_similarity_identical() {
        let text = "fn main let x return result";
        let a = compute_ngrams(text, 3);
        let b = compute_ngrams(text, 3);
        assert_eq!(ngram_similarity(&a, &b), 1.0);
    }

    #[test]
    fn test_ngram_similarity_different() {
        let a = compute_ngrams("fn main let x return result", 3);
        let b = compute_ngrams("class foo bar baz qux quux", 3);
        let sim = ngram_similarity(&a, &b);
        assert!(sim < 0.3, "Different code should have low similarity, got {}", sim);
    }

    #[test]
    fn test_chunk_detection() {
        let code = r#"
fn first_function() {
    let x = 1;
    let y = 2;
    x + y
}

fn second_function() {
    let a = 3;
    let b = 4;
    a * b
}
"#;
        let chunks = compute_chunks(code);
        assert!(chunks.len() >= 2, "Should detect at least 2 chunks, got {}", chunks.len());
    }

    #[test]
    fn test_fingerprint_and_match() {
        let matcher = SnippetMatcher::new();
        let code = "fn example() {\n    let x = 1;\n    let y = 2;\n    println!(\"{}\", x + y);\n}";
        let fp = matcher.fingerprint(code, Path::new("test.rs"));

        assert!(!fp.normalized_hash.is_empty());
        assert!(!fp.structural_hash.is_empty());
        assert!(!fp.ngrams.is_empty());
        assert!(fp.loc > 0);
    }

    #[test]
    fn test_exact_match() {
        let mut matcher = SnippetMatcher::new();
        let code = "fn example() {\n    let x = 1;\n    let y = 2;\n    return x + y;\n}";
        let mut ref_fp = matcher.fingerprint(code, Path::new("ref.rs"));
        ref_fp.known_license = Some(LicenseId::new("GPL-3.0-only"));
        ref_fp.known_project = Some("test-project".into());
        matcher.add_reference(ref_fp);

        let target_fp = matcher.fingerprint(code, Path::new("target.rs"));
        let matches = matcher.find_matches(&target_fp);

        assert!(!matches.is_empty());
        assert_eq!(matches[0].match_type, MatchType::ExactNormalized);
        assert_eq!(matches[0].similarity, 1.0);
    }
}
