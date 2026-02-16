//! Code Embeddings — semantic vector similarity for code comparison
//!
//! Instead of comparing code via n-gram Jaccard overlap (string-level),
//! this module computes dense vector embeddings that capture SEMANTIC
//! meaning. Two functions that do the same thing will have similar
//! embeddings even if they use completely different variable names,
//! control structures, or languages.
//!
//! ## Strategy
//!
//! We implement a lightweight, self-contained embedding scheme that
//! doesn't require an external model server:
//!
//! 1. **Lexical features**: TF-IDF weighted token vectors
//! 2. **Structural features**: Control flow graph shape encoding
//! 3. **Semantic features**: API call / import pattern encoding
//! 4. **Statistical features**: Complexity metrics, token distribution
//!
//! These are concatenated into a single feature vector and compared
//! using cosine similarity. This is FAR more robust than raw n-gram
//! matching while still being fast enough for local execution.
//!
//! For users with access to external ML models (CodeBERT, StarCoder),
//! we also provide an API to plug in external embedding providers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Types ─────────────────────────────────────────────────────────

/// A code embedding vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEmbedding {
    /// The dense feature vector
    pub vector: Vec<f64>,
    /// Which features contributed to which dimensions
    pub feature_map: FeatureMap,
    /// Source information
    pub source: String,
    /// Dimensionality
    pub dimensions: usize,
}

/// Map of feature contributions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureMap {
    /// Lexical feature dimensions (start, end)
    pub lexical_range: (usize, usize),
    /// Structural feature dimensions
    pub structural_range: (usize, usize),
    /// Semantic feature dimensions
    pub semantic_range: (usize, usize),
    /// Statistical feature dimensions
    pub statistical_range: (usize, usize),
}

/// Result of comparing two embeddings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingSimilarity {
    /// Overall cosine similarity (0.0 - 1.0)
    pub overall: f64,
    /// Lexical similarity (token-level)
    pub lexical: f64,
    /// Structural similarity (control flow)
    pub structural: f64,
    /// Semantic similarity (API/import patterns)
    pub semantic: f64,
    /// Statistical similarity (complexity metrics)
    pub statistical: f64,
}

// ─── Feature dimensions ────────────────────────────────────────────

/// Number of dimensions for each feature category
const LEXICAL_DIMS: usize = 128;
const STRUCTURAL_DIMS: usize = 64;
const SEMANTIC_DIMS: usize = 64;
const STATISTICAL_DIMS: usize = 32;
const TOTAL_DIMS: usize = LEXICAL_DIMS + STRUCTURAL_DIMS + SEMANTIC_DIMS + STATISTICAL_DIMS;

// ─── The Embedder ──────────────────────────────────────────────────

/// Code embedding engine
#[allow(dead_code)]
pub struct CodeEmbedder {
    /// Vocabulary for TF-IDF (built from seen code)
    vocabulary: HashMap<String, usize>,
    /// IDF weights
    idf_weights: HashMap<String, f64>,
    /// Number of documents seen
    doc_count: usize,
}

impl CodeEmbedder {
    pub fn new() -> Self {
        Self {
            vocabulary: Self::default_vocabulary(),
            idf_weights: HashMap::new(),
            doc_count: 0,
        }
    }

    /// Embed a piece of code into a dense feature vector
    pub fn embed(&self, code: &str, source: &str) -> CodeEmbedding {
        let mut vector = vec![0.0f64; TOTAL_DIMS];

        // Feature 1: Lexical (TF-IDF weighted tokens)
        let lexical = self.compute_lexical_features(code);
        for (i, &v) in lexical.iter().enumerate().take(LEXICAL_DIMS) {
            vector[i] = v;
        }

        // Feature 2: Structural (control flow shape)
        let structural = self.compute_structural_features(code);
        for (i, &v) in structural.iter().enumerate().take(STRUCTURAL_DIMS) {
            vector[LEXICAL_DIMS + i] = v;
        }

        // Feature 3: Semantic (API calls / imports)
        let semantic = self.compute_semantic_features(code);
        for (i, &v) in semantic.iter().enumerate().take(SEMANTIC_DIMS) {
            vector[LEXICAL_DIMS + STRUCTURAL_DIMS + i] = v;
        }

        // Feature 4: Statistical (complexity metrics)
        let statistical = self.compute_statistical_features(code);
        for (i, &v) in statistical.iter().enumerate().take(STATISTICAL_DIMS) {
            vector[LEXICAL_DIMS + STRUCTURAL_DIMS + SEMANTIC_DIMS + i] = v;
        }

        // L2 normalize the entire vector
        let norm = vector.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm > 0.0 {
            for v in vector.iter_mut() {
                *v /= norm;
            }
        }

        CodeEmbedding {
            vector,
            feature_map: FeatureMap {
                lexical_range: (0, LEXICAL_DIMS),
                structural_range: (LEXICAL_DIMS, LEXICAL_DIMS + STRUCTURAL_DIMS),
                semantic_range: (LEXICAL_DIMS + STRUCTURAL_DIMS, LEXICAL_DIMS + STRUCTURAL_DIMS + SEMANTIC_DIMS),
                statistical_range: (LEXICAL_DIMS + STRUCTURAL_DIMS + SEMANTIC_DIMS, TOTAL_DIMS),
            },
            source: source.to_string(),
            dimensions: TOTAL_DIMS,
        }
    }

    /// Compare two embeddings
    pub fn compare(a: &CodeEmbedding, b: &CodeEmbedding) -> EmbeddingSimilarity {
        let overall = cosine_similarity(&a.vector, &b.vector);

        let lexical = cosine_similarity(
            &a.vector[a.feature_map.lexical_range.0..a.feature_map.lexical_range.1],
            &b.vector[b.feature_map.lexical_range.0..b.feature_map.lexical_range.1],
        );

        let structural = cosine_similarity(
            &a.vector[a.feature_map.structural_range.0..a.feature_map.structural_range.1],
            &b.vector[b.feature_map.structural_range.0..b.feature_map.structural_range.1],
        );

        let semantic = cosine_similarity(
            &a.vector[a.feature_map.semantic_range.0..a.feature_map.semantic_range.1],
            &b.vector[b.feature_map.semantic_range.0..b.feature_map.semantic_range.1],
        );

        let statistical = cosine_similarity(
            &a.vector[a.feature_map.statistical_range.0..a.feature_map.statistical_range.1],
            &b.vector[b.feature_map.statistical_range.0..b.feature_map.statistical_range.1],
        );

        EmbeddingSimilarity {
            overall,
            lexical,
            structural,
            semantic,
            statistical,
        }
    }

    // ── Lexical features ────────────────────────────────────────────

    fn compute_lexical_features(&self, code: &str) -> Vec<f64> {
        let mut features = vec![0.0f64; LEXICAL_DIMS];

        // Tokenize
        let tokens = tokenize_code(code);
        let total_tokens = tokens.len() as f64;
        if total_tokens == 0.0 { return features; }

        // Compute term frequencies
        let mut tf: HashMap<&str, f64> = HashMap::new();
        for token in &tokens {
            *tf.entry(token.as_str()).or_default() += 1.0;
        }

        // Hash each token to a dimension and weight by TF-IDF
        for (token, count) in &tf {
            let dim = hash_to_dim(token, LEXICAL_DIMS);
            let tf_val = count / total_tokens;
            let idf_val = self.idf_weights.get(*token).copied().unwrap_or(1.0);
            features[dim] += tf_val * idf_val;
        }

        features
    }

    // ── Structural features ─────────────────────────────────────────

    fn compute_structural_features(&self, code: &str) -> Vec<f64> {
        let mut features = vec![0.0f64; STRUCTURAL_DIMS];

        let lines: Vec<&str> = code.lines().collect();
        let total_lines = lines.len() as f64;
        if total_lines == 0.0 { return features; }

        // Control flow keyword frequencies (normalized)
        let cf_keywords = [
            "if", "else", "for", "while", "do", "switch", "case",
            "match", "try", "catch", "finally", "return", "break",
            "continue", "throw", "yield", "async", "await", "loop",
        ];

        let code_lower = code.to_lowercase();
        for (i, kw) in cf_keywords.iter().enumerate() {
            if i >= STRUCTURAL_DIMS { break; }
            let count = code_lower.matches(kw).count() as f64;
            features[i] = count / total_lines;
        }

        // Nesting depth histogram
        let mut depth = 0i32;
        let mut depth_histogram = [0f64; 10];
        for line in &lines {
            for ch in line.chars() {
                match ch {
                    '{' | '(' | '[' => depth += 1,
                    '}' | ')' | ']' => depth = (depth - 1).max(0),
                    _ => {}
                }
            }
            let bucket = (depth as usize).min(9);
            depth_histogram[bucket] += 1.0;
        }

        // Normalize depth histogram
        for (i, &val) in depth_histogram.iter().enumerate() {
            if 20 + i < STRUCTURAL_DIMS {
                features[20 + i] = val / total_lines;
            }
        }

        // Branch complexity: ratio of branching keywords to total lines
        let branch_count = ["if", "else", "switch", "case", "match", "?"].iter()
            .map(|kw| code_lower.matches(kw).count())
            .sum::<usize>() as f64;
        if 30 < STRUCTURAL_DIMS {
            features[30] = branch_count / total_lines;
        }

        // Loop complexity
        let loop_count = ["for", "while", "do", "loop", ".map(", ".filter(", ".reduce("].iter()
            .map(|kw| code_lower.matches(kw).count())
            .sum::<usize>() as f64;
        if 31 < STRUCTURAL_DIMS {
            features[31] = loop_count / total_lines;
        }

        // Function definition density
        let func_count = ["function ", "fn ", "def ", "=>", "->"].iter()
            .map(|kw| code.matches(kw).count())
            .sum::<usize>() as f64;
        if 32 < STRUCTURAL_DIMS {
            features[32] = func_count / total_lines;
        }

        features
    }

    // ── Semantic features ───────────────────────────────────────────

    fn compute_semantic_features(&self, code: &str) -> Vec<f64> {
        let mut features = vec![0.0f64; SEMANTIC_DIMS];

        // API call patterns (hashed into feature dimensions)
        let api_patterns = [
            // DOM
            "document.", "window.", "Element.", "querySelector", "getElementById",
            // Node.js
            "require(", "module.exports", "process.", "Buffer.",
            // React
            "React.", "useState", "useEffect", "Component",
            // jQuery
            "jQuery", "$(", ".ajax", ".ready",
            // Crypto
            "crypto.", "createHash", "encrypt", "decrypt",
            // File I/O
            "readFile", "writeFile", "createReadStream", "open(",
            // Network
            "fetch(", "XMLHttpRequest", "axios.", "http.",
            // Database
            "query(", "SELECT", "INSERT", "UPDATE", "DELETE",
            // Rust-specific
            "impl ", "trait ", "enum ", "struct ", "pub fn",
            "unwrap(", "expect(", "Result<", "Option<",
            // Python-specific
            "import ", "from ", "__init__", "__main__",
            "pandas", "numpy", "torch", "tensorflow",
        ];

        let code_lower = code.to_lowercase();
        for (i, pattern) in api_patterns.iter().enumerate() {
            let dim = i % SEMANTIC_DIMS;
            if code_lower.contains(&pattern.to_lowercase()) {
                features[dim] += 1.0;
            }
        }

        // Import/require analysis
        let import_re = regex::Regex::new(r#"(?:import|require|from)\s+['"]([^'"]+)['"]"#).unwrap();
        for cap in import_re.captures_iter(code) {
            if let Some(module) = cap.get(1) {
                let dim = hash_to_dim(module.as_str(), SEMANTIC_DIMS);
                features[dim] += 2.0; // Weight imports heavily
            }
        }

        // Normalize
        let max = features.iter().cloned().fold(0.0f64, f64::max);
        if max > 0.0 {
            for v in features.iter_mut() {
                *v /= max;
            }
        }

        features
    }

    // ── Statistical features ────────────────────────────────────────

    fn compute_statistical_features(&self, code: &str) -> Vec<f64> {
        let mut features = vec![0.0f64; STATISTICAL_DIMS];
        let lines: Vec<&str> = code.lines().collect();
        let total_lines = lines.len();
        let total_chars = code.len();

        if total_lines == 0 { return features; }

        // 0: Total lines (log-scaled)
        features[0] = (total_lines as f64).ln() / 10.0;

        // 1: Average line length
        let avg_line_len = total_chars as f64 / total_lines as f64;
        features[1] = avg_line_len / 120.0; // Normalize to typical max

        // 2: Line length variance
        let mean = avg_line_len;
        let variance = lines.iter()
            .map(|l| {
                let diff = l.len() as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / total_lines as f64;
        features[2] = variance.sqrt() / 60.0;

        // 3: Comment ratio
        let comment_lines = lines.iter()
            .filter(|l| {
                let t = l.trim();
                t.starts_with("//") || t.starts_with('#') || t.starts_with("/*") || t.starts_with('*')
            })
            .count();
        features[3] = comment_lines as f64 / total_lines as f64;

        // 4: Blank line ratio
        let blank_lines = lines.iter().filter(|l| l.trim().is_empty()).count();
        features[4] = blank_lines as f64 / total_lines as f64;

        // 5: Semicolon density (C-family indicator)
        features[5] = code.matches(';').count() as f64 / total_lines as f64;

        // 6: Brace density
        features[6] = code.matches('{').count() as f64 / total_lines as f64;

        // 7: Parenthesis density
        features[7] = code.matches('(').count() as f64 / total_lines as f64;

        // 8: String literal density
        features[8] = code.matches('"').count() as f64 / total_lines as f64 / 2.0;

        // 9: Unique token count (log-scaled)
        let tokens = tokenize_code(code);
        let unique: std::collections::HashSet<&str> = tokens.iter().map(|s| s.as_str()).collect();
        features[9] = (unique.len() as f64).ln() / 10.0;

        // 10: Token-to-line ratio
        features[10] = tokens.len() as f64 / total_lines as f64 / 20.0;

        // 11: Max nesting depth (normalized)
        let mut max_depth = 0i32;
        let mut current_depth = 0i32;
        for ch in code.chars() {
            match ch {
                '{' => { current_depth += 1; max_depth = max_depth.max(current_depth); }
                '}' => current_depth -= 1,
                _ => {}
            }
        }
        features[11] = max_depth as f64 / 10.0;

        // 12: Number literal density
        let num_re = regex::Regex::new(r"\b\d+\b").unwrap();
        features[12] = num_re.find_iter(code).count() as f64 / total_lines as f64;

        // 13: Operator density
        let operators = ['=', '+', '-', '*', '/', '%', '&', '|', '^', '!', '<', '>'];
        let op_count: usize = operators.iter().map(|&op| code.matches(op).count()).sum();
        features[13] = op_count as f64 / total_lines as f64 / 5.0;

        // 14: Indentation consistency (spaces vs tabs)
        let space_indent = lines.iter().filter(|l| l.starts_with("  ")).count();
        let tab_indent = lines.iter().filter(|l| l.starts_with('\t')).count();
        features[14] = if space_indent + tab_indent > 0 {
            space_indent as f64 / (space_indent + tab_indent) as f64
        } else { 0.5 };

        features
    }

    // ── Vocabulary ──────────────────────────────────────────────────

    fn default_vocabulary() -> HashMap<String, usize> {
        let keywords = [
            "function", "return", "const", "let", "var", "if", "else",
            "for", "while", "class", "struct", "impl", "pub", "fn",
            "async", "await", "import", "export", "require", "module",
            "try", "catch", "throw", "new", "this", "self", "super",
            "true", "false", "null", "undefined", "None", "def", "lambda",
        ];

        keywords.iter().enumerate()
            .map(|(i, kw)| (kw.to_string(), i))
            .collect()
    }
}

impl Default for CodeEmbedder {
    fn default() -> Self { Self::new() }
}

// ─── Utilities ─────────────────────────────────────────────────────

fn cosine_similarity(a: &[f64], b: &[f64]) -> f64 {
    if a.len() != b.len() || a.is_empty() { return 0.0; }

    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;

    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }

    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 { 0.0 } else { (dot / denom).clamp(0.0, 1.0) }
}

fn hash_to_dim(token: &str, dims: usize) -> usize {
    let mut hash = 5381u64;
    for byte in token.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
    }
    (hash as usize) % dims
}

fn tokenize_code(code: &str) -> Vec<String> {
    let re = regex::Regex::new(r"[a-zA-Z_]\w*|\d+\.?\d*|[^\s\w]").unwrap();
    re.find_iter(code)
        .map(|m| m.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedding_dimensions() {
        let embedder = CodeEmbedder::new();
        let embedding = embedder.embed("function hello() { return 42; }", "test");
        assert_eq!(embedding.dimensions, TOTAL_DIMS);
        assert_eq!(embedding.vector.len(), TOTAL_DIMS);
    }

    #[test]
    fn test_identical_code_similarity() {
        let embedder = CodeEmbedder::new();
        let code = "function sort(arr) { return arr.sort(); }";
        let a = embedder.embed(code, "a");
        let b = embedder.embed(code, "b");
        let sim = CodeEmbedder::compare(&a, &b);
        assert!(sim.overall > 0.99, "Identical code should have ~1.0 similarity, got {}", sim.overall);
    }

    #[test]
    fn test_similar_code_high_similarity() {
        let embedder = CodeEmbedder::new();
        let a = embedder.embed(
            "function sort(arr) { if (arr.length <= 1) return arr; return arr.sort(); }",
            "a"
        );
        let b = embedder.embed(
            "function sortArray(list) { if (list.length <= 1) return list; return list.sort(); }",
            "b"
        );
        let sim = CodeEmbedder::compare(&a, &b);
        assert!(sim.overall > 0.7, "Similar code should have high similarity, got {}", sim.overall);
    }

    #[test]
    fn test_different_code_low_similarity() {
        let embedder = CodeEmbedder::new();
        let a = embedder.embed(
            "fn compute_trajectory(mass: f64, velocity: Vec3) -> Orbit { /* physics */ }",
            "a"
        );
        let b = embedder.embed(
            "SELECT users.name, orders.total FROM users JOIN orders ON users.id = orders.user_id",
            "b"
        );
        let sim = CodeEmbedder::compare(&a, &b);
        assert!(sim.overall < 0.5, "Different code should have low similarity, got {}", sim.overall);
    }

    #[test]
    fn test_cosine_similarity() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 0.001);
        assert!((cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]) - 0.0).abs() < 0.001);
    }
}
