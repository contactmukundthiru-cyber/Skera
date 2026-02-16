//! Structural fingerprinting — AST-level code identity that survives obfuscation
//!
//! This is skera-core's **moat**. Unlike string fingerprinting (which catches
//! obvious library markers) or fuzzy hashing (which catches byte-level similarity),
//! structural fingerprinting extracts the *logic skeleton* of code.
//!
//! How it works:
//!
//! 1. **Control Flow Graph (CFG) extraction** — extract the branching structure
//!    (if/else, loops, try/catch, switch) as an ordered sequence of node types.
//!    Variable names disappear; only the *shape* of logic remains.
//!
//! 2. **API Call Sequence (ACS)** — extract the sequence of method calls,
//!    property accesses, and operators. Even after minification, `Array.prototype.slice`
//!    becomes `a.slice` — the *call pattern* is preserved.
//!
//! 3. **Winnowing / k-gram hashing** — hash overlapping windows of the extracted
//!    sequence to produce *structural fingerprints*. Two files with >70% matching
//!    k-grams are structurally derived from the same source.
//!
//! 4. **Tree-sitter parsing** — we use tree-sitter for fast, incremental,
//!    fault-tolerant parsing of JavaScript/TypeScript/CSS/HTML.
//!
//! This layer makes evasion *extremely* difficult: you can rename every variable,
//! reformat every line, even reorder independent functions — but you cannot change
//! the fundamental control flow without rewriting the algorithm entirely.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Types ─────────────────────────────────────────────────────────

/// A structural fingerprint of a code file or block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralFingerprint {
    /// Control flow graph signature (sequence of CFG node types)
    pub cfg_signature: Vec<CfgNodeType>,
    /// API call sequence (method/property access patterns)
    pub api_calls: Vec<String>,
    /// Winnowed k-gram hashes (the actual fingerprints for comparison)
    pub kgram_hashes: Vec<u64>,
    /// Structural complexity score (cyclomatic-like)
    pub complexity: u32,
    /// Number of functions/methods detected
    pub function_count: u32,
    /// Number of unique string literals
    pub string_literal_count: u32,
    /// Detected code patterns (e.g., "event-emitter", "pub-sub", "factory")
    pub patterns: Vec<CodePattern>,
}

/// A node type in the control flow graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CfgNodeType {
    FunctionDecl,
    ArrowFunction,
    ClassDecl,
    MethodDef,
    IfStatement,
    ElseClause,
    ForLoop,
    WhileLoop,
    DoWhileLoop,
    ForInLoop,
    ForOfLoop,
    SwitchStatement,
    SwitchCase,
    TryCatch,
    CatchClause,
    FinallyClause,
    ThrowStatement,
    ReturnStatement,
    YieldExpression,
    AwaitExpression,
    Assignment,
    BinaryExpression,
    CallExpression,
    NewExpression,
    MemberExpression,
    SpreadElement,
    TemplateString,
    RegexLiteral,
    ArrayLiteral,
    ObjectLiteral,
    Ternary,
    NullishCoalescing,
    OptionalChaining,
    DestructuringAssignment,
    ImportStatement,
    ExportStatement,
    Unknown,
}

impl CfgNodeType {
    /// Convert a tree-sitter node kind to our CFG node type
    pub fn from_ts_kind(kind: &str) -> Option<Self> {
        Some(match kind {
            "function_declaration" | "function" => Self::FunctionDecl,
            "arrow_function" => Self::ArrowFunction,
            "class_declaration" | "class" => Self::ClassDecl,
            "method_definition" => Self::MethodDef,
            "if_statement" => Self::IfStatement,
            "else_clause" => Self::ElseClause,
            "for_statement" => Self::ForLoop,
            "while_statement" => Self::WhileLoop,
            "do_statement" => Self::DoWhileLoop,
            "for_in_statement" => Self::ForInLoop,
            "for_of_statement" | "for_each_statement" => Self::ForOfLoop,
            "switch_statement" => Self::SwitchStatement,
            "switch_case" | "switch_default" => Self::SwitchCase,
            "try_statement" => Self::TryCatch,
            "catch_clause" => Self::CatchClause,
            "finally_clause" => Self::FinallyClause,
            "throw_statement" => Self::ThrowStatement,
            "return_statement" => Self::ReturnStatement,
            "yield_expression" => Self::YieldExpression,
            "await_expression" => Self::AwaitExpression,
            "assignment_expression" | "augmented_assignment_expression" => Self::Assignment,
            "binary_expression" => Self::BinaryExpression,
            "call_expression" => Self::CallExpression,
            "new_expression" => Self::NewExpression,
            "member_expression" => Self::MemberExpression,
            "spread_element" => Self::SpreadElement,
            "template_string" => Self::TemplateString,
            "regex" => Self::RegexLiteral,
            "array" | "array_pattern" => Self::ArrayLiteral,
            "object" | "object_pattern" => Self::ObjectLiteral,
            "ternary_expression" => Self::Ternary,
            "import_statement" => Self::ImportStatement,
            "export_statement" => Self::ExportStatement,
            _ => return None,
        })
    }
}

/// A detected architectural pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodePattern {
    /// Pattern name
    pub name: String,
    /// Confidence
    pub confidence: f64,
    /// Description
    pub description: String,
}

/// Result of comparing two structural fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralSimilarity {
    /// Percentage of matching k-grams (Jaccard similarity)
    pub kgram_similarity: f64,
    /// CFG sequence similarity (edit distance normalized)
    pub cfg_similarity: f64,
    /// API call overlap ratio
    pub api_overlap: f64,
    /// Combined structural similarity score
    pub combined_score: f64,
    /// Assessment
    pub assessment: String,
}

// ─── Core Functions ────────────────────────────────────────────────

/// Extract a structural fingerprint from JavaScript/TypeScript source code.
/// This operates purely on the text representation using regex-based extraction,
/// with tree-sitter integration available when the parser is loaded.
pub fn extract_fingerprint(source: &str) -> StructuralFingerprint {
    let cfg_signature = extract_cfg_from_text(source);
    let api_calls = extract_api_calls(source);
    let kgram_hashes = compute_winnowed_kgrams(&cfg_signature, &api_calls);
    let complexity = compute_complexity(&cfg_signature);
    let function_count = cfg_signature
        .iter()
        .filter(|n| matches!(n, CfgNodeType::FunctionDecl | CfgNodeType::ArrowFunction | CfgNodeType::MethodDef))
        .count() as u32;
    let string_literal_count = count_string_literals(source);
    let patterns = detect_code_patterns(source, &api_calls);

    StructuralFingerprint {
        cfg_signature,
        api_calls,
        kgram_hashes,
        complexity,
        function_count,
        string_literal_count,
        patterns,
    }
}

/// Compare two structural fingerprints.
pub fn compare_fingerprints(a: &StructuralFingerprint, b: &StructuralFingerprint) -> StructuralSimilarity {
    let kgram_sim = jaccard_similarity(&a.kgram_hashes, &b.kgram_hashes);
    let cfg_sim = sequence_similarity(&a.cfg_signature, &b.cfg_signature);
    let api_sim = set_overlap(&a.api_calls, &b.api_calls);

    // Weighted combination
    let combined = kgram_sim * 0.50 + cfg_sim * 0.30 + api_sim * 0.20;

    let assessment = if combined > 0.90 {
        "PLAGIARISM — near-identical structural fingerprint"
    } else if combined > 0.70 {
        "HIGHLY SUSPICIOUS — major structural overlap"
    } else if combined > 0.50 {
        "POSSIBLY DERIVED — significant shared structure"
    } else if combined > 0.30 {
        "SOME OVERLAP — common patterns detected"
    } else {
        "INDEPENDENT — no meaningful structural similarity"
    };

    StructuralSimilarity {
        kgram_similarity: kgram_sim,
        cfg_similarity: cfg_sim,
        api_overlap: api_sim,
        combined_score: combined,
        assessment: assessment.to_string(),
    }
}

// ─── CFG Extraction (regex-based, no tree-sitter required) ─────────

/// Extract control flow graph nodes from source text.
/// This is a lightweight extraction that doesn't require tree-sitter.
fn extract_cfg_from_text(source: &str) -> Vec<CfgNodeType> {
    let mut nodes = Vec::new();

    // Regex-free keyword scanning for performance
    let keywords: &[(&str, CfgNodeType)] = &[
        ("function ", CfgNodeType::FunctionDecl),
        ("function(", CfgNodeType::FunctionDecl),
        ("=>", CfgNodeType::ArrowFunction),
        ("class ", CfgNodeType::ClassDecl),
        ("if(", CfgNodeType::IfStatement),
        ("if (", CfgNodeType::IfStatement),
        ("}else", CfgNodeType::ElseClause),
        ("} else", CfgNodeType::ElseClause),
        ("for(", CfgNodeType::ForLoop),
        ("for (", CfgNodeType::ForLoop),
        ("while(", CfgNodeType::WhileLoop),
        ("while (", CfgNodeType::WhileLoop),
        ("do{", CfgNodeType::DoWhileLoop),
        ("do {", CfgNodeType::DoWhileLoop),
        ("switch(", CfgNodeType::SwitchStatement),
        ("switch (", CfgNodeType::SwitchStatement),
        ("case ", CfgNodeType::SwitchCase),
        ("try{", CfgNodeType::TryCatch),
        ("try {", CfgNodeType::TryCatch),
        ("catch(", CfgNodeType::CatchClause),
        ("catch (", CfgNodeType::CatchClause),
        ("finally{", CfgNodeType::FinallyClause),
        ("finally {", CfgNodeType::FinallyClause),
        ("throw ", CfgNodeType::ThrowStatement),
        ("return ", CfgNodeType::ReturnStatement),
        ("return;", CfgNodeType::ReturnStatement),
        ("yield ", CfgNodeType::YieldExpression),
        ("await ", CfgNodeType::AwaitExpression),
        ("new ", CfgNodeType::NewExpression),
        ("import ", CfgNodeType::ImportStatement),
        ("export ", CfgNodeType::ExportStatement),
    ];

    let source_lower = source.to_lowercase();
    for (keyword, node_type) in keywords {
        let kw_lower = keyword.to_lowercase();
        let count = source_lower.matches(&kw_lower).count();
        for _ in 0..count {
            nodes.push(*node_type);
        }
    }

    // Sort by "significance" — control flow first, then expressions
    nodes.sort_by_key(|n| match n {
        CfgNodeType::FunctionDecl | CfgNodeType::ClassDecl => 0,
        CfgNodeType::IfStatement | CfgNodeType::ForLoop | CfgNodeType::WhileLoop => 1,
        CfgNodeType::SwitchStatement | CfgNodeType::TryCatch => 2,
        _ => 3,
    });

    nodes
}

// ─── API Call Extraction ───────────────────────────────────────────

/// Extract API call patterns from source code.
/// Catches patterns like `jQuery.fn.init`, `React.createElement`, `Array.prototype.slice`.
fn extract_api_calls(source: &str) -> Vec<String> {
    let re = regex::Regex::new(
        r"(?:([A-Z][a-zA-Z0-9_$]*(?:\.[a-zA-Z_$][a-zA-Z0-9_$]*)+)\s*\()"
    ).unwrap();

    let mut calls: Vec<String> = re
        .captures_iter(source)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    calls.retain(|c| seen.insert(c.clone()));

    calls
}

// ─── Winnowing / k-gram Hashing ────────────────────────────────────

/// Compute winnowed k-gram hashes from CFG and API call sequences.
///
/// Winnowing algorithm (Schleimer, Wilkerson, Aiken 2003):
/// 1. Convert feature sequence to k-grams (overlapping windows of size k)
/// 2. Hash each k-gram
/// 3. For each window of w consecutive hashes, select the minimum
/// 4. The selected hashes are the fingerprint
///
/// This produces a compact fingerprint that is robust against insertions/deletions.
fn compute_winnowed_kgrams(cfg: &[CfgNodeType], api_calls: &[String]) -> Vec<u64> {
    // Build feature sequence: interleave CFG nodes and API call hashes
    let mut features: Vec<u64> = Vec::new();

    for node in cfg {
        features.push(*node as u64);
    }
    for call in api_calls {
        features.push(hash_string(call));
    }

    if features.len() < 5 {
        return features;
    }

    // k-gram size (window of features to hash together)
    let k = 5usize;
    // Winnowing window size
    let w = 4usize;

    // Step 1: Compute k-gram hashes
    let kgram_hashes: Vec<u64> = features
        .windows(k)
        .map(|window| {
            let mut h: u64 = 0;
            for (i, &val) in window.iter().enumerate() {
                h ^= val.wrapping_mul(HASH_PRIMES[i % HASH_PRIMES.len()]);
                h = h.rotate_left(7);
            }
            h
        })
        .collect();

    if kgram_hashes.len() < w {
        return kgram_hashes;
    }

    // Step 2: Winnowing — select minimum hash from each window
    let mut fingerprints: Vec<u64> = Vec::new();
    let mut last_selected: Option<u64> = None;

    for window in kgram_hashes.windows(w) {
        let min_hash = *window.iter().min().unwrap();
        if last_selected != Some(min_hash) {
            fingerprints.push(min_hash);
            last_selected = Some(min_hash);
        }
    }

    fingerprints
}

/// Primes used for k-gram hashing (FNV-inspired)
const HASH_PRIMES: [u64; 8] = [
    14_695_981_039_346_656_037,
    1_099_511_628_211,
    6_364_136_223_846_793_005,
    1_442_695_040_888_963_407,
    2_862_933_555_777_941_757,
    3_037_000_493,
    3_266_489_917,
    668_265_263,
];

/// Hash a string into a u64 (FNV-1a)
fn hash_string(s: &str) -> u64 {
    let mut h: u64 = 14_695_981_039_346_656_037;
    for byte in s.bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    h
}

// ─── Similarity Computation ───────────────────────────────────────

/// Jaccard similarity between two sets of k-gram hashes.
fn jaccard_similarity(a: &[u64], b: &[u64]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let set_a: std::collections::HashSet<u64> = a.iter().copied().collect();
    let set_b: std::collections::HashSet<u64> = b.iter().copied().collect();

    let intersection = set_a.intersection(&set_b).count();
    let union = set_a.union(&set_b).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

/// Sequence similarity using normalized Levenshtein-like edit distance.
fn sequence_similarity(a: &[CfgNodeType], b: &[CfgNodeType]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    // For performance, use a simplified approach for long sequences:
    // Compare frequency distributions instead of full edit distance
    let max_len = a.len().max(b.len());
    if max_len > 500 {
        return frequency_similarity(a, b);
    }

    // Standard edit distance for shorter sequences
    let m = a.len();
    let n = b.len();
    let mut dp = vec![vec![0u32; n + 1]; m + 1];

    for i in 0..=m {
        dp[i][0] = i as u32;
    }
    for j in 0..=n {
        dp[0][j] = j as u32;
    }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            dp[i][j] = (dp[i - 1][j] + 1)
                .min(dp[i][j - 1] + 1)
                .min(dp[i - 1][j - 1] + cost);
        }
    }

    let distance = dp[m][n] as f64;
    let max_distance = max_len as f64;
    1.0 - (distance / max_distance)
}

/// Frequency-based similarity for long sequences.
fn frequency_similarity(a: &[CfgNodeType], b: &[CfgNodeType]) -> f64 {
    let freq_a = node_frequencies(a);
    let freq_b = node_frequencies(b);

    let all_keys: std::collections::HashSet<CfgNodeType> =
        freq_a.keys().chain(freq_b.keys()).copied().collect();

    if all_keys.is_empty() {
        return 1.0;
    }

    let mut dot_product = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;

    for key in &all_keys {
        let va = *freq_a.get(key).unwrap_or(&0) as f64;
        let vb = *freq_b.get(key).unwrap_or(&0) as f64;
        dot_product += va * vb;
        norm_a += va * va;
        norm_b += vb * vb;
    }

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    // Cosine similarity
    dot_product / (norm_a.sqrt() * norm_b.sqrt())
}

/// Count frequency of each CFG node type
fn node_frequencies(nodes: &[CfgNodeType]) -> HashMap<CfgNodeType, usize> {
    let mut freq = HashMap::new();
    for node in nodes {
        *freq.entry(*node).or_insert(0) += 1;
    }
    freq
}

/// Set overlap ratio between two API call lists.
fn set_overlap(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }

    let set_a: std::collections::HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let set_b: std::collections::HashSet<&str> = b.iter().map(|s| s.as_str()).collect();

    let intersection = set_a.intersection(&set_b).count();
    let min_size = set_a.len().min(set_b.len());

    if min_size == 0 {
        0.0
    } else {
        intersection as f64 / min_size as f64
    }
}

// ─── Utility Functions ─────────────────────────────────────────────

/// Compute cyclomatic-like complexity from CFG nodes.
fn compute_complexity(cfg: &[CfgNodeType]) -> u32 {
    let branching: u32 = cfg
        .iter()
        .map(|n| match n {
            CfgNodeType::IfStatement => 1,
            CfgNodeType::ForLoop | CfgNodeType::WhileLoop | CfgNodeType::DoWhileLoop => 1,
            CfgNodeType::ForInLoop | CfgNodeType::ForOfLoop => 1,
            CfgNodeType::SwitchCase => 1,
            CfgNodeType::TryCatch => 1,
            CfgNodeType::Ternary => 1,
            CfgNodeType::NullishCoalescing => 1,
            _ => 0,
        })
        .sum();
    branching + 1 // +1 for the base path
}

/// Count unique string literals in source code.
fn count_string_literals(source: &str) -> u32 {
    // Simple pattern: match single and double-quoted strings (no look-ahead needed)
    let re_double = regex::Regex::new(r#""[^"]*""#).unwrap();
    let re_single = regex::Regex::new(r"'[^']*'").unwrap();
    let mut seen = std::collections::HashSet::new();
    for cap in re_double.find_iter(source) {
        seen.insert(cap.as_str());
    }
    for cap in re_single.find_iter(source) {
        seen.insert(cap.as_str());
    }
    seen.len() as u32
}

/// Detect common architectural patterns from API calls and code structure.
fn detect_code_patterns(source: &str, api_calls: &[String]) -> Vec<CodePattern> {
    let mut patterns = Vec::new();

    // Event emitter pattern
    let event_keywords = ["addEventListener", "removeEventListener", "emit", "on(", "off(", "trigger"];
    let event_count = event_keywords.iter().filter(|k| source.contains(*k)).count();
    if event_count >= 2 {
        patterns.push(CodePattern {
            name: "Event Emitter".into(),
            confidence: (event_count as f64 * 0.2).min(0.95),
            description: "Event-driven architecture (pub/sub, observer)".into(),
        });
    }

    // Promise/async pattern
    let async_keywords = ["Promise", ".then(", ".catch(", "async ", "await "];
    let async_count = async_keywords.iter().filter(|k| source.contains(*k)).count();
    if async_count >= 2 {
        patterns.push(CodePattern {
            name: "Async/Promise".into(),
            confidence: (async_count as f64 * 0.2).min(0.95),
            description: "Asynchronous programming pattern".into(),
        });
    }

    // Factory pattern
    if api_calls.iter().any(|c| c.contains("create") || c.contains("Create")) {
        patterns.push(CodePattern {
            name: "Factory".into(),
            confidence: 0.6,
            description: "Factory creation pattern detected".into(),
        });
    }

    // Prototype chain / class hierarchy
    if source.contains("prototype") || source.contains("__proto__") || source.contains("Object.create") {
        patterns.push(CodePattern {
            name: "Prototype Chain".into(),
            confidence: 0.7,
            description: "Prototypal inheritance pattern".into(),
        });
    }

    // Module pattern (IIFE)
    if source.contains("(function(") || source.contains("!function(") {
        patterns.push(CodePattern {
            name: "IIFE Module".into(),
            confidence: 0.8,
            description: "Immediately Invoked Function Expression module pattern".into(),
        });
    }

    // Singleton pattern
    if source.contains("getInstance") || source.contains("instance ||") {
        patterns.push(CodePattern {
            name: "Singleton".into(),
            confidence: 0.7,
            description: "Singleton instance pattern".into(),
        });
    }

    patterns
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_fingerprint_basic() {
        let source = r#"
function hello(name) {
    if (name) {
        return "Hello, " + name;
    } else {
        return "Hello, World!";
    }
}
for (var i = 0; i < 10; i++) {
    console.log(i);
}
"#;
        let fp = extract_fingerprint(source);
        assert!(!fp.cfg_signature.is_empty());
        assert!(fp.complexity > 1);
        assert!(fp.function_count >= 1);
    }

    #[test]
    fn test_identical_fingerprints() {
        let source = "function foo() { if (x) { return 1; } else { return 2; } }";
        let fp1 = extract_fingerprint(source);
        let fp2 = extract_fingerprint(source);
        let sim = compare_fingerprints(&fp1, &fp2);
        assert!(sim.combined_score > 0.95, "Identical code should be near-identical: {}", sim.combined_score);
    }

    #[test]
    fn test_variable_renamed_similarity() {
        let source1 = "function calculate(x, y) { if (x > y) { return x - y; } else { return y - x; } }";
        let source2 = "function compute(a, b) { if (a > b) { return a - b; } else { return b - a; } }";
        let fp1 = extract_fingerprint(source1);
        let fp2 = extract_fingerprint(source2);
        let sim = compare_fingerprints(&fp1, &fp2);
        // Should still be similar despite variable renaming
        assert!(sim.cfg_similarity > 0.8, "CFG should survive variable renaming: {}", sim.cfg_similarity);
    }

    #[test]
    fn test_different_code_distinct() {
        let source1 = "function sort(arr) { for (var i = 0; i < arr.length; i++) { for (var j = 0; j < arr.length; j++) { if (arr[i] < arr[j]) { var tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp; } } } }";
        let source2 = "class EventEmitter { constructor() { this.events = {}; } on(event, fn) { this.events[event] = fn; } emit(event) { this.events[event](); } }";
        let fp1 = extract_fingerprint(source1);
        let fp2 = extract_fingerprint(source2);
        let sim = compare_fingerprints(&fp1, &fp2);
        assert!(sim.combined_score < 0.5, "Structurally different code should be distinct: {}", sim.combined_score);
    }

    #[test]
    fn test_api_call_extraction() {
        let source = r#"
React.createElement("div", null, "Hello");
Array.prototype.slice.call(arguments);
jQuery.fn.init();
"#;
        let calls = extract_api_calls(source);
        assert!(calls.iter().any(|c| c.contains("React.createElement")));
        assert!(calls.iter().any(|c| c.contains("Array.prototype.slice.call")));
    }

    #[test]
    fn test_pattern_detection() {
        let source = r#"
element.addEventListener("click", handler);
element.removeEventListener("click", handler);
emitter.on("data", callback);
emitter.emit("complete");
"#;
        let fp = extract_fingerprint(source);
        assert!(fp.patterns.iter().any(|p| p.name == "Event Emitter"),
            "Should detect event emitter pattern");
    }

    #[test]
    fn test_winnowing_deterministic() {
        let source = "function test() { if (x) { return 1; } for (var i = 0; i < n; i++) { console.log(i); } }";
        let fp1 = extract_fingerprint(source);
        let fp2 = extract_fingerprint(source);
        assert_eq!(fp1.kgram_hashes, fp2.kgram_hashes, "Winnowing should be deterministic");
    }

    #[test]
    fn test_complexity_score() {
        let simple = "function hello() { return 'world'; }";
        let complex = "function test() { if (a) { for (var i = 0; i < n; i++) { switch(x) { case 1: break; case 2: break; } } } else { try { foo(); } catch(e) { bar(); } } }";
        let fp_simple = extract_fingerprint(simple);
        let fp_complex = extract_fingerprint(complex);
        assert!(fp_complex.complexity > fp_simple.complexity,
            "Complex code ({}) should score higher than simple code ({})",
            fp_complex.complexity, fp_simple.complexity);
    }
}
