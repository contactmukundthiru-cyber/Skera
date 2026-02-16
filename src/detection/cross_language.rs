//! Cross-Language Provenance Detection — tracing code lineage across languages
//!
//! Detects when code has been ported from one language to another.
//! "This Rust code was ported from this Python library."
//! "This JavaScript was generated from this TypeScript."
//! "This Go module uses the same algorithm as this C library."
//!
//! ## Strategy
//!
//! Language-agnostic features that survive translation:
//! 1. **Algorithm topology**: The shape of the computation graph
//! 2. **Constant values**: Magic numbers, crypto constants, error strings
//! 3. **API surface shape**: Function signatures, parameter ordering
//! 4. **Naming etymology**: Variable names often carry over (camelCase → snake_case)
//! 5. **Comment archaeology**: Comments/docs are often copied verbatim

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ─── Types ─────────────────────────────────────────────────────────

/// Cross-language provenance analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceAnalysis {
    /// Detected source language (if ported)
    pub probable_source_language: Option<String>,
    /// Confidence that this is a port (0.0 - 1.0)
    pub port_confidence: f64,
    /// Evidence of cross-language provenance
    pub evidence: Vec<ProvenanceEvidence>,
    /// Language-agnostic fingerprint for comparison
    pub universal_fingerprint: UniversalFingerprint,
    /// Translation artifacts detected
    pub translation_artifacts: Vec<TranslationArtifact>,
}

/// A piece of evidence for cross-language provenance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceEvidence {
    pub kind: EvidenceKind,
    pub description: String,
    pub confidence: f64,
    pub source_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceKind {
    /// Same magic numbers/constants
    SharedConstants,
    /// Same error message strings
    SharedErrorMessages,
    /// Matching function signature shapes
    MatchingSignatures,
    /// Name transliteration (camelCase ↔ snake_case ↔ PascalCase)
    NameTransliteration,
    /// Verbatim comment/doc copying
    VerbatimComments,
    /// Algorithm shape match
    AlgorithmTopology,
    /// Import/dependency pattern match
    DependencyPattern,
    /// Identical constant ordering
    ConstantOrdering,
}

/// Language-agnostic code fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalFingerprint {
    /// Numeric constants found (sorted)
    pub constants: Vec<String>,
    /// String literals (sorted, normalized)
    pub string_literals: Vec<String>,
    /// Function arity distribution (param count → frequency)
    pub arity_distribution: HashMap<usize, usize>,
    /// Algorithm shape tokens
    pub algorithm_shape: Vec<String>,
    /// Normalized identifier stems
    pub identifier_stems: Vec<String>,
}

/// An artifact left behind by language translation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationArtifact {
    pub description: String,
    pub source_language: String,
    pub target_language: String,
    pub line: Option<usize>,
}

// ─── The Analyzer ──────────────────────────────────────────────────

pub struct ProvenanceDetector;

impl ProvenanceDetector {
    /// Analyze code for cross-language provenance indicators
    pub fn analyze(code: &str, target_language: &str) -> ProvenanceAnalysis {
        let mut evidence = Vec::new();
        let mut translation_artifacts = Vec::new();

        // Extract universal fingerprint
        let universal_fingerprint = Self::extract_universal_fingerprint(code);

        // Detect translation artifacts
        let artifacts = Self::detect_translation_artifacts(code, target_language);
        translation_artifacts.extend(artifacts);

        // Check for naming convention mismatches
        let naming_evidence = Self::analyze_naming_conventions(code, target_language);
        evidence.extend(naming_evidence);

        // Check for language-specific idiom leakage
        let idiom_evidence = Self::detect_idiom_leakage(code, target_language);
        evidence.extend(idiom_evidence);

        // Check for verbatim comments from another language
        let comment_evidence = Self::analyze_comments(code, target_language);
        evidence.extend(comment_evidence);

        // Calculate probability of provenance from each language
        let probable_source = Self::determine_source_language(&evidence, &translation_artifacts);

        let port_confidence = if evidence.is_empty() {
            0.0
        } else {
            evidence.iter().map(|e| e.confidence).sum::<f64>() / evidence.len() as f64
        };

        ProvenanceAnalysis {
            probable_source_language: probable_source,
            port_confidence,
            evidence,
            universal_fingerprint,
            translation_artifacts,
        }
    }

    /// Compare two pieces of code in different languages for provenance
    pub fn compare_cross_language(
        code_a: &str,
        lang_a: &str,
        code_b: &str,
        lang_b: &str,
    ) -> CrossLanguageSimilarity {
        let fp_a = Self::extract_universal_fingerprint(code_a);
        let fp_b = Self::extract_universal_fingerprint(code_b);

        // Compare constants
        let const_sim = jaccard_str(&fp_a.constants, &fp_b.constants);

        // Compare string literals
        let string_sim = jaccard_str(&fp_a.string_literals, &fp_b.string_literals);

        // Compare arity distributions
        let arity_sim = Self::compare_arity_distributions(
            &fp_a.arity_distribution,
            &fp_b.arity_distribution,
        );

        // Compare algorithm shapes
        let algo_sim = jaccard_str(&fp_a.algorithm_shape, &fp_b.algorithm_shape);

        // Compare identifier stems
        let stem_sim = jaccard_str(&fp_a.identifier_stems, &fp_b.identifier_stems);

        let overall = const_sim * 0.2 + string_sim * 0.2 + arity_sim * 0.15
            + algo_sim * 0.25 + stem_sim * 0.2;

        CrossLanguageSimilarity {
            overall,
            constant_similarity: const_sim,
            string_similarity: string_sim,
            arity_similarity: arity_sim,
            algorithm_similarity: algo_sim,
            identifier_similarity: stem_sim,
            language_a: lang_a.to_string(),
            language_b: lang_b.to_string(),
        }
    }

    // ── Universal fingerprint extraction ────────────────────────────

    fn extract_universal_fingerprint(code: &str) -> UniversalFingerprint {
        // Extract numeric constants
        let num_re = regex::Regex::new(r"\b(0x[0-9a-fA-F]+|\d+\.\d+|\d{3,})\b").unwrap();
        let constants: Vec<String> = num_re.find_iter(code)
            .map(|m| m.as_str().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Extract string literals
        let str_re = regex::Regex::new(r#"["']([^"']{5,})['""]"#).unwrap();
        let string_literals: Vec<String> = str_re.captures_iter(code)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Function arity distribution
        let mut arity_distribution = HashMap::new();
        let func_re = regex::Regex::new(r"(?:function\s+\w+|fn\s+\w+|def\s+\w+|\w+\s*=\s*(?:async\s+)?function)\s*\(([^)]*)\)").unwrap();
        for cap in func_re.captures_iter(code) {
            let params = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let arity = if params.trim().is_empty() {
                0
            } else {
                params.split(',').count()
            };
            *arity_distribution.entry(arity).or_insert(0) += 1;
        }

        // Algorithm shape: extract control flow pattern
        let cf_keywords = ["if", "else", "for", "while", "return", "switch",
                          "match", "case", "try", "catch", "break", "continue"];
        let mut algorithm_shape = Vec::new();
        for line in code.lines() {
            let trimmed = line.trim().to_lowercase();
            for kw in &cf_keywords {
                if trimmed.starts_with(kw) || trimmed.contains(&format!(" {} ", kw)) {
                    algorithm_shape.push(kw.to_string());
                }
            }
        }

        // Identifier stems: normalize naming conventions
        let id_re = regex::Regex::new(r"\b([a-zA-Z_]\w{3,})\b").unwrap();
        let identifier_stems: Vec<String> = id_re.find_iter(code)
            .map(|m| normalize_identifier(m.as_str()))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        UniversalFingerprint {
            constants,
            string_literals,
            arity_distribution,
            algorithm_shape,
            identifier_stems,
        }
    }

    // ── Translation artifact detection ──────────────────────────────

    fn detect_translation_artifacts(code: &str, target_lang: &str) -> Vec<TranslationArtifact> {
        let mut artifacts = Vec::new();

        match target_lang {
            "javascript" | "typescript" => {
                // Python-isms in JS
                if code.contains("None") && !code.contains("\"None\"") {
                    artifacts.push(TranslationArtifact {
                        description: "Use of 'None' (Python) instead of 'null'/'undefined'".to_string(),
                        source_language: "python".to_string(),
                        target_language: target_lang.to_string(),
                        line: code.lines().position(|l| l.contains("None")),
                    });
                }
                if code.contains("True") || code.contains("False") {
                    artifacts.push(TranslationArtifact {
                        description: "Capitalized boolean (Python True/False instead of true/false)".to_string(),
                        source_language: "python".to_string(),
                        target_language: target_lang.to_string(),
                        line: None,
                    });
                }
                // Rust-isms in JS
                if code.contains("unwrap()") || code.contains("expect(") {
                    artifacts.push(TranslationArtifact {
                        description: "Rust-style error handling (unwrap/expect) in JavaScript".to_string(),
                        source_language: "rust".to_string(),
                        target_language: target_lang.to_string(),
                        line: None,
                    });
                }
            }
            "rust" => {
                // Python-isms in Rust
                if code.contains("def ") {
                    artifacts.push(TranslationArtifact {
                        description: "Python 'def' keyword found in Rust context".to_string(),
                        source_language: "python".to_string(),
                        target_language: "rust".to_string(),
                        line: None,
                    });
                }
                // JS-isms in Rust
                if code.contains("var ") || code.contains("undefined") {
                    artifacts.push(TranslationArtifact {
                        description: "JavaScript idiom (var/undefined) found in Rust".to_string(),
                        source_language: "javascript".to_string(),
                        target_language: "rust".to_string(),
                        line: None,
                    });
                }
            }
            "python" => {
                // JS-isms in Python
                if code.contains("function ") {
                    artifacts.push(TranslationArtifact {
                        description: "JavaScript 'function' keyword found in Python context".to_string(),
                        source_language: "javascript".to_string(),
                        target_language: "python".to_string(),
                        line: None,
                    });
                }
                // C/C++ isms
                if code.contains("NULL") || code.contains("nullptr") {
                    artifacts.push(TranslationArtifact {
                        description: "C/C++ null idiom found in Python".to_string(),
                        source_language: "c".to_string(),
                        target_language: "python".to_string(),
                        line: None,
                    });
                }
            }
            _ => {}
        }

        artifacts
    }

    // ── Naming convention analysis ──────────────────────────────────

    fn analyze_naming_conventions(code: &str, target_lang: &str) -> Vec<ProvenanceEvidence> {
        let mut evidence = Vec::new();

        let id_re = regex::Regex::new(r"\b([a-zA-Z_]\w{3,})\b").unwrap();
        let identifiers: Vec<&str> = id_re.find_iter(code)
            .map(|m| m.as_str())
            .collect();

        let total = identifiers.len();
        if total == 0 { return evidence; }

        // Count naming conventions
        let snake_count = identifiers.iter().filter(|id| is_snake_case(id)).count();
        let camel_count = identifiers.iter().filter(|id| is_camel_case(id)).count();
        let _pascal_count = identifiers.iter().filter(|id| is_pascal_case(id)).count();

        let snake_ratio = snake_count as f64 / total as f64;
        let camel_ratio = camel_count as f64 / total as f64;

        match target_lang {
            "javascript" | "typescript" => {
                // JS should be camelCase — lots of snake_case suggests Python/Ruby/Rust origin
                if snake_ratio > 0.4 {
                    evidence.push(ProvenanceEvidence {
                        kind: EvidenceKind::NameTransliteration,
                        description: format!(
                            "{:.0}% snake_case identifiers in JavaScript — suggests Python/Rust port",
                            snake_ratio * 100.0
                        ),
                        confidence: snake_ratio * 0.7,
                        source_hint: Some("python or rust".to_string()),
                    });
                }
            }
            "rust" => {
                // Rust should be snake_case — lots of camelCase suggests JS/Java origin
                if camel_ratio > 0.3 {
                    evidence.push(ProvenanceEvidence {
                        kind: EvidenceKind::NameTransliteration,
                        description: format!(
                            "{:.0}% camelCase identifiers in Rust — suggests JavaScript/Java port",
                            camel_ratio * 100.0
                        ),
                        confidence: camel_ratio * 0.6,
                        source_hint: Some("javascript or java".to_string()),
                    });
                }
            }
            "python" => {
                // Python should be snake_case — lots of camelCase suggests JS/Java origin
                if camel_ratio > 0.3 {
                    evidence.push(ProvenanceEvidence {
                        kind: EvidenceKind::NameTransliteration,
                        description: format!(
                            "{:.0}% camelCase identifiers in Python — suggests JavaScript/Java port",
                            camel_ratio * 100.0
                        ),
                        confidence: camel_ratio * 0.6,
                        source_hint: Some("javascript or java".to_string()),
                    });
                }
            }
            _ => {}
        }

        evidence
    }

    // ── Idiom leakage detection ─────────────────────────────────────

    fn detect_idiom_leakage(code: &str, target_lang: &str) -> Vec<ProvenanceEvidence> {
        let mut evidence = Vec::new();

        // Common cross-language idiom patterns
        let idioms: Vec<(&str, &str, &str, f64)> = vec![
            // (pattern, found_in_target, suggests_source, confidence)
            ("enumerate(", "javascript", "python", 0.7),
            (".items()", "javascript", "python", 0.6),
            ("range(", "javascript", "python", 0.5),
            ("len(", "javascript", "python", 0.6),
            ("append(", "javascript", "python", 0.5),
            (".forEach(", "python", "javascript", 0.6),
            (".map(", "python", "javascript", 0.5),
            ("===", "python", "javascript", 0.7),
            ("!==", "python", "javascript", 0.7),
            (".unwrap()", "javascript", "rust", 0.8),
            ("Option<", "javascript", "rust", 0.8),
            ("Result<", "javascript", "rust", 0.8),
            ("match ", "javascript", "rust", 0.4),
            ("Some(", "javascript", "rust", 0.7),
            ("Ok(", "javascript", "rust", 0.7),
            ("Err(", "javascript", "rust", 0.7),
        ];

        for (pattern, applies_to, source, confidence) in &idioms {
            if target_lang == *applies_to && code.contains(pattern) {
                evidence.push(ProvenanceEvidence {
                    kind: EvidenceKind::AlgorithmTopology,
                    description: format!(
                        "Idiom '{}' is native to {} but found in {} code",
                        pattern, source, target_lang
                    ),
                    confidence: *confidence,
                    source_hint: Some(source.to_string()),
                });
            }
        }

        evidence
    }

    // ── Comment analysis ────────────────────────────────────────────

    fn analyze_comments(code: &str, target_lang: &str) -> Vec<ProvenanceEvidence> {
        let mut evidence = Vec::new();

        // Look for comments that reference another language
        let lang_refs = ["python", "javascript", "rust", "java", "c++", "golang",
                        "typescript", "ruby", "php", "swift", "kotlin"];

        for line in code.lines() {
            let trimmed = line.trim().to_lowercase();
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*") {
                // "ported from", "translated from", "based on", "adapted from"
                if trimmed.contains("ported from") || trimmed.contains("translated from")
                    || trimmed.contains("based on") || trimmed.contains("adapted from")
                    || trimmed.contains("converted from")
                {
                    for lang in &lang_refs {
                        if trimmed.contains(lang) && *lang != target_lang {
                            evidence.push(ProvenanceEvidence {
                                kind: EvidenceKind::VerbatimComments,
                                description: format!(
                                    "Comment indicates code was ported/translated from {}",
                                    lang
                                ),
                                confidence: 0.95,
                                source_hint: Some(lang.to_string()),
                            });
                        }
                    }
                }

                // Python-style comments in non-Python code
                if target_lang != "python" && trimmed.starts_with("# ") && !trimmed.starts_with("#!") {
                    // Could be a copied Python comment
                    evidence.push(ProvenanceEvidence {
                        kind: EvidenceKind::VerbatimComments,
                        description: "Python-style # comment in non-Python code".to_string(),
                        confidence: 0.2,
                        source_hint: Some("python".to_string()),
                    });
                }
            }
        }

        evidence
    }

    // ── Source language determination ────────────────────────────────

    fn determine_source_language(
        evidence: &[ProvenanceEvidence],
        artifacts: &[TranslationArtifact],
    ) -> Option<String> {
        let mut lang_scores: HashMap<String, f64> = HashMap::new();

        for ev in evidence {
            if let Some(ref hint) = ev.source_hint {
                *lang_scores.entry(hint.clone()).or_default() += ev.confidence;
            }
        }

        for art in artifacts {
            *lang_scores.entry(art.source_language.clone()).or_default() += 0.3;
        }

        lang_scores.into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
            .filter(|(_, score)| *score > 0.5)
            .map(|(lang, _)| lang)
    }

    fn compare_arity_distributions(
        a: &HashMap<usize, usize>,
        b: &HashMap<usize, usize>,
    ) -> f64 {
        if a.is_empty() && b.is_empty() { return 1.0; }
        if a.is_empty() || b.is_empty() { return 0.0; }

        let all_keys: HashSet<usize> = a.keys().chain(b.keys()).cloned().collect();
        let mut matching = 0;
        let mut total = 0;

        for key in &all_keys {
            let va = a.get(key).copied().unwrap_or(0);
            let vb = b.get(key).copied().unwrap_or(0);
            let max = va.max(vb);
            if max > 0 {
                matching += va.min(vb);
                total += max;
            }
        }

        if total == 0 { 0.0 } else { matching as f64 / total as f64 }
    }
}

/// Cross-language similarity result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossLanguageSimilarity {
    pub overall: f64,
    pub constant_similarity: f64,
    pub string_similarity: f64,
    pub arity_similarity: f64,
    pub algorithm_similarity: f64,
    pub identifier_similarity: f64,
    pub language_a: String,
    pub language_b: String,
}

// ─── Helpers ───────────────────────────────────────────────────────

fn normalize_identifier(id: &str) -> String {
    // Convert any naming convention to a canonical stem
    // camelCase → camel_case → ["camel", "case"]
    // snake_case → ["snake", "case"]
    // PascalCase → pascal_case → ["pascal", "case"]

    let mut words = Vec::new();
    let mut current = String::new();

    for ch in id.chars() {
        if ch == '_' || ch == '-' {
            if !current.is_empty() {
                words.push(current.to_lowercase());
                current.clear();
            }
        } else if ch.is_uppercase() && !current.is_empty() {
            words.push(current.to_lowercase());
            current.clear();
            current.push(ch);
        } else {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current.to_lowercase());
    }

    words.join("_")
}

fn is_snake_case(s: &str) -> bool {
    s.contains('_') && s.chars().all(|c| c.is_lowercase() || c.is_numeric() || c == '_')
}

fn is_camel_case(s: &str) -> bool {
    !s.contains('_') && s.chars().next().map_or(false, |c| c.is_lowercase())
        && s.chars().any(|c| c.is_uppercase())
}

fn is_pascal_case(s: &str) -> bool {
    !s.contains('_') && s.chars().next().map_or(false, |c| c.is_uppercase())
        && s.chars().skip(1).any(|c| c.is_lowercase())
}

fn jaccard_str(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() && b.is_empty() { return 0.0; }
    let a_set: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
    let intersection = a_set.intersection(&b_set).count() as f64;
    let union = a_set.union(&b_set).count() as f64;
    if union == 0.0 { 0.0 } else { intersection / union }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_identifier() {
        assert_eq!(normalize_identifier("camelCase"), "camel_case");
        assert_eq!(normalize_identifier("snake_case"), "snake_case");
        assert_eq!(normalize_identifier("PascalCase"), "pascal_case");
        assert_eq!(normalize_identifier("XMLParser"), "x_m_l_parser");
    }

    #[test]
    fn test_naming_convention_detection() {
        assert!(is_snake_case("hello_world"));
        assert!(!is_snake_case("helloWorld"));
        assert!(is_camel_case("helloWorld"));
        assert!(!is_camel_case("HelloWorld"));
        assert!(is_pascal_case("HelloWorld"));
    }

    #[test]
    fn test_python_in_javascript() {
        let code = r#"
            // ported from Python implementation
            function range(start, stop) {
                let result = [];
                for (let i = start; i < stop; i++) {
                    result.append(i);  // Python-ism
                }
                return result;
            }
        "#;

        let result = ProvenanceDetector::analyze(code, "javascript");
        assert!(!result.evidence.is_empty());
        assert!(result.evidence.iter().any(|e| e.source_hint.as_deref() == Some("python")));
    }

    #[test]
    fn test_cross_language_similarity() {
        let python = r#"
            def fibonacci(n):
                if n <= 1:
                    return n
                return fibonacci(n - 1) + fibonacci(n - 2)
        "#;

        let javascript = r#"
            function fibonacci(n) {
                if (n <= 1) return n;
                return fibonacci(n - 1) + fibonacci(n - 2);
            }
        "#;

        let sim = ProvenanceDetector::compare_cross_language(
            python, "python", javascript, "javascript"
        );
        assert!(sim.algorithm_similarity > 0.3, "Fibonacci should match across languages");
    }
}
