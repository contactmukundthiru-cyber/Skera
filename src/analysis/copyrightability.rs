//! Copyrightability Analyzer — determines WHETHER code is even protectable
//!
//! This is Skera's _legal intelligence_ layer. Instead of just flagging "this
//! code is similar," we analyze WHETHER the similar code is copyrightable at all.
//!
//! ## Legal Doctrines Implemented
//!
//! ### Merger Doctrine
//! When there is only one (or very few) ways to express an idea, the expression
//! "merges" with the idea and is NOT copyrightable. A quicksort is a quicksort.
//! There are only so many ways to write `Array.prototype.sort`.
//!
//! ### Scènes à Faire
//! Standard programming patterns that are dictated by the nature of the problem
//! are not copyrightable. Error handling patterns, initialization boilerplate,
//! getter/setter pairs — these are scenes that "must" be written a certain way.
//!
//! ### Functional Limitation
//! Code whose expression is entirely dictated by its function cannot be
//! copyrighted separately from its function. You can't copyright a hash
//! function's implementation if the algorithm IS the expression.
//!
//! ### LLM Output & Purpose Binding
//! LLM-generated code learns statistical patterns from training data. Claiming
//! that LLM output "copies" training data would require binding the OUTPUT to
//! the PURPOSE of the training data — but purpose/function is an IDEA, not
//! EXPRESSION, and ideas are not copyrightable. The LLM doesn't copy; it
//! learns patterns and generates new expressions of the same ideas.
//!
//! ## How It Works
//!
//! ```text
//! Input: Two similar code snippets
//!        ↓
//! 1. Algorithmic Classification
//!    → Is this a known algorithm? (sort, search, hash, crypto)
//!    → If yes: merger doctrine may apply
//!        ↓
//! 2. Expression Space Analysis
//!    → How many DIFFERENT ways can this function be written?
//!    → Low expression space = likely not copyrightable
//!        ↓
//! 3. Scènes à Faire Detection
//!    → Is this a standard pattern (error handling, init, config)?
//!    → If yes: not copyrightable
//!        ↓
//! 4. Creative Expression Test
//!    → After removing non-copyrightable elements, is there
//!      sufficient CREATIVE CHOICE in the remaining expression?
//!    → Variable naming, code organization, comments, unique
//!      architectural decisions count as creative expression
//!        ↓
//! Output: CopyrightabilityAssessment
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ─── Core Types ─────────────────────────────────────────────────────

/// Assessment of whether code is copyrightable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyrightabilityAssessment {
    /// Overall conclusion
    pub conclusion: Copyrightability,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Doctrines that apply
    pub applicable_doctrines: Vec<LegalDoctrine>,
    /// Detailed reasoning
    pub reasoning: Vec<String>,
    /// Expression space score — how many ways can this be written?
    /// 0.0 = only one way (merger), 1.0 = infinite creative choices
    pub expression_space: f64,
    /// Proportion of code that is scènes à faire
    pub scenes_a_faire_ratio: f64,
    /// Creative elements identified
    pub creative_elements: Vec<CreativeElement>,
    /// Non-copyrightable elements identified
    pub non_copyrightable_elements: Vec<NonCopyrightableElement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Copyrightability {
    /// Clearly copyrightable — creative expression present
    Copyrightable,
    /// Likely copyrightable but thin protection
    ThinProtection,
    /// Borderline — significant functional constraints
    Borderline,
    /// Likely NOT copyrightable — merger/scènes à faire
    LikelyNotCopyrightable,
    /// Definitively not copyrightable — pure algorithm/idea
    NotCopyrightable,
}

impl std::fmt::Display for Copyrightability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Copyrightable => write!(f, "Copyrightable"),
            Self::ThinProtection => write!(f, "Thin Protection"),
            Self::Borderline => write!(f, "Borderline"),
            Self::LikelyNotCopyrightable => write!(f, "Likely Not Copyrightable"),
            Self::NotCopyrightable => write!(f, "Not Copyrightable"),
        }
    }
}

/// Legal doctrines that may limit copyrightability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalDoctrine {
    pub name: String,
    pub applies: bool,
    pub strength: f64,
    pub explanation: String,
}

/// An element of creative expression in code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreativeElement {
    pub kind: CreativeElementKind,
    pub description: String,
    pub line_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreativeElementKind {
    /// Unique variable/function naming scheme
    NamingConvention,
    /// Non-obvious code organization
    ArchitecturalChoice,
    /// Distinctive comment style/content
    CommentaryExpression,
    /// Creative error message text
    ErrorMessageText,
    /// Unique API surface design
    ApiDesign,
    /// Non-standard algorithm variation
    AlgorithmVariation,
    /// Distinctive formatting/style
    StyleChoice,
    /// Custom data structure design
    DataStructureDesign,
}

/// A non-copyrightable element
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonCopyrightableElement {
    pub kind: NonCopyrightableKind,
    pub description: String,
    pub doctrine: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NonCopyrightableKind {
    /// Standard algorithm implementation
    StandardAlgorithm,
    /// Boilerplate/initialization code
    Boilerplate,
    /// Error handling pattern
    ErrorHandlingPattern,
    /// Language-mandated syntax
    LanguageSyntax,
    /// API-conforming implementation
    ApiConformance,
    /// Mathematical formula
    MathematicalFormula,
    /// Industry-standard protocol implementation
    ProtocolImplementation,
    /// Common design pattern (singleton, factory, observer)
    DesignPattern,
    /// LLM-generated statistical pattern
    LlmStatisticalPattern,
}

// ─── Known Algorithms / Patterns ───────────────────────────────────

/// Known algorithms and their expression space constraints
struct KnownAlgorithm {
    name: &'static str,
    /// Signature patterns that identify this algorithm
    patterns: &'static [&'static str],
    /// How constrained is the expression? (0.0 = completely constrained)
    expression_freedom: f64,
    /// Legal doctrine that applies
    doctrine: &'static str,
}

const KNOWN_ALGORITHMS: &[KnownAlgorithm] = &[
    KnownAlgorithm {
        name: "quicksort",
        patterns: &["pivot", "partition", "quicksort", "qsort"],
        expression_freedom: 0.15,
        doctrine: "Merger: limited ways to implement quicksort",
    },
    KnownAlgorithm {
        name: "mergesort",
        patterns: &["merge", "mergesort", "merge_sort"],
        expression_freedom: 0.15,
        doctrine: "Merger: limited ways to implement mergesort",
    },
    KnownAlgorithm {
        name: "binary_search",
        patterns: &["binary_search", "binarySearch", "bisect", "lower_bound", "upper_bound"],
        expression_freedom: 0.1,
        doctrine: "Merger: binary search has essentially one correct implementation",
    },
    KnownAlgorithm {
        name: "hash_table",
        patterns: &["hash_map", "HashMap", "hash_table", "bucket", "rehash", "load_factor"],
        expression_freedom: 0.3,
        doctrine: "Merger: hash table mechanics are well-determined",
    },
    KnownAlgorithm {
        name: "sha256",
        patterns: &["sha256", "SHA-256", "sha2", "0x6a09e667", "0xbb67ae85"],
        expression_freedom: 0.05,
        doctrine: "Merger: SHA-256 is a mathematical specification with one implementation",
    },
    KnownAlgorithm {
        name: "aes",
        patterns: &["aes", "AES", "rijndael", "SubBytes", "ShiftRows", "MixColumns", "sbox"],
        expression_freedom: 0.05,
        doctrine: "Merger: AES is specified by FIPS 197 — the implementation IS the spec",
    },
    KnownAlgorithm {
        name: "json_parser",
        patterns: &["parse_value", "parse_string", "parse_number", "parse_array", "parse_object", "JSON.parse"],
        expression_freedom: 0.2,
        doctrine: "Merger: JSON parsing is constrained by RFC 8259",
    },
    KnownAlgorithm {
        name: "url_parser",
        patterns: &["parse_url", "parse_authority", "parse_path", "parse_query", "URL.parse"],
        expression_freedom: 0.2,
        doctrine: "Merger: URL parsing is constrained by RFC 3986",
    },
    KnownAlgorithm {
        name: "regex_engine",
        patterns: &["nfa", "dfa", "compile_regex", "match_char", "alternation", "kleene"],
        expression_freedom: 0.35,
        doctrine: "Scènes à faire: regex engines follow the Thompson/Pike construction",
    },
    KnownAlgorithm {
        name: "http_server",
        patterns: &["listen", "accept", "parse_request", "send_response", "Content-Type", "200 OK"],
        expression_freedom: 0.25,
        doctrine: "Scènes à faire: HTTP server patterns are protocol-dictated",
    },
    KnownAlgorithm {
        name: "event_emitter",
        patterns: &["addEventListener", "removeEventListener", "emit", "on(", "off(", "listeners"],
        expression_freedom: 0.2,
        doctrine: "Design pattern: event emitter/observer is a standard pattern",
    },
    KnownAlgorithm {
        name: "promise_implementation",
        patterns: &["resolve", "reject", "then(", "catch(", "finally(", "Promise"],
        expression_freedom: 0.15,
        doctrine: "Scènes à faire: Promise/A+ spec dictates implementation",
    },
    KnownAlgorithm {
        name: "linked_list",
        patterns: &["next", "prev", "head", "tail", "push_front", "push_back", "node"],
        expression_freedom: 0.1,
        doctrine: "Merger: linked list has essentially one implementation",
    },
    KnownAlgorithm {
        name: "tree_traversal",
        patterns: &["inorder", "preorder", "postorder", "visit", "left", "right", "traverse"],
        expression_freedom: 0.1,
        doctrine: "Merger: tree traversal algorithms are mathematically determined",
    },
];

/// Common scènes à faire patterns
const SCENES_A_FAIRE: &[(&str, &[&str])] = &[
    ("error_handling", &["try", "catch", "throw", "Error", "finally", "error", "err"]),
    ("null_checks", &["null", "undefined", "None", "nil", "== null", "!= null", "is None"]),
    ("type_checking", &["typeof", "instanceof", "is_a?", "isinstance", ".is_none()"]),
    ("getters_setters", &["get_", "set_", "get()", "set()", "getter", "setter"]),
    ("constructor_init", &["constructor", "__init__", "new(", "initialize", "init("]),
    ("iterator_pattern", &["next()", "hasNext", "iter()", "Iterator", "__iter__", "StopIteration"]),
    ("comparison", &["compareTo", "equals", "==", "!=", "cmp", "Ord", "PartialEq"]),
    ("string_formatting", &["format!", "sprintf", "f\"", "Template", "interpolate"]),
    ("file_io", &["open(", "read(", "write(", "close(", "File::", "fopen", "fclose"]),
    ("config_loading", &["load_config", "parse_config", "dotenv", "env::", "process.env"]),
    ("logging", &["log(", "debug(", "info(", "warn(", "error(", "trace(", "tracing::"]),
    ("serialization", &["serialize", "deserialize", "to_json", "from_json", "encode", "decode"]),
    ("validation", &["validate", "is_valid", "check_", "assert", "ensure"]),
];

// ─── The Analyzer ──────────────────────────────────────────────────

/// Copyrightability analyzer
pub struct CopyrightabilityAnalyzer;

impl CopyrightabilityAnalyzer {
    /// Analyze whether a code snippet is copyrightable
    pub fn analyze(code: &str) -> CopyrightabilityAssessment {
        let code_lower = code.to_lowercase();
        let lines: Vec<&str> = code.lines().collect();
        let total_lines = lines.len();

        let mut applicable_doctrines = Vec::new();
        let mut reasoning = Vec::new();
        let mut creative_elements = Vec::new();
        let mut non_copyrightable_elements = Vec::new();

        // Step 1: Check for known algorithm implementations
        let mut algorithm_match = None;
        let mut best_algo_score = 0usize;

        for algo in KNOWN_ALGORITHMS {
            let matches: usize = algo.patterns.iter()
                .filter(|p| code_lower.contains(&p.to_lowercase()))
                .count();

            if matches > best_algo_score && matches >= 2 {
                best_algo_score = matches;
                algorithm_match = Some(algo);
            }
        }

        let expression_space;

        if let Some(algo) = algorithm_match {
            expression_space = algo.expression_freedom;
            applicable_doctrines.push(LegalDoctrine {
                name: "Merger Doctrine".to_string(),
                applies: true,
                strength: 1.0 - algo.expression_freedom,
                explanation: algo.doctrine.to_string(),
            });
            reasoning.push(format!(
                "Code implements '{}' — a known algorithm with expression freedom {:.0}%. {}",
                algo.name, algo.expression_freedom * 100.0, algo.doctrine
            ));
            non_copyrightable_elements.push(NonCopyrightableElement {
                kind: NonCopyrightableKind::StandardAlgorithm,
                description: format!("Implementation of '{}'", algo.name),
                doctrine: "Merger Doctrine".to_string(),
            });
        } else {
            // Estimate expression space from code complexity
            expression_space = estimate_expression_space(code);
        }

        // Step 2: Detect scènes à faire
        let mut saf_lines = 0usize;

        for (pattern_name, markers) in SCENES_A_FAIRE {
            let mut found_markers = 0;
            for marker in *markers {
                if code_lower.contains(&marker.to_lowercase()) {
                    found_markers += 1;
                }
            }

            if found_markers >= 2 {
                // Count lines that are part of this scene
                for line in &lines {
                    let line_lower = line.to_lowercase();
                    for marker in *markers {
                        if line_lower.contains(&marker.to_lowercase()) {
                            saf_lines += 1;
                            break;
                        }
                    }
                }

                non_copyrightable_elements.push(NonCopyrightableElement {
                    kind: NonCopyrightableKind::Boilerplate,
                    description: format!("'{}' pattern (standard programming convention)", pattern_name),
                    doctrine: "Scènes à Faire".to_string(),
                });
            }
        }

        let scenes_a_faire_ratio = if total_lines > 0 {
            (saf_lines as f64 / total_lines as f64).min(1.0)
        } else {
            0.0
        };

        if scenes_a_faire_ratio > 0.4 {
            applicable_doctrines.push(LegalDoctrine {
                name: "Scènes à Faire".to_string(),
                applies: true,
                strength: scenes_a_faire_ratio,
                explanation: format!(
                    "{:.0}% of code consists of standard programming patterns dictated by the nature of the problem",
                    scenes_a_faire_ratio * 100.0
                ),
            });
            reasoning.push(format!(
                "{:.0}% of lines are scènes à faire — standard patterns any programmer would write the same way",
                scenes_a_faire_ratio * 100.0
            ));
        }

        // Step 3: Identify creative elements
        // Comments with unique content
        let comment_lines: Vec<&str> = lines.iter()
            .filter(|l| l.trim().starts_with("//") || l.trim().starts_with('#')
                || l.trim().starts_with("/*") || l.trim().starts_with('*'))
            .copied()
            .collect();

        if comment_lines.len() > 3 {
            // Check if comments contain creative expression (not just "TODO" or "FIXME")
            let creative_comments = comment_lines.iter()
                .filter(|c| {
                    let t = c.trim().to_lowercase();
                    !t.starts_with("// todo") && !t.starts_with("// fixme")
                        && !t.starts_with("// hack") && !t.starts_with("// note:")
                        && t.len() > 20
                })
                .count();

            if creative_comments > 2 {
                creative_elements.push(CreativeElement {
                    kind: CreativeElementKind::CommentaryExpression,
                    description: format!("{} substantive comments with original expression", creative_comments),
                    line_range: None,
                });
            }
        }

        // Unique naming conventions
        let identifier_re = regex::Regex::new(r"\b([a-zA-Z_]\w{3,})\b").unwrap();
        let identifiers: HashSet<String> = identifier_re.captures_iter(code)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        // Check for domain-specific or creative identifiers
        let common_identifiers: HashSet<&str> = [
            "function", "return", "const", "let", "var", "this", "self",
            "true", "false", "null", "undefined", "string", "number",
            "boolean", "void", "async", "await", "import", "export",
            "class", "struct", "enum", "impl", "pub", "fn", "use",
            "for", "while", "if", "else", "match", "switch", "case",
            "break", "continue", "try", "catch", "throw", "finally",
        ].iter().cloned().collect();

        let unique_identifiers: Vec<&String> = identifiers.iter()
            .filter(|id| !common_identifiers.contains(id.as_str()))
            .collect();

        // Domain-specific naming suggests creative expression
        if unique_identifiers.len() > 10 {
            creative_elements.push(CreativeElement {
                kind: CreativeElementKind::NamingConvention,
                description: format!("{} unique identifiers suggesting domain-specific creative naming", unique_identifiers.len()),
                line_range: None,
            });
        }

        // Check for custom error messages (creative expression)
        let error_msg_re = regex::Regex::new(r#"(?:Error|throw|panic!?|raise)\s*\(\s*["']([^"']{20,})["']"#).unwrap();
        let error_msgs: Vec<String> = error_msg_re.captures_iter(code)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect();

        if !error_msgs.is_empty() {
            creative_elements.push(CreativeElement {
                kind: CreativeElementKind::ErrorMessageText,
                description: format!("{} custom error messages with original text", error_msgs.len()),
                line_range: None,
            });
        }

        // Step 4: Check for code size (very short code is rarely copyrightable)
        if total_lines < 10 {
            applicable_doctrines.push(LegalDoctrine {
                name: "De Minimis".to_string(),
                applies: true,
                strength: 0.8,
                explanation: format!(
                    "Code is only {} lines — may not meet the threshold of originality for copyright protection",
                    total_lines
                ),
            });
            reasoning.push(format!(
                "Code is {} lines — extremely short code rarely has sufficient creative expression for copyright",
                total_lines
            ));
        }

        // Step 5: Determine overall copyrightability
        let creative_score = creative_elements.len() as f64 * 0.15;
        let noncopyright_penalty = non_copyrightable_elements.len() as f64 * 0.12;
        let space_factor = expression_space;

        // Final score: high creative + high expression space = copyrightable
        let final_score = (creative_score + space_factor - noncopyright_penalty - scenes_a_faire_ratio * 0.5)
            .clamp(0.0, 1.0);

        let conclusion = if final_score > 0.7 {
            Copyrightability::Copyrightable
        } else if final_score > 0.5 {
            Copyrightability::ThinProtection
        } else if final_score > 0.3 {
            Copyrightability::Borderline
        } else if final_score > 0.15 {
            Copyrightability::LikelyNotCopyrightable
        } else {
            Copyrightability::NotCopyrightable
        };

        if conclusion == Copyrightability::NotCopyrightable || conclusion == Copyrightability::LikelyNotCopyrightable {
            reasoning.push(
                "After removing standard algorithm implementations, scènes à faire patterns, \
                 and language-mandated syntax, insufficient creative expression remains for \
                 copyright protection.".to_string()
            );
        }

        CopyrightabilityAssessment {
            conclusion,
            confidence: 0.5 + (final_score - 0.5).abs() * 0.8,
            applicable_doctrines,
            reasoning,
            expression_space,
            scenes_a_faire_ratio,
            creative_elements,
            non_copyrightable_elements,
        }
    }

    /// Analyze whether LLM-generated code inherits the copyright of its training data
    ///
    /// Core argument: binding LLM output to training data licenses requires
    /// binding PURPOSE (the function the code performs), not EXPRESSION (how
    /// the code is written). Purpose is IDEA; ideas aren't copyrightable.
    pub fn analyze_llm_output(generated_code: &str, similar_training_code: Option<&str>) -> LlmCopyrightAssessment {
        let base_assessment = Self::analyze(generated_code);

        let mut reasoning = Vec::new();

        // LLMs learn statistical patterns, not expressions
        reasoning.push(
            "LLMs do not 'copy' training data — they learn statistical patterns and generate \
             new expressions. Copyright protects EXPRESSION, not the statistical distribution \
             of tokens learned during training.".to_string()
        );

        // The purpose/function distinction
        reasoning.push(
            "Claiming LLM output infringes training data copyright requires proving the output \
             copies protectable EXPRESSION, not just that it serves the same PURPOSE. Serving \
             the same purpose (sorting, parsing, hashing) is implementing an IDEA, which is \
             not copyrightable under 17 U.S.C. § 102(b).".to_string()
        );

        let mut similarity_assessment = None;

        if let Some(training_code) = similar_training_code {
            // Compare the generated code against the similar training code
            let training_assessment = Self::analyze(training_code);

            // If the training code itself isn't copyrightable (merger/scènes à faire),
            // then similarity to it by LLM output is irrelevant
            if training_assessment.conclusion == Copyrightability::NotCopyrightable
                || training_assessment.conclusion == Copyrightability::LikelyNotCopyrightable
            {
                reasoning.push(format!(
                    "The similar training code is itself likely NOT copyrightable ({}) — \
                     similarity to non-copyrightable code cannot constitute infringement.",
                    training_assessment.conclusion
                ));
            }

            // Check structural similarity vs. creative similarity
            let structural_sim = compute_structural_similarity(generated_code, training_code);
            let creative_sim = compute_creative_similarity(generated_code, training_code);

            reasoning.push(format!(
                "Structural similarity: {:.0}% (algorithm/pattern level). \
                 Creative similarity: {:.0}% (naming/comments/style level). \
                 If structural similarity is high but creative similarity is low, \
                 the similarity is at the IDEA level, not EXPRESSION level.",
                structural_sim * 100.0, creative_sim * 100.0
            ));

            similarity_assessment = Some(SimilarityBreakdown {
                structural_similarity: structural_sim,
                creative_similarity: creative_sim,
                total_similarity: structural_sim * 0.3 + creative_sim * 0.7,
                training_code_copyrightable: training_assessment.conclusion != Copyrightability::NotCopyrightable
                    && training_assessment.conclusion != Copyrightability::LikelyNotCopyrightable,
            });
        }

        let infringement_risk = if let Some(ref sim) = similarity_assessment {
            if !sim.training_code_copyrightable {
                InfringementRisk::None
            } else if sim.creative_similarity > 0.8 {
                InfringementRisk::High
            } else if sim.creative_similarity > 0.5 {
                InfringementRisk::Moderate
            } else if sim.structural_similarity > 0.8 && sim.creative_similarity < 0.3 {
                reasoning.push(
                    "High structural similarity with low creative similarity indicates \
                     convergent implementation of the same algorithm — this is the IDEA, \
                     not protectable EXPRESSION.".to_string()
                );
                InfringementRisk::Low
            } else {
                InfringementRisk::Low
            }
        } else {
            InfringementRisk::Unknown
        };

        LlmCopyrightAssessment {
            base_assessment,
            infringement_risk,
            similarity: similarity_assessment,
            reasoning,
        }
    }
}

/// Assessment of LLM-generated code copyright status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmCopyrightAssessment {
    pub base_assessment: CopyrightabilityAssessment,
    pub infringement_risk: InfringementRisk,
    pub similarity: Option<SimilarityBreakdown>,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InfringementRisk {
    None,
    Low,
    Moderate,
    High,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityBreakdown {
    /// Similarity at the algorithm/structure level (idea)
    pub structural_similarity: f64,
    /// Similarity at the creative expression level (naming, style, comments)
    pub creative_similarity: f64,
    /// Combined similarity (weighted toward creative)
    pub total_similarity: f64,
    /// Whether the training code is itself copyrightable
    pub training_code_copyrightable: bool,
}

// ─── Internal helpers ──────────────────────────────────────────────

fn estimate_expression_space(code: &str) -> f64 {
    let lines = code.lines().count() as f64;
    let unique_chars: HashSet<char> = code.chars().collect();

    // More complex code = more room for creative choices
    let complexity = (lines / 100.0).min(1.0);
    let vocabulary = (unique_chars.len() as f64 / 80.0).min(1.0);

    // Average
    (complexity * 0.6 + vocabulary * 0.4).clamp(0.1, 0.95)
}

fn compute_structural_similarity(a: &str, b: &str) -> f64 {
    // Extract control flow keywords from both
    let keywords = ["if", "else", "for", "while", "return", "switch", "match",
                    "try", "catch", "fn", "function", "def", "class"];

    let a_structure: Vec<&str> = a.split_whitespace()
        .filter(|w| keywords.contains(&w.to_lowercase().as_str()))
        .collect();
    let b_structure: Vec<&str> = b.split_whitespace()
        .filter(|w| keywords.contains(&w.to_lowercase().as_str()))
        .collect();

    if a_structure.is_empty() && b_structure.is_empty() { return 0.0; }
    if a_structure.is_empty() || b_structure.is_empty() { return 0.0; }

    let a_set: HashSet<&&str> = a_structure.iter().collect();
    let b_set: HashSet<&&str> = b_structure.iter().collect();

    let intersection = a_set.intersection(&b_set).count() as f64;
    let union = a_set.union(&b_set).count() as f64;

    if union == 0.0 { 0.0 } else { intersection / union }
}

fn compute_creative_similarity(a: &str, b: &str) -> f64 {
    // Compare non-keyword identifiers, comments, string literals
    let id_re = regex::Regex::new(r"\b([a-zA-Z_]\w{4,})\b").unwrap();

    let common_words: HashSet<&str> = [
        "function", "return", "const", "let", "var", "this", "self",
        "true", "false", "null", "undefined", "string", "number",
        "class", "struct", "impl", "pub", "async", "await",
    ].iter().cloned().collect();

    let a_ids: HashSet<String> = id_re.captures_iter(a)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|id| !common_words.contains(id.as_str()))
        .collect();

    let b_ids: HashSet<String> = id_re.captures_iter(b)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter(|id| !common_words.contains(id.as_str()))
        .collect();

    if a_ids.is_empty() && b_ids.is_empty() { return 0.0; }
    if a_ids.is_empty() || b_ids.is_empty() { return 0.0; }

    let intersection = a_ids.intersection(&b_ids).count() as f64;
    let union = a_ids.union(&b_ids).count() as f64;

    if union == 0.0 { 0.0 } else { intersection / union }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quicksort_not_copyrightable() {
        let code = r#"
            function quicksort(arr) {
                if (arr.length <= 1) return arr;
                const pivot = arr[0];
                const left = arr.filter(x => x < pivot);
                const right = arr.filter(x => x > pivot);
                return [...quicksort(left), pivot, ...quicksort(right)];
            }
        "#;

        let result = CopyrightabilityAnalyzer::analyze(code);
        assert!(result.expression_space < 0.3);
        assert!(matches!(
            result.conclusion,
            Copyrightability::NotCopyrightable | Copyrightability::LikelyNotCopyrightable | Copyrightability::Borderline
        ));
    }

    #[test]
    fn test_sha256_not_copyrightable() {
        let code = r#"
            fn sha256_transform(state: &mut [u32; 8], block: &[u8; 64]) {
                let mut w = [0u32; 64];
                // SHA-256 constants: 0x6a09e667, 0xbb67ae85
                for i in 0..16 {
                    w[i] = u32::from_be_bytes([block[4*i], block[4*i+1], block[4*i+2], block[4*i+3]]);
                }
            }
        "#;

        let result = CopyrightabilityAnalyzer::analyze(code);
        assert!(result.expression_space < 0.2);
    }

    #[test]
    fn test_creative_code_copyrightable() {
        let code = r#"
            /// The Nebula Engine processes celestial data streams using a proprietary
            /// algorithm developed by the Meridian Observatory team. Each observation
            /// is weighted by its photonic resonance coefficient, creating a spectral
            /// fingerprint unique to each stellar classification.
            ///
            /// Dr. Chen's insight was that chromatic aberration in the sensor array
            /// could be leveraged as a natural frequency filter, turning a hardware
            /// limitation into an analytical advantage.
            pub struct NebulaEngine {
                spectral_harmonizer: SpectralHarmonizer,
                photonic_weight_table: HashMap<StarClass, Vec<f64>>,
                aberration_compensator: AberrationCompensator,
                resonance_threshold: f64,
            }

            impl NebulaEngine {
                pub fn classify_observation(&self, raw_data: &ObservationData) -> StellarClassification {
                    let compensated = self.aberration_compensator.apply(raw_data);
                    let spectrum = self.spectral_harmonizer.harmonize(&compensated);
                    let weights = self.photonic_weight_table.get(&StarClass::Unknown)
                        .expect("Default classification weights missing — this should never happen");

                    let resonance = spectrum.compute_resonance(weights);
                    if resonance > self.resonance_threshold {
                        self.classify_high_resonance(&spectrum, resonance)
                    } else {
                        self.classify_standard(&spectrum)
                    }
                }
            }
        "#;

        let result = CopyrightabilityAnalyzer::analyze(code);
        assert!(result.creative_elements.len() >= 2);
        assert!(matches!(
            result.conclusion,
            Copyrightability::Copyrightable | Copyrightability::ThinProtection
        ));
    }

    #[test]
    fn test_llm_output_structural_similarity() {
        let generated = r#"
            function sort(arr) {
                if (arr.length <= 1) return arr;
                let pivot = arr[Math.floor(arr.length / 2)];
                let left = arr.filter(x => x < pivot);
                let middle = arr.filter(x => x === pivot);
                let right = arr.filter(x => x > pivot);
                return [...sort(left), ...middle, ...sort(right)];
            }
        "#;

        let training = r#"
            function quicksort(array) {
                if (array.length <= 1) return array;
                const pivot = array[0];
                const less = array.filter(item => item < pivot);
                const greater = array.filter(item => item > pivot);
                return [...quicksort(less), pivot, ...quicksort(greater)];
            }
        "#;

        let result = CopyrightabilityAnalyzer::analyze_llm_output(generated, Some(training));
        // Structural similarity should be high (same algorithm)
        // But creative similarity should be lower (different naming)
        // And the training code itself isn't copyrightable (it's quicksort)
        assert!(matches!(
            result.infringement_risk,
            InfringementRisk::None | InfringementRisk::Low
        ));
    }
}
