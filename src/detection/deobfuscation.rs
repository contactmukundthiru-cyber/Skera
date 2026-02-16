//! JavaScript de-obfuscation pipeline
//!
//! Pre-processes obfuscated JavaScript to recover original string literals,
//! resolve encoded values, and reverse common obfuscation patterns.
//! This module runs BEFORE fingerprint scanning so that our signature
//! database can match against the recovered content.
//!
//! ## Supported obfuscation techniques
//!
//! - **Hex/Unicode escape sequences**: `\x6a\x51\x75\x65\x72\x79` → `"jQuery"`
//! - **Base64 encoded strings**: `atob("alF1ZXJ5")` → `"jQuery"`
//! - **String array rotation**: `var _0x1234 = ["jQuery", ...]; _0x1234.push(_0x1234.shift());`
//! - **Hex integer variable names**: `_0x4a2f`, `_0x1b3c` (cosmetic, tracked)
//! - **String concatenation**: `"jQ" + "ue" + "ry"` → `"jQuery"`
//! - **String.fromCharCode**: `String.fromCharCode(106,81,117,101,114,121)` → `"jQuery"`
//! - **Unicode escapes**: `\u006a\u0051\u0075\u0065\u0072\u0079` → `"jQuery"`
//! - **Bracket notation property access**: `window["eval"]` → `window.eval`
//!
//! ## Architecture
//!
//! The de-obfuscator runs as a series of passes. Each pass produces a cleaner
//! version of the source. The original is preserved alongside for evidence.

use regex::Regex;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

// ─── Result Types ──────────────────────────────────────────────────

/// Result of de-obfuscation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeobfuscationResult {
    /// The cleaned/de-obfuscated content
    pub cleaned: String,
    /// The original content (preserved for evidence)
    pub original_length: usize,
    /// How many transformations were applied
    pub transformations: Vec<Transformation>,
    /// Overall obfuscation score (0.0 = clean, 1.0 = heavily obfuscated)
    pub obfuscation_score: f64,
    /// Detected obfuscator (if identifiable)
    pub detected_obfuscator: Option<String>,
}

/// A single de-obfuscation transformation that was applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transformation {
    /// What kind of transformation
    pub kind: TransformKind,
    /// How many instances were resolved
    pub count: usize,
    /// Example of what was resolved (for evidence)
    pub example: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransformKind {
    /// `\x6a\x51` → decoded string
    HexEscape,
    /// `\u006a\u0051` → decoded string
    UnicodeEscape,
    /// `atob("...")` → decoded string
    Base64Decode,
    /// `"a" + "b"` → `"ab"`
    StringConcat,
    /// `String.fromCharCode(...)` → string
    FromCharCode,
    /// String array lookup resolution
    StringArrayLookup,
    /// `parseInt("0x1b", 16)` → number
    ParseIntHex,
    /// Bracket notation → dot notation
    BracketToDot,
}

// ─── Regex Patterns ────────────────────────────────────────────────

static HEX_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches sequences of \xNN inside strings
    Regex::new(r#"(?:\\x[0-9a-fA-F]{2})+"#).unwrap()
});

static UNICODE_ESCAPE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches sequences of \uNNNN inside strings
    Regex::new(r#"(?:\\u[0-9a-fA-F]{4})+"#).unwrap()
});

static ATOB_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches atob("base64string") or atob('base64string')
    Regex::new(r#"atob\s*\(\s*["']([A-Za-z0-9+/=]+)["']\s*\)"#).unwrap()
});

static FROM_CHAR_CODE_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches String.fromCharCode(n1, n2, n3, ...)
    Regex::new(r#"String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)"#).unwrap()
});

static STRING_CONCAT_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches "a" + "b" or 'a' + 'b' (simple adjacent string concatenation)
    Regex::new(r#"["']([^"']{0,20})["']\s*\+\s*["']([^"']{0,20})["']"#).unwrap()
});

static BRACKET_PROP_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches obj["property"] → obj.property
    Regex::new(r#"(\w+)\s*\[\s*["'](\w+)["']\s*\]"#).unwrap()
});

static PARSE_INT_HEX_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches parseInt("0x1b", 16) or parseInt('0x1b', 16)
    Regex::new(r#"parseInt\s*\(\s*["'](0x[0-9a-fA-F]+)["']\s*,\s*16\s*\)"#).unwrap()
});

// ─── String Array Detection ───────────────────────────────────────

static STRING_ARRAY_DECL_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches: var _0xNNNN = ["str1", "str2", ...]
    Regex::new(r#"(?:var|let|const)\s+(_0x[0-9a-fA-F]+)\s*=\s*\[((?:\s*["'][^"']*["']\s*,?\s*)+)\]"#).unwrap()
});

#[allow(dead_code)]
static STRING_ARRAY_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    // Matches: _0xNNNN[0] or _0xNNNN[0x1b] or _0xNNNN(0x1b)
    Regex::new(r#"(_0x[0-9a-fA-F]+)\s*[\[\(]\s*(?:0x)?([0-9a-fA-F]+)\s*[\]\)]"#).unwrap()
});

// ─── Obfuscator Detection ─────────────────────────────────────────

static OBFUSCATOR_IO_RE: Lazy<Regex> = Lazy::new(|| {
    // javascript-obfuscator (obfuscator.io) signature patterns
    Regex::new(r#"_0x[0-9a-f]{4,6}\s*=\s*function\s*\(\s*_0x[0-9a-f]+"#).unwrap()
});

static JSCRAMBLER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"jscrambler|__jsc__"#).unwrap()
});

static UGLIFY_RE: Lazy<Regex> = Lazy::new(|| {
    // UglifyJS typically produces single-letter variables with specific patterns
    Regex::new(r#"!function\s*\([a-z]\s*,\s*[a-z]\s*,\s*[a-z]\)"#).unwrap()
});

// ─── The De-obfuscation Engine ────────────────────────────────────

/// JavaScript de-obfuscator
pub struct JsDeobfuscator {
    /// Maximum number of passes
    max_passes: usize,
}

impl JsDeobfuscator {
    pub fn new() -> Self {
        Self { max_passes: 5 }
    }

    /// Run the full de-obfuscation pipeline on JavaScript content
    pub fn deobfuscate(&self, content: &str) -> DeobfuscationResult {
        let original_length = content.len();
        let mut cleaned = content.to_string();
        let mut all_transforms = Vec::new();

        // Detect which obfuscator was used
        let detected_obfuscator = self.detect_obfuscator(content);

        // Multi-pass de-obfuscation — each pass may reveal new patterns
        for _pass in 0..self.max_passes {
            let before_len = cleaned.len();
            let mut pass_transforms = Vec::new();

            // Pass 1: Resolve hex escape sequences
            if let Some(t) = self.resolve_hex_escapes(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 2: Resolve unicode escape sequences
            if let Some(t) = self.resolve_unicode_escapes(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 3: Resolve atob() calls
            if let Some(t) = self.resolve_atob(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 4: Resolve String.fromCharCode()
            if let Some(t) = self.resolve_from_char_code(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 5: Resolve string concatenation
            if let Some(t) = self.resolve_string_concat(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 6: Resolve parseInt hex
            if let Some(t) = self.resolve_parse_int_hex(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 7: Resolve string array lookups
            if let Some(t) = self.resolve_string_arrays(&mut cleaned) {
                pass_transforms.push(t);
            }

            // Pass 8: Bracket to dot notation
            if let Some(t) = self.resolve_bracket_notation(&mut cleaned) {
                pass_transforms.push(t);
            }

            if pass_transforms.is_empty() || cleaned.len() == before_len {
                break; // No more transformations possible
            }

            all_transforms.extend(pass_transforms);
        }

        // Calculate obfuscation score
        let obfuscation_score = self.calculate_obfuscation_score(content, &cleaned);

        DeobfuscationResult {
            cleaned,
            original_length,
            transformations: all_transforms,
            obfuscation_score,
            detected_obfuscator,
        }
    }

    /// Detect which obfuscator tool was likely used
    fn detect_obfuscator(&self, content: &str) -> Option<String> {
        if OBFUSCATOR_IO_RE.is_match(content) {
            Some("javascript-obfuscator (obfuscator.io)".to_string())
        } else if JSCRAMBLER_RE.is_match(content) {
            Some("JScrambler".to_string())
        } else if UGLIFY_RE.is_match(content) {
            Some("UglifyJS".to_string())
        } else {
            None
        }
    }

    // ── Individual resolvers ────────────────────────────────────────

    /// Resolve `\x6a\x51\x75\x65\x72\x79` → decoded string
    fn resolve_hex_escapes(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = HEX_ESCAPE_RE.replace_all(content, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let decoded = decode_hex_escapes(matched);
            if count == 0 {
                example = Some(format!("{} → \"{}\"", matched, decoded));
            }
            count += 1;
            decoded
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::HexEscape,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `\u006a\u0051` → decoded string
    fn resolve_unicode_escapes(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = UNICODE_ESCAPE_RE.replace_all(content, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let decoded = decode_unicode_escapes(matched);
            if count == 0 {
                example = Some(format!("{} → \"{}\"", matched, decoded));
            }
            count += 1;
            decoded
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::UnicodeEscape,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `atob("base64")` → decoded string
    fn resolve_atob(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = ATOB_RE.replace_all(content, |caps: &regex::Captures| {
            let b64 = caps.get(1).unwrap().as_str();
            match decode_base64(b64) {
                Some(decoded) => {
                    if count == 0 {
                        example = Some(format!(
                            "atob(\"{}\") → \"{}\"",
                            &b64[..b64.len().min(20)],
                            &decoded[..decoded.len().min(30)]
                        ));
                    }
                    count += 1;
                    format!("\"{}\"", decoded.replace('"', "\\\""))
                }
                None => caps.get(0).unwrap().as_str().to_string(),
            }
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::Base64Decode,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `String.fromCharCode(106,81,117)` → decoded string
    fn resolve_from_char_code(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = FROM_CHAR_CODE_RE.replace_all(content, |caps: &regex::Captures| {
            let nums_str = caps.get(1).unwrap().as_str();
            let decoded: String = nums_str
                .split(',')
                .filter_map(|n| n.trim().parse::<u32>().ok())
                .filter_map(char::from_u32)
                .collect();

            if !decoded.is_empty() {
                if count == 0 {
                    example = Some(format!("fromCharCode({}) → \"{}\"", nums_str.trim(), decoded));
                }
                count += 1;
                format!("\"{}\"", decoded.replace('"', "\\\""))
            } else {
                caps.get(0).unwrap().as_str().to_string()
            }
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::FromCharCode,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `"a" + "b"` → `"ab"`
    fn resolve_string_concat(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        // Multi-pass — "a" + "b" + "c" requires two passes
        for _ in 0..10 {
            let prev = content.clone();
            let result = STRING_CONCAT_RE.replace_all(content, |caps: &regex::Captures| {
                let a = caps.get(1).unwrap().as_str();
                let b = caps.get(2).unwrap().as_str();
                if count == 0 {
                    example = Some(format!("\"{}\" + \"{}\" → \"{}{}\"", a, b, a, b));
                }
                count += 1;
                format!("\"{}{}\"", a, b)
            });
            *content = result.into_owned();
            if *content == prev {
                break;
            }
        }

        if count > 0 {
            Some(Transformation {
                kind: TransformKind::StringConcat,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `parseInt("0x1b", 16)` → `27`
    fn resolve_parse_int_hex(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = PARSE_INT_HEX_RE.replace_all(content, |caps: &regex::Captures| {
            let hex_str = caps.get(1).unwrap().as_str();
            let hex_digits = hex_str.trim_start_matches("0x");
            match u64::from_str_radix(hex_digits, 16) {
                Ok(val) => {
                    if count == 0 {
                        example = Some(format!("parseInt(\"{}\", 16) → {}", hex_str, val));
                    }
                    count += 1;
                    val.to_string()
                }
                Err(_) => caps.get(0).unwrap().as_str().to_string(),
            }
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::ParseIntHex,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve string array lookups:
    /// `var _0x1234 = ["jQuery", "fn"]; ... _0x1234[0]` → `"jQuery"`
    fn resolve_string_arrays(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        // First, find all string array declarations
        let arrays: Vec<(String, Vec<String>)> = STRING_ARRAY_DECL_RE
            .captures_iter(content)
            .filter_map(|cap| {
                let var_name = cap.get(1)?.as_str().to_string();
                let array_content = cap.get(2)?.as_str();

                // Parse the array elements
                let elements: Vec<String> = Regex::new(r#"["']([^"']*)["']"#)
                    .ok()?
                    .captures_iter(array_content)
                    .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
                    .collect();

                if elements.is_empty() {
                    None
                } else {
                    Some((var_name, elements))
                }
            })
            .collect();

        // Then resolve all accesses
        for (var_name, elements) in &arrays {
            let access_pattern = format!(
                r#"{}[\[\(]\s*(?:0x)?([0-9a-fA-F]+)\s*[\]\)]"#,
                regex::escape(var_name)
            );

            if let Ok(re) = Regex::new(&access_pattern) {
                let result = re.replace_all(content, |caps: &regex::Captures| {
                    let index_str = caps.get(1).unwrap().as_str();
                    let index = if index_str.len() > 2 {
                        usize::from_str_radix(index_str, 16).unwrap_or(usize::MAX)
                    } else {
                        index_str.parse::<usize>().unwrap_or(usize::MAX)
                    };

                    if let Some(value) = elements.get(index) {
                        if count == 0 {
                            example = Some(format!(
                                "{}[0x{}] → \"{}\"",
                                var_name, index_str, value
                            ));
                        }
                        count += 1;
                        format!("\"{}\"", value)
                    } else {
                        caps.get(0).unwrap().as_str().to_string()
                    }
                });

                *content = result.into_owned();
            }
        }

        if count > 0 {
            Some(Transformation {
                kind: TransformKind::StringArrayLookup,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Resolve `obj["property"]` → `obj.property`
    fn resolve_bracket_notation(&self, content: &mut String) -> Option<Transformation> {
        let mut count = 0;
        let mut example = None;

        let result = BRACKET_PROP_RE.replace_all(content, |caps: &regex::Captures| {
            let obj = caps.get(1).unwrap().as_str();
            let prop = caps.get(2).unwrap().as_str();
            if count == 0 {
                example = Some(format!("{}[\"{}\"] → {}.{}", obj, prop, obj, prop));
            }
            count += 1;
            format!("{}.{}", obj, prop)
        });

        if count > 0 {
            *content = result.into_owned();
            Some(Transformation {
                kind: TransformKind::BracketToDot,
                count,
                example,
            })
        } else {
            None
        }
    }

    /// Calculate how obfuscated the original content is (0.0 = clean, 1.0 = heavy)
    fn calculate_obfuscation_score(&self, original: &str, cleaned: &str) -> f64 {
        let mut score = 0.0;
        let len = original.len() as f64;
        if len == 0.0 {
            return 0.0;
        }

        // Factor 1: Density of hex variable names (_0xNNNN)
        let hex_vars = Regex::new(r"_0x[0-9a-fA-F]{2,6}")
            .unwrap()
            .find_iter(original)
            .count();
        let hex_density = (hex_vars as f64) / (len / 100.0);
        score += (hex_density * 0.1).min(0.3);

        // Factor 2: How much content changed during de-obfuscation
        let change_ratio = if cleaned.len() < original.len() {
            1.0 - (cleaned.len() as f64 / original.len() as f64)
        } else {
            0.0
        };
        score += change_ratio * 0.3;

        // Factor 3: Ratio of non-ASCII printable characters
        let non_ascii = original
            .chars()
            .filter(|c| !c.is_ascii_graphic() && !c.is_ascii_whitespace())
            .count();
        let non_ascii_ratio = non_ascii as f64 / len;
        score += (non_ascii_ratio * 10.0).min(0.2);

        // Factor 4: Average identifier length (obfuscated code has very short names)
        let ident_re = Regex::new(r"\b[a-zA-Z_]\w{0,2}\b").unwrap();
        let short_idents = ident_re.find_iter(original).count();
        let total_idents = Regex::new(r"\b[a-zA-Z_]\w*\b")
            .unwrap()
            .find_iter(original)
            .count()
            .max(1);
        let short_ratio = short_idents as f64 / total_idents as f64;
        if short_ratio > 0.8 {
            score += 0.2;
        }

        score.min(1.0)
    }
}

impl Default for JsDeobfuscator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helper Functions ──────────────────────────────────────────────

/// Decode `\x6a\x51\x75\x65\x72\x79` → "jQuery"
fn decode_hex_escapes(s: &str) -> String {
    let hex_re = Regex::new(r"\\x([0-9a-fA-F]{2})").unwrap();
    let mut result = String::new();
    for cap in hex_re.captures_iter(s) {
        if let Some(hex) = cap.get(1) {
            if let Ok(byte) = u8::from_str_radix(hex.as_str(), 16) {
                result.push(byte as char);
            }
        }
    }
    if result.is_empty() {
        s.to_string()
    } else {
        result
    }
}

/// Decode `\u006a\u0051` → "jQ"
fn decode_unicode_escapes(s: &str) -> String {
    let uni_re = Regex::new(r"\\u([0-9a-fA-F]{4})").unwrap();
    let mut result = String::new();
    for cap in uni_re.captures_iter(s) {
        if let Some(hex) = cap.get(1) {
            if let Ok(code) = u32::from_str_radix(hex.as_str(), 16) {
                if let Some(c) = char::from_u32(code) {
                    result.push(c);
                }
            }
        }
    }
    if result.is_empty() {
        s.to_string()
    } else {
        result
    }
}

/// Decode base64 string
fn decode_base64(s: &str) -> Option<String> {
    // Simple Base64 decoder (no external dependency)
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut bytes = Vec::new();
    let chars: Vec<u8> = s.bytes().filter(|b| *b != b'=').collect();

    for chunk in chars.chunks(4) {
        let mut val: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            let pos = alphabet.iter().position(|&b| b == byte)?;
            val |= (pos as u32) << (6 * (3 - i));
        }
        bytes.push((val >> 16) as u8);
        if chunk.len() > 2 {
            bytes.push((val >> 8) as u8);
        }
        if chunk.len() > 3 {
            bytes.push(val as u8);
        }
    }

    String::from_utf8(bytes).ok()
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_escape_decoding() {
        assert_eq!(
            decode_hex_escapes(r"\x6a\x51\x75\x65\x72\x79"),
            "jQuery"
        );
    }

    #[test]
    fn test_unicode_escape_decoding() {
        assert_eq!(
            decode_unicode_escapes(r"\u006a\u0051\u0075\u0065\u0072\u0079"),
            "jQuery"
        );
    }

    #[test]
    fn test_base64_decoding() {
        assert_eq!(decode_base64("alF1ZXJ5"), Some("jQuery".to_string()));
        assert_eq!(decode_base64("aGVsbG8="), Some("hello".to_string()));
    }

    #[test]
    fn test_from_char_code() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"var x = String.fromCharCode(106,81,117,101,114,121);"#.to_string();
        let t = deob.resolve_from_char_code(&mut content);
        assert!(t.is_some());
        assert!(content.contains("\"jQuery\""));
    }

    #[test]
    fn test_string_concat() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"var x = "jQ" + "ue" + "ry";"#.to_string();
        let t = deob.resolve_string_concat(&mut content);
        assert!(t.is_some());
        assert!(content.contains("\"jQuery\""));
    }

    #[test]
    fn test_atob() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"var x = atob("alF1ZXJ5");"#.to_string();
        let t = deob.resolve_atob(&mut content);
        assert!(t.is_some());
        assert!(content.contains("\"jQuery\""));
    }

    #[test]
    fn test_bracket_notation() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"window["eval"](code)"#.to_string();
        let t = deob.resolve_bracket_notation(&mut content);
        assert!(t.is_some());
        assert!(content.contains("window.eval"));
    }

    #[test]
    fn test_full_pipeline() {
        let deob = JsDeobfuscator::new();

        // Simulated obfuscated code referencing jQuery
        let obfuscated = r#"
            var _0x1234 = String.fromCharCode(106,81,117,101,114,121);
            var _0x5678 = atob("Zm4=");
            window["eval"](_0x1234);
        "#;

        let result = deob.deobfuscate(obfuscated);
        assert!(result.cleaned.contains("jQuery") || result.cleaned.contains("\"jQuery\""));
        assert!(!result.transformations.is_empty());
    }

    #[test]
    fn test_parse_int_hex() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"var idx = parseInt("0x1b", 16);"#.to_string();
        let t = deob.resolve_parse_int_hex(&mut content);
        assert!(t.is_some());
        assert!(content.contains("27"));
    }

    #[test]
    fn test_string_array_lookup() {
        let deob = JsDeobfuscator::new();
        let mut content = r#"
            var _0xabc = ["jQuery", "fn", "extend", "prototype"];
            var x = _0xabc[0];
            var y = _0xabc[0x1];
        "#
        .to_string();
        let t = deob.resolve_string_arrays(&mut content);
        assert!(t.is_some());
        assert!(content.contains("\"jQuery\""));
        assert!(content.contains("\"fn\""));
    }
}
