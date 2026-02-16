//! Advanced JS analysis techniques — entropy, obfuscation, font/CSS extraction
//!
//! These complement the fingerprint-based detection in `js_bundle_forensics`
//! with signal-layer analysis that makes detection "unrelenting":
//!
//! - **Entropy analysis**: high entropy ⇒ obfuscated/encoded content
//! - **Obfuscation scoring**: variable name patterns, eval usage, string encoding
//! - **Network endpoint extraction**: URLs found in code
//! - **Font/CSS extraction**: detect font-family and @font-face usage
//! - **Minifier identification**: which tool was used to transform the code

use serde::{Deserialize, Serialize};

// ─── Entropy Analysis ──────────────────────────────────────────────

/// Shannon entropy of a byte string (bits per byte, 0.0-8.0).
/// Normal minified JS: ~4.5-5.5. Obfuscated: ~5.5-6.5. Encrypted/packed: ~7.0+.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Windowed entropy — computes entropy for sliding windows across the file.
/// Useful for finding pockets of obfuscated/encoded data within normal code.
pub fn windowed_entropy(data: &[u8], window_size: usize, step: usize) -> Vec<EntropyWindow> {
    let mut windows = Vec::new();
    let mut offset = 0;

    while offset + window_size <= data.len() {
        let window = &data[offset..offset + window_size];
        let entropy = shannon_entropy(window);
        windows.push(EntropyWindow {
            offset,
            size: window_size,
            entropy,
        });
        offset += step;
    }

    windows
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyWindow {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
}

// ─── Obfuscation Scoring ───────────────────────────────────────────

/// Analyze code for signs of deliberate obfuscation.
/// Returns a score from 0.0 (clean) to 1.0 (heavily obfuscated).
pub fn obfuscation_score(content: &str) -> ObfuscationReport {
    let mut signals = Vec::new();
    let mut score = 0.0;

    // Signal 1: eval() / Function() usage — classic obfuscation technique
    let eval_count = content.matches("eval(").count() + content.matches("eval (").count();
    let function_constructor = content.matches("Function(").count()
        + content.matches("new Function").count();
    if eval_count > 0 {
        let s = (eval_count as f64 * 0.15).min(0.3);
        score += s;
        signals.push(ObfuscationSignal {
            kind: "eval_usage".into(),
            description: format!("{} eval() calls detected", eval_count),
            weight: s,
        });
    }
    if function_constructor > 0 {
        let s = (function_constructor as f64 * 0.1).min(0.2);
        score += s;
        signals.push(ObfuscationSignal {
            kind: "function_constructor".into(),
            description: format!("{} Function() constructor calls", function_constructor),
            weight: s,
        });
    }

    // Signal 2: Hex/unicode escape sequences in strings
    let hex_escapes = content.matches("\\x").count();
    let unicode_escapes = content.matches("\\u").count();
    let total_escapes = hex_escapes + unicode_escapes;
    if total_escapes > 20 {
        let s = ((total_escapes as f64 / 100.0) * 0.2).min(0.3);
        score += s;
        signals.push(ObfuscationSignal {
            kind: "string_encoding".into(),
            description: format!(
                "{} hex escapes + {} unicode escapes — strings may be deliberately encoded",
                hex_escapes, unicode_escapes
            ),
            weight: s,
        });
    }

    // Signal 3: Very long single lines (extreme minification / packing)
    let max_line_len = content.lines().map(|l| l.len()).max().unwrap_or(0);
    if max_line_len > 50000 {
        let s = 0.1;
        score += s;
        signals.push(ObfuscationSignal {
            kind: "extreme_line_length".into(),
            description: format!(
                "Maximum line length: {} chars — potential code packing",
                max_line_len
            ),
            weight: s,
        });
    }

    // Signal 4: High entropy overall
    let entropy = shannon_entropy(content.as_bytes());
    if entropy > 6.0 {
        let s = ((entropy - 6.0) * 0.15).min(0.3);
        score += s;
        signals.push(ObfuscationSignal {
            kind: "high_entropy".into(),
            description: format!(
                "Overall entropy: {:.2} bits/byte (normal JS: 4.5-5.5, suspicious: >6.0)",
                entropy
            ),
            weight: s,
        });
    }

    // Signal 5: Base64-encoded blocks
    let base64_re =
        regex::Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap();
    let base64_count = base64_re.find_iter(content).count();
    if base64_count > 3 {
        let s = (base64_count as f64 * 0.05).min(0.2);
        score += s;
        signals.push(ObfuscationSignal {
            kind: "base64_blocks".into(),
            description: format!("{} large Base64-encoded blocks detected", base64_count),
            weight: s,
        });
    }

    // Signal 6: String array + index access pattern (common obfuscator output)
    let string_array_pattern = content.contains("split(\"|\")")
        || content.contains("split('|')")
        || (content.matches("[\"").count() > 50 && content.matches("](").count() > 30);
    if string_array_pattern {
        score += 0.2;
        signals.push(ObfuscationSignal {
            kind: "string_array_obfuscation".into(),
            description: "String array rotation pattern detected — common obfuscator output".into(),
            weight: 0.2,
        });
    }

    ObfuscationReport {
        score: score.min(1.0),
        entropy,
        signals,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationReport {
    /// 0.0 = clean, 1.0 = heavily obfuscated
    pub score: f64,
    /// Shannon entropy (bits per byte)
    pub entropy: f64,
    /// Individual obfuscation signals detected
    pub signals: Vec<ObfuscationSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationSignal {
    pub kind: String,
    pub description: String,
    pub weight: f64,
}

// ─── Font and CSS Extraction ───────────────────────────────────────

/// Extract font-family declarations from CSS/HTML content.
pub fn extract_font_references(content: &str) -> Vec<FontReference> {
    let mut refs = Vec::new();

    // Match font-family declarations in CSS
    let font_family_re =
        regex::Regex::new(r#"font-family\s*:\s*([^;}{]+)"#).unwrap();
    for cap in font_family_re.captures_iter(content) {
        if let Some(families) = cap.get(1) {
            let raw = families.as_str().trim();
            // Split by comma and clean each family name
            for family in raw.split(',') {
                let name = family
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim();
                if !name.is_empty() && !is_generic_font(name) {
                    let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
                    refs.push(FontReference {
                        name: name.to_string(),
                        context: FontContext::CssDeclaration,
                        byte_offset: offset,
                    });
                }
            }
        }
    }

    // Match @font-face declarations
    let font_face_re =
        regex::Regex::new(r#"@font-face\s*\{[^}]*font-family\s*:\s*['"]?([^'";}{]+)"#).unwrap();
    for cap in font_face_re.captures_iter(content) {
        if let Some(name) = cap.get(1) {
            let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
            refs.push(FontReference {
                name: name.as_str().trim().to_string(),
                context: FontContext::FontFaceDeclaration,
                byte_offset: offset,
            });
        }
    }

    // Match font file references (.woff, .woff2, .ttf, .otf, .eot)
    let font_file_re =
        regex::Regex::new(r#"url\s*\(\s*['"]?([^'")\s]+\.(?:woff2?|ttf|otf|eot))"#).unwrap();
    for cap in font_file_re.captures_iter(content) {
        if let Some(url) = cap.get(1) {
            let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
            refs.push(FontReference {
                name: url.as_str().to_string(),
                context: FontContext::FontFile,
                byte_offset: offset,
            });
        }
    }

    refs
}

fn is_generic_font(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "serif"
            | "sans-serif"
            | "monospace"
            | "cursive"
            | "fantasy"
            | "system-ui"
            | "ui-serif"
            | "ui-sans-serif"
            | "ui-monospace"
            | "ui-rounded"
            | "inherit"
            | "initial"
            | "unset"
            | "revert"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontReference {
    pub name: String,
    pub context: FontContext,
    pub byte_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FontContext {
    CssDeclaration,
    FontFaceDeclaration,
    FontFile,
}

// ─── Network Endpoint Extraction ───────────────────────────────────

/// Extract URLs and network endpoints from code.
pub fn extract_endpoints(content: &str) -> Vec<EndpointReference> {
    let mut endpoints = Vec::new();

    let url_re = regex::Regex::new(
        r#"(?:["'`])(https?://[^\s"'`<>]{5,200})(?:["'`])"#
    ).unwrap();

    for cap in url_re.captures_iter(content) {
        if let Some(url) = cap.get(1) {
            let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
            endpoints.push(EndpointReference {
                url: url.as_str().to_string(),
                byte_offset: offset,
            });
        }
    }

    endpoints
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReference {
    pub url: String,
    pub byte_offset: usize,
}

// ─── Minifier Identification ───────────────────────────────────────

/// Attempt to identify which minifier/bundler produced the code.
pub fn identify_minifier(content: &str) -> Option<MinifierInfo> {
    // Terser / UglifyJS: typically produces `!function(` wrapping, short vars
    if content.contains("__webpack_require__") {
        return Some(MinifierInfo {
            name: "Webpack + Terser".into(),
            confidence: 0.85,
            evidence: "__webpack_require__ module system".into(),
        });
    }

    // Closure Compiler: uses `$jscomp` namespace
    if content.contains("$jscomp.") || content.contains("$jscomp=") {
        return Some(MinifierInfo {
            name: "Google Closure Compiler".into(),
            confidence: 0.90,
            evidence: "$jscomp namespace".into(),
        });
    }

    // esbuild: uses `__toESM` / `__toCommonJS` / `__name`
    if content.contains("__toESM") || content.contains("__toCommonJS") {
        return Some(MinifierInfo {
            name: "esbuild".into(),
            confidence: 0.85,
            evidence: "__toESM/__toCommonJS wrappers".into(),
        });
    }

    // Rollup: `Object.defineProperty(exports, '__esModule'` pattern
    if content.contains("Object.defineProperty(exports,\"__esModule\"")
        || content.contains("Object.defineProperty(exports, '__esModule'")
    {
        return Some(MinifierInfo {
            name: "Rollup".into(),
            confidence: 0.70,
            evidence: "__esModule export marker".into(),
        });
    }

    // Browserify: `(function e(t,n,r){` typical wrapper
    if content.starts_with("(function e(t,n,r){")
        || content.contains("Cannot find module")
    {
        return Some(MinifierInfo {
            name: "Browserify".into(),
            confidence: 0.70,
            evidence: "Browserify module wrapper pattern".into(),
        });
    }

    // UglifyJS standalone: `!function(` or `(function(` with single-letter vars
    if content.starts_with("!function(") || content.starts_with("(function(") {
        return Some(MinifierInfo {
            name: "UglifyJS/Terser (standalone)".into(),
            confidence: 0.50,
            evidence: "IIFE wrapper with minified variables".into(),
        });
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MinifierInfo {
    pub name: String,
    pub confidence: f64,
    pub evidence: String,
}

// ─── Source Map Detection ──────────────────────────────────────────

/// Check for source map references (inline or external).
pub fn detect_source_maps(content: &str) -> Vec<SourceMapRef> {
    let mut refs = Vec::new();

    // External source map reference
    let external_re =
        regex::Regex::new(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)").unwrap();
    for cap in external_re.captures_iter(content) {
        if let Some(url) = cap.get(1) {
            let url_str = url.as_str();
            if url_str.starts_with("data:") {
                refs.push(SourceMapRef {
                    kind: SourceMapKind::Inline,
                    reference: url_str[..url_str.len().min(100)].to_string(),
                });
            } else {
                refs.push(SourceMapRef {
                    kind: SourceMapKind::External,
                    reference: url_str.to_string(),
                });
            }
        }
    }

    refs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapRef {
    pub kind: SourceMapKind,
    pub reference: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceMapKind {
    Inline,
    External,
}

// ─── Complete File Analysis ────────────────────────────────────────

/// Run all analysis techniques on a file's content.
/// This provides the "impossible to escape" layer — multiple independent
/// detection channels that chain together.
pub fn full_analysis(content: &str) -> FileAnalysis {
    FileAnalysis {
        entropy: shannon_entropy(content.as_bytes()),
        obfuscation: obfuscation_score(content),
        font_references: extract_font_references(content),
        endpoints: extract_endpoints(content),
        minifier: identify_minifier(content),
        source_maps: detect_source_maps(content),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAnalysis {
    pub entropy: f64,
    pub obfuscation: ObfuscationReport,
    pub font_references: Vec<FontReference>,
    pub endpoints: Vec<EndpointReference>,
    pub minifier: Option<MinifierInfo>,
    pub source_maps: Vec<SourceMapRef>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_normal_text() {
        let e = shannon_entropy(b"hello world this is normal text");
        assert!(e > 3.0 && e < 5.0, "Normal text entropy: {}", e);
    }

    #[test]
    fn test_entropy_random_bytes() {
        let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.5, "Random bytes entropy: {}", e);
    }

    #[test]
    fn test_obfuscation_clean_code() {
        let code = "function greet(name) { return 'Hello ' + name; }";
        let report = obfuscation_score(code);
        assert!(report.score < 0.2, "Clean code score: {}", report.score);
    }

    #[test]
    fn test_obfuscation_eval_heavy() {
        let code = "eval(atob('aGVsbG8=')); eval('console.log(1)'); eval(x); eval(y);";
        let report = obfuscation_score(code);
        assert!(report.score > 0.1, "Eval-heavy score: {}", report.score);
    }

    #[test]
    fn test_font_extraction() {
        let css = r#"body { font-family: 'Proxima Nova', Arial, sans-serif; }"#;
        let refs = extract_font_references(css);
        assert!(refs.iter().any(|r| r.name == "Proxima Nova"));
        assert!(refs.iter().any(|r| r.name == "Arial"));
        assert!(!refs.iter().any(|r| r.name == "sans-serif")); // generic filtered
    }

    #[test]
    fn test_font_face_extraction() {
        let css = r#"@font-face { font-family: 'Gotham'; src: url('gotham.woff2'); }"#;
        let refs = extract_font_references(css);
        assert!(refs.iter().any(|r| r.name == "Gotham" && r.context == FontContext::FontFaceDeclaration));
        assert!(refs.iter().any(|r| r.name.contains("gotham.woff2") && r.context == FontContext::FontFile));
    }

    #[test]
    fn test_minifier_webpack() {
        let code = "var x = __webpack_require__(123);";
        let info = identify_minifier(code);
        assert!(info.is_some());
        assert!(info.unwrap().name.contains("Webpack"));
    }

    #[test]
    fn test_minifier_closure() {
        let code = "var $jscomp={asyncExecutePromiseGeneratorFunction:function(a){return new Promise(function(b){});}};";
        let info = identify_minifier(code);
        assert!(info.is_some());
        assert!(info.unwrap().name.contains("Closure"));
    }

    #[test]
    fn test_endpoint_extraction() {
        let code = r#"fetch("https://api.securly.com/v2/filter"); var x = 'https://cdn.example.com/lib.js';"#;
        let endpoints = extract_endpoints(code);
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().any(|e| e.url.contains("securly.com")));
    }
}
