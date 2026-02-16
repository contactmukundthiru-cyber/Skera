//! Advanced De-obfuscation — control flow flattening, opaque predicates,
//! dead code elimination, and self-defending code neutralization.
//!
//! This extends the base deobfuscation pipeline with techniques that
//! defeat commercial-grade obfuscators (javascript-obfuscator "high",
//! JScrambler, Jsfuck, etc.)
//!
//! ## Techniques
//!
//! ### Control Flow Flattening Reversal
//! Obfuscators transform structured code into flat switch/case state machines:
//! ```js
//! while(true) { switch(state) { case "0": x=1; state="3"; break; ... } }
//! ```
//! We detect this pattern, trace the state transitions, and reconstruct
//! the original control flow.
//!
//! ### Opaque Predicate Elimination
//! Obfuscators insert conditions that always evaluate to true/false but
//! are hard to prove statically: `if((x*x+x)%2===0)` (always true).
//! We identify common opaque predicate patterns and simplify them.
//!
//! ### Dead Code Removal
//! After flattening reversal and predicate elimination, unreachable code
//! paths can be identified and removed.
//!
//! ### Self-Defending Code Detection
//! Some obfuscators inject integrity checks that crash if the code is
//! modified. We detect and neutralize these traps.

use regex::Regex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

// ─── Result Types ──────────────────────────────────────────────────

/// What kind of advanced transformation was applied
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvancedTransformKind {
    /// Recovered flattened control flow back to structured code
    ControlFlowRecovery,
    /// Eliminated an opaque predicate (always-true or always-false condition)
    OpaquePredicateElimination,
    /// Removed dead/unreachable code
    DeadCodeRemoval,
    /// Neutralized a self-defending code trap
    SelfDefendingRemoval,
    /// Inlined a proxy function (single-operation wrapper)
    ProxyFunctionInlining,
    /// Simplified comma expression sequences
    CommaExpressionSimplification,
}

/// A single advanced de-obfuscation transformation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTransformation {
    /// What kind of transformation
    pub kind: AdvancedTransformKind,
    /// Human-readable description
    pub description: String,
    /// How many instances were resolved
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedDeobfuscationResult {
    pub cleaned_content: String,
    pub transformations: Vec<AdvancedTransformation>,
    pub flattened_blocks_recovered: usize,
    pub opaque_predicates_eliminated: usize,
    pub dead_code_lines_removed: usize,
    pub self_defending_traps_found: usize,
    pub proxy_functions_inlined: usize,
}

// ─── Patterns ──────────────────────────────────────────────────────

// Control flow flattening: while(true) { switch(state) { case ... } }
static CFF_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?s)while\s*\(\s*(?:true|!!\[\]|!0|1)\s*\)\s*\{\s*switch\s*\(\s*(\w+)\s*\)").unwrap()
});

// State assignment: state = "3"; or _0x1234 = "0x5";
static STATE_ASSIGN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(\w+)\s*=\s*['"]([^'"]+)['"];\s*(?:break|continue)"#).unwrap()
});

// Case label: case "0": or case 0x3:
static CASE_LABEL: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"case\s+(?:['"]([^'"]+)['"]|(\d+)|0x([0-9a-fA-F]+))\s*:"#).unwrap()
});

// Opaque predicates — always true
static OPAQUE_TRUE: Lazy<Vec<Regex>> = Lazy::new(|| vec![
    // (x * x + x) % 2 === 0  — always true for integers
    Regex::new(r"\(\s*\w+\s*\*\s*\w+\s*\+\s*\w+\s*\)\s*%\s*2\s*===?\s*0").unwrap(),
    // typeof undefined === "undefined"
    Regex::new(r#"typeof\s+undefined\s*===?\s*['"]undefined['"]"#).unwrap(),
    // void 0 === undefined
    Regex::new(r"void\s+0\s*===?\s*undefined").unwrap(),
    // ![] === false   (always true)
    Regex::new(r"!\[\]\s*===?\s*false").unwrap(),
    // !![] === true   (always true)
    Regex::new(r"!!\[\]\s*===?\s*true").unwrap(),
    // NaN !== NaN (always true)
    Regex::new(r"NaN\s*!==?\s*NaN").unwrap(),
    // (x|0) === x  (always true for 32-bit ints)
    Regex::new(r"\(\s*\w+\s*\|\s*0\s*\)\s*===?\s*\w+").unwrap(),
    // Infinity === Infinity
    Regex::new(r"Infinity\s*===?\s*Infinity").unwrap(),
]);

// Opaque predicates — always false
static OPAQUE_FALSE: Lazy<Vec<Regex>> = Lazy::new(|| vec![
    // typeof undefined === "number"
    Regex::new(r#"typeof\s+undefined\s*===?\s*['"]number['"]"#).unwrap(),
    // NaN === NaN (always false)
    Regex::new(r"NaN\s*===?\s*NaN").unwrap(),
    // [] === []  (always false — reference comparison)
    Regex::new(r"\[\]\s*===?\s*\[\]").unwrap(),
    // false && anything
    Regex::new(r"false\s*&&").unwrap(),
]);

// Self-defending patterns
static SELF_DEFEND: Lazy<Vec<Regex>> = Lazy::new(|| vec![
    // Function.toString checking (detects if code was modified)
    Regex::new(r"\.toString\(\)\.search\(").unwrap(),
    // debugger trap loops
    Regex::new(r"(?:setInterval|setTimeout)\s*\(\s*function\s*\(\)\s*\{\s*debugger").unwrap(),
    // Console override — use r# to avoid char literal issues with quotes
    Regex::new(r#"console\s*\[\s*['"]\w+['"]\s*\]\s*=\s*function"#).unwrap(),
    // Anti-debugging timing
    Regex::new(r"(?:Date\.now|performance\.now)\s*\(\s*\).*(?:Date\.now|performance\.now)\s*\(\s*\).*>\s*\d{2,}").unwrap(),
]);

// Proxy function patterns: function _0x1234(a,b) { return a + b; }
// Backreferences (\2, \3) are not supported by the Rust `regex` crate.
// Instead we capture the structure and verify parameter reuse in code.
static PROXY_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"function\s+(_0x[0-9a-fA-F]+)\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*\{\s*return\s+\w+\s*([+\-*/%&|^]|===?|!==?|<<|>>|>>>)\s*\w+\s*;\s*\}").unwrap()
});

// ─── The Engine ────────────────────────────────────────────────────

pub struct AdvancedDeobfuscator;

impl AdvancedDeobfuscator {
    /// Run the advanced de-obfuscation pipeline
    pub fn deobfuscate(content: &str) -> AdvancedDeobfuscationResult {
        let mut code = content.to_string();
        let mut transformations = Vec::new();
        let mut flattened_blocks = 0;
        let mut opaque_eliminated = 0;
        let mut dead_removed = 0;
        let mut self_defend_found = 0;
        let mut proxy_inlined = 0;

        // Pass 1: Detect and neutralize self-defending code
        let (new_code, sd_count) = Self::neutralize_self_defending(&code);
        if sd_count > 0 {
            self_defend_found = sd_count;
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::SelfDefendingRemoval,
                description: format!("Neutralized {} self-defending code traps", sd_count),
                count: sd_count,
            });
            code = new_code;
        }

        // Pass 2: Inline proxy functions
        let (new_code, pi_count) = Self::inline_proxy_functions(&code);
        if pi_count > 0 {
            proxy_inlined = pi_count;
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::ProxyFunctionInlining,
                description: format!("Inlined {} proxy functions", pi_count),
                count: pi_count,
            });
            code = new_code;
        }

        // Pass 3: Eliminate opaque predicates
        let (new_code, op_count) = Self::eliminate_opaque_predicates(&code);
        if op_count > 0 {
            opaque_eliminated = op_count;
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::OpaquePredicateElimination,
                description: format!("Eliminated {} opaque predicates", op_count),
                count: op_count,
            });
            code = new_code;
        }

        // Pass 4: Reverse control flow flattening
        let (new_code, cff_count) = Self::reverse_control_flow_flattening(&code);
        if cff_count > 0 {
            flattened_blocks = cff_count;
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::ControlFlowRecovery,
                description: format!("Recovered {} flattened control flow blocks", cff_count),
                count: cff_count,
            });
            code = new_code;
        }

        // Pass 5: Remove dead code after predicate elimination
        let (new_code, dc_count) = Self::remove_dead_code(&code);
        if dc_count > 0 {
            dead_removed = dc_count;
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::DeadCodeRemoval,
                description: format!("Removed {} lines of dead code", dc_count),
                count: dc_count,
            });
            code = new_code;
        }

        // Pass 6: Simplify comma expressions
        let (new_code, ce_count) = Self::simplify_comma_expressions(&code);
        if ce_count > 0 {
            transformations.push(AdvancedTransformation {
                kind: AdvancedTransformKind::CommaExpressionSimplification,
                description: format!("Simplified {} comma expressions", ce_count),
                count: ce_count,
            });
            code = new_code;
        }

        AdvancedDeobfuscationResult {
            cleaned_content: code,
            transformations,
            flattened_blocks_recovered: flattened_blocks,
            opaque_predicates_eliminated: opaque_eliminated,
            dead_code_lines_removed: dead_removed,
            self_defending_traps_found: self_defend_found,
            proxy_functions_inlined: proxy_inlined,
        }
    }

    // ── Control flow flattening reversal ────────────────────────────

    fn reverse_control_flow_flattening(content: &str) -> (String, usize) {
        let mut code = content.to_string();
        let mut recovered = 0;

        while let Some(cff_match) = CFF_PATTERN.find(&code) {
            let start = cff_match.start();
            let state_var = CFF_PATTERN.captures(&code[start..])
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string());

            let state_var = match state_var {
                Some(v) => v,
                None => break,
            };

            let block_start = match code[start..].find('{') {
                Some(pos) => start + pos,
                None => break,
            };

            let block_end = match find_matching_brace(&code, block_start) {
                Some(pos) => pos,
                None => break,
            };

            let switch_block = &code[block_start..=block_end];

            // Extract case blocks and state transitions
            let mut cases: Vec<(String, String, Option<String>)> = Vec::new();

            for case_cap in CASE_LABEL.captures_iter(switch_block) {
                let case_label = case_cap.get(1)
                    .or(case_cap.get(2))
                    .or(case_cap.get(3))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                let case_pos = case_cap.get(0).unwrap().end();
                let remaining = &switch_block[case_pos..];

                let body_end = remaining.find("case ")
                    .or_else(|| remaining.find("default:"))
                    .or_else(|| remaining.rfind('}'))
                    .unwrap_or(remaining.len());

                let body = remaining[..body_end].trim().to_string();

                let next_state = STATE_ASSIGN.captures(&body)
                    .filter(|c| c.get(1).map(|m| m.as_str()) == Some(&state_var))
                    .and_then(|c| c.get(2).map(|m| m.as_str().to_string()));

                let cleaned_body = body
                    .lines()
                    .filter(|l| {
                        let t = l.trim();
                        !t.starts_with("break") && !t.starts_with("continue")
                            && !t.contains(&format!("{} = ", state_var))
                    })
                    .collect::<Vec<&str>>()
                    .join("\n");

                cases.push((case_label, cleaned_body, next_state));
            }

            if cases.is_empty() { break; }

            // Find initial state
            let init_search = &code[..start];
            let init_re = Regex::new(&format!(
                r#"{}\s*=\s*['"]([^'"]+)['"]"#,
                regex::escape(&state_var)
            )).ok();

            let initial_state = init_re.and_then(|re| {
                re.captures_iter(init_search).last()
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            });

            // Linearize
            let mut linearized = String::new();
            let mut visited = std::collections::HashSet::new();

            if let Some(mut current_state) = initial_state {
                while !visited.contains(&current_state) {
                    visited.insert(current_state.clone());

                    if let Some((_, body, next)) = cases.iter()
                        .find(|(label, _, _)| *label == current_state)
                    {
                        if !body.trim().is_empty() {
                            linearized.push_str(body.trim());
                            linearized.push('\n');
                        }

                        match next {
                            Some(ns) => current_state = ns.clone(),
                            None => break,
                        }
                    } else {
                        break;
                    }
                }
            }

            if !linearized.is_empty() {
                let replacement = format!("/* recovered control flow */\n{}", linearized);
                let outer_end = (block_end + 1).min(code.len());

                let end_pos = if outer_end < code.len() && code.as_bytes().get(outer_end) == Some(&b'}') {
                    outer_end + 1
                } else {
                    outer_end
                };

                code = format!("{}{}{}", &code[..start], replacement, &code[end_pos..]);
                recovered += 1;
            } else {
                break;
            }
        }

        (code, recovered)
    }

    // ── Opaque predicate elimination ────────────────────────────────

    fn eliminate_opaque_predicates(content: &str) -> (String, usize) {
        let mut code = content.to_string();
        let mut count = 0;

        for pattern in OPAQUE_TRUE.iter() {
            let new_code = pattern.replace_all(&code, "true").to_string();
            if new_code != code {
                count += 1;
                code = new_code;
            }
        }

        for pattern in OPAQUE_FALSE.iter() {
            let new_code = pattern.replace_all(&code, "false").to_string();
            if new_code != code {
                count += 1;
                code = new_code;
            }
        }

        let if_true = Regex::new(r"if\s*\(\s*true\s*\)\s*\{").unwrap();
        let new_code = if_true.replace_all(&code, "{ /* always-true path */").to_string();
        if new_code != code { count += 1; code = new_code; }

        let if_false = Regex::new(r"(?s)if\s*\(\s*false\s*\)\s*\{[^}]*\}").unwrap();
        let new_code = if_false.replace_all(&code, "/* dead: always-false path removed */").to_string();
        if new_code != code { count += 1; code = new_code; }

        (code, count)
    }

    // ── Dead code removal ───────────────────────────────────────────

    fn remove_dead_code(content: &str) -> (String, usize) {
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut removed = 0;

        let mut i = 0;
        while i < lines.len() {
            let trimmed = lines[i].trim();
            if trimmed == "function(){};" || trimmed == "()=>{}" || trimmed == "function(){}" {
                lines[i] = "/* dead function */".to_string();
                removed += 1;
            }
            i += 1;
        }

        let mut after_terminator = false;
        let mut depth = 0i32;
        let mut start_depth = 0i32;

        for i in 0..lines.len() {
            let trimmed = lines[i].trim().to_string();

            for ch in trimmed.chars() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if after_terminator && depth <= start_depth {
                            after_terminator = false;
                        }
                    }
                    _ => {}
                }
            }

            if after_terminator && depth > start_depth {
                if !trimmed.is_empty() && !trimmed.starts_with("//") && !trimmed.starts_with("/*") {
                    lines[i] = format!("/* unreachable: {} */", trimmed);
                    removed += 1;
                }
            }

            if (trimmed.starts_with("return ") || trimmed.starts_with("throw ")
                || trimmed == "return;" || trimmed == "break;" || trimmed == "continue;")
                && !trimmed.contains("if") && !trimmed.contains("?")
            {
                after_terminator = true;
                start_depth = depth;
            }

            if trimmed.contains('}') && depth <= start_depth {
                after_terminator = false;
            }
        }

        let result = lines.join("\n");
        (result, removed)
    }

    // ── Self-defending code neutralization ──────────────────────────

    fn neutralize_self_defending(content: &str) -> (String, usize) {
        let mut code = content.to_string();
        let mut count = 0;

        for pattern in SELF_DEFEND.iter() {
            if pattern.is_match(&code) {
                count += 1;
            }
        }

        // Remove debugger traps
        let debugger_trap = Regex::new(
            r"(?s)(?:setInterval|setTimeout)\s*\(\s*function\s*\(\)\s*\{\s*debugger\s*;?\s*\}\s*,\s*\d+\s*\)"
        ).unwrap();
        code = debugger_trap.replace_all(&code, "/* debugger trap neutralized */").to_string();

        // Remove console overrides
        let console_override = Regex::new(
            r#"console\s*\[\s*['"]\w+['"]\s*\]\s*=\s*function\s*\([^)]*\)\s*\{[^}]*\}"#
        ).unwrap();
        code = console_override.replace_all(&code, "/* console override neutralized */").to_string();

        (code, count)
    }

    // ── Proxy function inlining ─────────────────────────────────────

    fn inline_proxy_functions(content: &str) -> (String, usize) {
        let mut code = content.to_string();
        let mut count = 0;

        let proxies: Vec<(String, String)> = PROXY_FUNC.captures_iter(&code)
            .filter_map(|cap| {
                let func_name = cap.get(1)?.as_str().to_string();
                let _param_a = cap.get(2)?.as_str();
                let _param_b = cap.get(3)?.as_str();
                let operator = cap.get(4)?.as_str();
                Some((func_name, operator.to_string()))
            })
            .collect();

        for (func_name, operator) in &proxies {
            let call_re = Regex::new(&format!(
                r"{}\s*\(\s*([^,)]+)\s*,\s*([^)]+)\s*\)",
                regex::escape(func_name)
            )).unwrap();

            let replacement = format!("($1 {} $2)", operator);
            let new_code = call_re.replace_all(&code, replacement.as_str()).to_string();
            if new_code != code {
                count += 1;
                code = new_code;
            }
        }

        // Remove the proxy function definitions
        for (func_name, _) in &proxies {
            let pattern_str = format!(
                r"function\s+{}\s*\([^)]*\)\s*\{{[^}}]*\}}\s*;?",
                regex::escape(func_name)
            );
            if let Ok(re) = Regex::new(&pattern_str) {
                code = re.replace_all(&code, "").to_string();
            }
        }

        (code, count)
    }

    // ── Comma expression simplification ─────────────────────────────

    fn simplify_comma_expressions(content: &str) -> (String, usize) {
        let mut code = content.to_string();
        let mut count = 0;

        let comma_seq = Regex::new(r"\((\w+\s*=\s*[^,]+(?:,\s*\w+\s*=\s*[^,]+)*),\s*(\w+)\s*\)").unwrap();

        for cap in comma_seq.captures_iter(&code.clone()) {
            let full = cap.get(0).unwrap().as_str();
            let assignments = cap.get(1).unwrap().as_str();
            let result_var = cap.get(2).unwrap().as_str();

            let expanded: Vec<&str> = assignments.split(',')
                .map(|s| s.trim())
                .collect();

            if expanded.len() >= 2 {
                let mut replacement = String::new();
                for stmt in &expanded {
                    replacement.push_str(stmt);
                    replacement.push_str(";\n");
                }
                replacement.push_str(result_var);

                code = code.replace(full, &replacement);
                count += 1;
            }
        }

        (code, count)
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

fn find_matching_brace(code: &str, open_pos: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    if bytes.get(open_pos) != Some(&b'{') { return None; }

    let mut depth = 0;
    let mut in_string = false;
    let mut string_char = b' ';

    for i in open_pos..code.len() {
        let ch = bytes[i];

        if in_string {
            if ch == string_char && (i == 0 || bytes[i - 1] != b'\\') {
                in_string = false;
            }
            continue;
        }

        match ch {
            b'"' | b'\'' | b'`' => {
                in_string = true;
                string_char = ch;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_predicate_true() {
        let code = r#"if ((x * x + x) % 2 === 0) { doSomething(); }"#;
        let (result, count) = AdvancedDeobfuscator::eliminate_opaque_predicates(code);
        assert!(count > 0);
        assert!(result.contains("true"));
    }

    #[test]
    fn test_opaque_predicate_typeof() {
        let code = r#"if (typeof undefined === "undefined") { realCode(); }"#;
        let (result, count) = AdvancedDeobfuscator::eliminate_opaque_predicates(code);
        assert!(count > 0);
        assert!(result.contains("true"));
    }

    #[test]
    fn test_self_defending_detection() {
        let code = r#"setInterval(function() { debugger }, 100)"#;
        let (result, count) = AdvancedDeobfuscator::neutralize_self_defending(code);
        assert!(count > 0);
        assert!(result.contains("neutralized"));
    }

    #[test]
    fn test_find_matching_brace() {
        assert_eq!(find_matching_brace("{ inner }", 0), Some(8));
        assert_eq!(find_matching_brace("{ { nested } }", 0), Some(13));
    }

    #[test]
    fn test_full_pipeline() {
        let obfuscated = r#"
            setInterval(function() { debugger }, 500);
            if (typeof undefined === "undefined") {
                if ((x * x + x) % 2 === 0) {
                    console.log("real code");
                }
            }
        "#;

        let result = AdvancedDeobfuscator::deobfuscate(obfuscated);
        assert!(result.self_defending_traps_found > 0);
        assert!(result.opaque_predicates_eliminated > 0);
    }
}
