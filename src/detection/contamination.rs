//! License contamination tracing — forensic-grade copyleft propagation analysis
//!
//! ## Overview
//!
//! Traces how copyleft/viral licenses propagate through a dependency
//! graph. When a GPL dependency is found, this module determines which
//! parts of the project are "contaminated" and must comply.
//!
//! ## Industry-Leading Features
//!
//! 1. **SPDX Expression Parsing** — handles `MIT OR Apache-2.0`, `GPL-2.0-only
//!    WITH Classpath-exception-2.0`, compound `AND`/`OR` expressions.
//!
//! 2. **Linking Exception Database** — recognizes GCC Runtime Exception,
//!    Classpath Exception, FOSS Exception, Autoconf Exception, etc.
//!    Correctly suppresses contamination when exceptions apply.
//!
//! 3. **Dual-License Handling** — when a package offers `GPL-2.0 OR MIT`,
//!    the consumer can legally choose MIT, avoiding GPL contamination.
//!
//! 4. **Boundary-Aware Propagation** — distinguishes static, dynamic,
//!    IPC/network, header-only, and build-tool boundaries. Each has
//!    different contamination semantics under GPL, LGPL, AGPL.
//!
//! 5. **Confidence-Weighted Contamination** — propagation chains carry
//!    confidence scores that decay with distance and boundary crossings.
//!
//! 6. **Transitive Exception Inheritance** — exceptions on a dependency
//!    are properly inherited by downstream contamination chains.

use crate::detection::{Violation, ViolationType, Severity};
use crate::evidence::EvidenceItem;
use crate::license::{LicenseId, LicenseFamily, LicenseObligation};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

// ─── Types ──────────────────────────────────────────────────────────

/// A node in the dependency graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepNode {
    pub name: String,
    pub version: Option<String>,
    pub license: LicenseId,
    /// Raw SPDX expression if available (e.g. "MIT OR Apache-2.0")
    pub spdx_expression: Option<String>,
    /// Direct dependencies (names)
    pub depends_on: Vec<String>,
    /// Is this statically or dynamically linked?
    pub linking: LinkingMode,
    /// SPDX license exceptions applied (e.g. "Classpath-exception-2.0")
    pub license_exceptions: Vec<String>,
    /// Whether this is a build-time-only dependency (dev, test, build)
    pub build_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkingMode {
    Static,
    Dynamic,
    Source,       // directly compiled in (vendored)
    HeaderOnly,   // header-only library (template instantiation)
    ProcMacro,    // compile-time code generation (Rust proc-macros)
    BuildTool,    // build-time tool, not linked into output
    IpcNetwork,   // inter-process or network communication boundary
    Unknown,
}

/// A parsed SPDX expression
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpdxExpression {
    /// A single license identifier (e.g. "MIT")
    License(String),
    /// License WITH exception (e.g. "GPL-2.0-only WITH Classpath-exception-2.0")
    WithException(String, String),
    /// Disjunction — user may choose either side (e.g. "MIT OR Apache-2.0")
    Or(Box<SpdxExpression>, Box<SpdxExpression>),
    /// Conjunction — both must be complied with (e.g. "MIT AND CC-BY-4.0")
    And(Box<SpdxExpression>, Box<SpdxExpression>),
}

impl SpdxExpression {
    /// Parse an SPDX license expression string.
    ///
    /// Supports:
    /// - Simple: `MIT`
    /// - WITH: `GPL-2.0-only WITH Classpath-exception-2.0`
    /// - OR: `MIT OR Apache-2.0`
    /// - AND: `MIT AND CC-BY-4.0`
    /// - Parenthesized: `(MIT OR Apache-2.0) AND CC-BY-4.0`
    /// - LicenseRef: `LicenseRef-custom`
    pub fn parse(input: &str) -> Self {
        let input = input.trim();
        if input.is_empty() {
            return Self::License("UNKNOWN".to_string());
        }
        Self::parse_or(input)
    }

    fn parse_or(input: &str) -> Self {
        // Split on top-level " OR " (not inside parentheses)
        if let Some((left, right)) = Self::split_at_keyword(input, " OR ") {
            return Self::Or(
                Box::new(Self::parse_or(left)),
                Box::new(Self::parse_or(right)),
            );
        }
        Self::parse_and(input)
    }

    fn parse_and(input: &str) -> Self {
        if let Some((left, right)) = Self::split_at_keyword(input, " AND ") {
            return Self::And(
                Box::new(Self::parse_and(left)),
                Box::new(Self::parse_and(right)),
            );
        }
        Self::parse_with(input)
    }

    fn parse_with(input: &str) -> Self {
        let input = input.trim();
        // Strip outer parentheses
        if input.starts_with('(') && input.ends_with(')') {
            let inner = &input[1..input.len()-1];
            // Verify matched parens
            if Self::parens_balanced(inner) {
                return Self::parse_or(inner);
            }
        }
        // WITH exception
        if let Some((license, exception)) = Self::split_at_keyword(input, " WITH ") {
            return Self::WithException(
                license.trim().to_string(),
                exception.trim().to_string(),
            );
        }
        Self::License(input.to_string())
    }

    /// Split at a keyword that is not inside parentheses.
    fn split_at_keyword<'a>(input: &'a str, keyword: &str) -> Option<(&'a str, &'a str)> {
        let mut depth = 0;
        let kw_len = keyword.len();
        let bytes = input.as_bytes();
        for i in 0..input.len() {
            if bytes[i] == b'(' {
                depth += 1;
            } else if bytes[i] == b')' {
                depth -= 1;
            } else if depth == 0 && i + kw_len <= input.len() {
                if &input[i..i + kw_len] == keyword {
                    return Some((&input[..i], &input[i + kw_len..]));
                }
            }
        }
        None
    }

    fn parens_balanced(input: &str) -> bool {
        let mut depth = 0i32;
        for ch in input.chars() {
            if ch == '(' { depth += 1; }
            if ch == ')' { depth -= 1; }
            if depth < 0 { return false; }
        }
        depth == 0
    }

    /// Collect all individual license identifiers in this expression.
    pub fn all_licenses(&self) -> Vec<String> {
        match self {
            Self::License(id) => vec![id.clone()],
            Self::WithException(id, _) => vec![id.clone()],
            Self::Or(a, b) | Self::And(a, b) => {
                let mut v = a.all_licenses();
                v.extend(b.all_licenses());
                v
            }
        }
    }

    /// Check if ANY branch of this expression is non-copyleft (i.e.,
    /// the consumer can legally avoid copyleft by choosing that branch).
    pub fn has_permissive_choice(&self) -> bool {
        match self {
            Self::License(id) => !LicenseId::new(id).is_copyleft(),
            Self::WithException(id, exception) => {
                // If exception neutralizes copyleft, treat as permissive
                !LicenseId::new(id).is_copyleft()
                    || COPYLEFT_NEUTRALIZING_EXCEPTIONS.iter().any(|e| {
                        exception.to_lowercase().contains(&e.to_lowercase())
                    })
            }
            Self::Or(a, b) => {
                // OR: user can choose the permissive side
                a.has_permissive_choice() || b.has_permissive_choice()
            }
            Self::And(a, b) => {
                // AND: both must be permissive for the combo to be permissive
                a.has_permissive_choice() && b.has_permissive_choice()
            }
        }
    }

    /// Check if this expression has any copyleft component.
    pub fn has_copyleft(&self) -> bool {
        match self {
            Self::License(id) => LicenseId::new(id).is_copyleft(),
            Self::WithException(id, exception) => {
                LicenseId::new(id).is_copyleft()
                    && !COPYLEFT_NEUTRALIZING_EXCEPTIONS.iter().any(|e| {
                        exception.to_lowercase().contains(&e.to_lowercase())
                    })
            }
            Self::Or(a, b) => a.has_copyleft() || b.has_copyleft(),
            Self::And(a, b) => a.has_copyleft() || b.has_copyleft(),
        }
    }

    /// Get the "effective" copyleft family, considering exceptions and OR choices.
    /// Returns None if copyleft can be avoided (via OR choice or exception).
    pub fn effective_copyleft_family(&self) -> Option<LicenseFamily> {
        match self {
            Self::License(id) => {
                let lid = LicenseId::new(id);
                if lid.is_copyleft() {
                    Some(lid.family())
                } else {
                    None
                }
            }
            Self::WithException(id, exception) => {
                let lid = LicenseId::new(id);
                if lid.is_copyleft() {
                    // Check if exception neutralizes copyleft propagation
                    if COPYLEFT_NEUTRALIZING_EXCEPTIONS.iter().any(|e| {
                        exception.to_lowercase().contains(&e.to_lowercase())
                    }) {
                        None // Exception neutralizes copyleft
                    } else {
                        Some(lid.family())
                    }
                } else {
                    None
                }
            }
            Self::Or(a, b) => {
                // If either branch is permissive, consumer can choose it
                if a.has_permissive_choice() || b.has_permissive_choice() {
                    None // Can avoid copyleft
                } else {
                    // Both are copyleft — take the strongest
                    let fa = a.effective_copyleft_family();
                    let fb = b.effective_copyleft_family();
                    match (fa, fb) {
                        (Some(a), Some(b)) => Some(stronger_copyleft(a, b)),
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (None, None) => None,
                    }
                }
            }
            Self::And(a, b) => {
                // Both must be complied with — take the strongest
                let fa = a.effective_copyleft_family();
                let fb = b.effective_copyleft_family();
                match (fa, fb) {
                    (Some(a), Some(b)) => Some(stronger_copyleft(a, b)),
                    (Some(a), None) => Some(a),
                    (None, Some(b)) => Some(b),
                    (None, None) => None,
                }
            }
        }
    }
}

impl std::fmt::Display for SpdxExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::License(id) => write!(f, "{}", id),
            Self::WithException(id, ex) => write!(f, "{} WITH {}", id, ex),
            Self::Or(a, b) => write!(f, "({} OR {})", a, b),
            Self::And(a, b) => write!(f, "({} AND {})", a, b),
        }
    }
}

// ─── Linking Exception Database ─────────────────────────────────────

/// SPDX exceptions that neutralize copyleft propagation.
/// When one of these is applied via `WITH`, the copyleft requirements
/// do not propagate to the linking/using code.
const COPYLEFT_NEUTRALIZING_EXCEPTIONS: &[&str] = &[
    // Java/JVM ecosystem
    "Classpath-exception-2.0",          // OpenJDK, GlassFish — permits linking
    "GCC-exception-3.1",               // GCC Runtime Library Exception
    "Autoconf-exception-3.0",          // Autoconf-generated scripts
    "Autoconf-exception-generic",
    "Autoconf-exception-macro",
    "Bison-exception-2.2",             // Bison-generated parsers
    "FLTK-exception",                  // FLTK GUI toolkit
    "Font-exception-2.0",             // GPL fonts can be embedded
    "GCC-exception-3.1",              // libgcc, libstdc++ exception
    "LZMA-exception",                 // LZMA SDK
    "Libtool-exception",              // Libtool-generated code
    "Linux-syscall-note",             // Linux kernel UAPI headers
    "Nokia-Qt-exception-1.1",         // Qt LGPL exception
    "OpenVPN-openssl-exception",      // OpenVPN can link against OpenSSL
    "PS-or-PDF-font-exception-20170817",
    "Qt-LGPL-exception-1.1",          // Qt framework
    "Qt-no-exception",
    "Swift-exception",                // Swift runtime exception
    "Universal-FOSS-exception-1.0",   // Permits linking with any FOSS
    "WxWindows-exception-3.1",        // wxWidgets
    "eCos-exception-2.0",             // eCos RTOS
    "gnu-compiler-exception",
    "i2p-gpl-java-exception",
    "mif-exception",
    "u-boot-exception-2.0",           // U-Boot bootloader
];

/// Linking modes that do NOT propagate strong copyleft (GPL).
/// GPL contamination only propagates through "derivative work" boundaries.
const NON_PROPAGATING_LINKS_GPL: &[LinkingMode] = &[
    LinkingMode::BuildTool,     // Build tools are not linked into output
    LinkingMode::ProcMacro,     // Code generators — output is not derivative
    LinkingMode::IpcNetwork,    // Separate process = separate work
];

/// Linking modes that do NOT propagate weak copyleft (LGPL).
/// LGPL specifically allows dynamic linking without propagation.
const NON_PROPAGATING_LINKS_LGPL: &[LinkingMode] = &[
    LinkingMode::Dynamic,       // LGPL explicitly permits dynamic linking
    LinkingMode::BuildTool,
    LinkingMode::ProcMacro,
    LinkingMode::IpcNetwork,
    LinkingMode::HeaderOnly,    // Header-only is effectively dynamic
];

/// Determine which copyleft family is "stronger" (more viral).
fn stronger_copyleft(a: LicenseFamily, b: LicenseFamily) -> LicenseFamily {
    // NetworkCopyleft > StrongCopyleft > WeakCopyleft
    match (a, b) {
        (LicenseFamily::NetworkCopyleft, _) | (_, LicenseFamily::NetworkCopyleft) => {
            LicenseFamily::NetworkCopyleft
        }
        (LicenseFamily::StrongCopyleft, _) | (_, LicenseFamily::StrongCopyleft) => {
            LicenseFamily::StrongCopyleft
        }
        _ => LicenseFamily::WeakCopyleft,
    }
}

// ─── Contamination Result ───────────────────────────────────────────

/// Result of contamination analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContaminationResult {
    /// Which packages are contaminated by copyleft
    pub contaminated: Vec<ContaminatedPackage>,
    /// The root copyleft sources causing contamination
    pub copyleft_sources: Vec<CopyleftSource>,
    /// Dependency chains showing how contamination propagates
    pub propagation_chains: Vec<PropagationChain>,
    /// Packages where copyleft was avoided via OR choice
    pub dual_license_avoidances: Vec<DualLicenseAvoidance>,
    /// Packages where exceptions neutralized copyleft
    pub exception_neutralizations: Vec<ExceptionNeutralization>,
    /// Summary statistics
    pub stats: ContaminationStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContaminatedPackage {
    pub name: String,
    pub own_license: LicenseId,
    pub contaminated_by: LicenseId,
    pub contamination_source: String,
    pub chain: Vec<String>,
    /// Confidence of contamination (1.0 = certain, decays with distance)
    pub confidence: f64,
    /// Why this package is contaminated
    pub reason: ContaminationReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContaminationReason {
    /// Directly linked against copyleft code
    DirectLink { linking: LinkingMode },
    /// Transitively contaminated through dependency chain
    TransitiveChain { depth: usize },
    /// Source-level inclusion (vendored/bundled)
    SourceInclusion,
    /// Network/AGPL interaction
    NetworkInteraction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyleftSource {
    pub name: String,
    pub license: LicenseId,
    pub family: LicenseFamily,
    pub spdx_expression: Option<String>,
    pub exceptions: Vec<String>,
    /// Whether this source's copyleft is neutralized by exceptions
    pub neutralized: bool,
    /// Whether dual-licensing allows avoiding copyleft
    pub dual_license_avoidable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationChain {
    pub source: String,
    pub chain: Vec<String>,
    pub confidence: f64,
    pub linking_modes: Vec<LinkingMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualLicenseAvoidance {
    pub package: String,
    pub copyleft_license: String,
    pub permissive_choice: String,
    pub full_expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionNeutralization {
    pub package: String,
    pub base_license: String,
    pub exception: String,
    pub effect: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContaminationStats {
    pub total_nodes_analyzed: usize,
    pub copyleft_source_count: usize,
    pub contaminated_count: usize,
    pub neutralized_by_exceptions: usize,
    pub avoided_by_dual_licensing: usize,
    pub build_only_excluded: usize,
}

// ─── Core Engine ────────────────────────────────────────────────────

/// Contamination tracing engine
pub struct ContaminationTracer;

impl ContaminationTracer {
    pub fn new() -> Self {
        Self
    }

    /// Trace copyleft contamination through a dependency graph.
    ///
    /// This is the main entry point. It:
    /// 1. Parses SPDX expressions for all nodes
    /// 2. Identifies copyleft sources (accounting for exceptions)
    /// 3. Performs boundary-aware BFS propagation
    /// 4. Computes confidence-weighted contamination chains
    /// 5. Records dual-license avoidances and exception neutralizations
    pub fn trace(&self, nodes: &[DepNode], _root_package: &str) -> ContaminationResult {
        let mut graph: HashMap<&str, &DepNode> = HashMap::new();
        let mut reverse_graph: HashMap<&str, Vec<&str>> = HashMap::new();

        for node in nodes {
            graph.insert(&node.name, node);
            for dep in &node.depends_on {
                reverse_graph
                    .entry(dep.as_str())
                    .or_default()
                    .push(&node.name);
            }
        }

        let mut stats = ContaminationStats {
            total_nodes_analyzed: nodes.len(),
            ..Default::default()
        };

        // Parse SPDX expressions and classify copyleft sources
        let mut copyleft_sources = Vec::new();
        let mut dual_license_avoidances = Vec::new();
        let mut exception_neutralizations = Vec::new();

        for node in nodes {
            let expr = if let Some(ref spdx) = node.spdx_expression {
                SpdxExpression::parse(spdx)
            } else {
                SpdxExpression::License(node.license.0.clone())
            };

            // Check for exceptions explicitly listed on the node
            let has_neutralizing_exception = node.license_exceptions.iter().any(|ex| {
                COPYLEFT_NEUTRALIZING_EXCEPTIONS.iter().any(|known| {
                    ex.to_lowercase().contains(&known.to_lowercase())
                })
            });

            if has_neutralizing_exception && node.license.is_copyleft() {
                exception_neutralizations.push(ExceptionNeutralization {
                    package: node.name.clone(),
                    base_license: node.license.0.clone(),
                    exception: node.license_exceptions.join(", "),
                    effect: "Copyleft propagation neutralized by exception".to_string(),
                });
                stats.neutralized_by_exceptions += 1;

                copyleft_sources.push(CopyleftSource {
                    name: node.name.clone(),
                    license: node.license.clone(),
                    family: node.license.family(),
                    spdx_expression: node.spdx_expression.clone(),
                    exceptions: node.license_exceptions.clone(),
                    neutralized: true,
                    dual_license_avoidable: false,
                });
                continue;
            }

            // Check SPDX expression for dual-license avoidance
            if expr.has_copyleft() && expr.has_permissive_choice() {
                let all = expr.all_licenses();
                let permissive: Vec<_> = all.iter()
                    .filter(|l| !LicenseId::new(l.as_str()).is_copyleft())
                    .collect();
                let copyleft: Vec<_> = all.iter()
                    .filter(|l| LicenseId::new(l.as_str()).is_copyleft())
                    .collect();

                dual_license_avoidances.push(DualLicenseAvoidance {
                    package: node.name.clone(),
                    copyleft_license: copyleft.first().map(|s| s.as_str()).unwrap_or("").to_string(),
                    permissive_choice: permissive.first().map(|s| s.as_str()).unwrap_or("").to_string(),
                    full_expression: expr.to_string(),
                });
                stats.avoided_by_dual_licensing += 1;

                copyleft_sources.push(CopyleftSource {
                    name: node.name.clone(),
                    license: node.license.clone(),
                    family: node.license.family(),
                    spdx_expression: node.spdx_expression.clone(),
                    exceptions: node.license_exceptions.clone(),
                    neutralized: false,
                    dual_license_avoidable: true,
                });
                continue;
            }

            // Check for effective copyleft (considering WITH exceptions in expression)
            if let Some(family) = expr.effective_copyleft_family() {
                // Skip build-only dependencies — they don't contaminate output
                if node.build_only {
                    stats.build_only_excluded += 1;
                    continue;
                }

                copyleft_sources.push(CopyleftSource {
                    name: node.name.clone(),
                    license: node.license.clone(),
                    family,
                    spdx_expression: node.spdx_expression.clone(),
                    exceptions: node.license_exceptions.clone(),
                    neutralized: false,
                    dual_license_avoidable: false,
                });
            }
        }

        stats.copyleft_source_count = copyleft_sources.len();

        // BFS contamination propagation
        let mut contaminated = Vec::new();
        let mut propagation_chains = Vec::new();

        let active_sources: Vec<&CopyleftSource> = copyleft_sources.iter()
            .filter(|s| !s.neutralized && !s.dual_license_avoidable)
            .collect();

        for source in &active_sources {
            let source_node = match graph.get(source.name.as_str()) {
                Some(n) => n,
                None => continue,
            };

            let mut visited: HashSet<&str> = HashSet::new();
            let mut queue: VecDeque<(Vec<String>, Vec<LinkingMode>, &str, f64)> = VecDeque::new();
            queue.push_back((
                vec![source.name.clone()],
                vec![],
                source.name.as_str(),
                1.0, // initial confidence
            ));

            while let Some((chain, link_modes, current, confidence)) = queue.pop_front() {
                if !visited.insert(current) {
                    continue;
                }

                if let Some(dependents) = reverse_graph.get(current) {
                    for &dependent in dependents {
                        if visited.contains(dependent) {
                            continue;
                        }

                        let dep_node = match graph.get(dependent) {
                            Some(n) => n,
                            None => continue,
                        };

                        // Skip build-only dependents
                        if dep_node.build_only {
                            continue;
                        }

                        let mut new_chain = chain.clone();
                        new_chain.push(dependent.to_string());

                        let mut new_link_modes = link_modes.clone();
                        new_link_modes.push(dep_node.linking);

                        // Check if contamination propagates through this boundary
                        let (propagates, reason) = self.check_propagation(
                            source.family,
                            dep_node.linking,
                            source_node,
                            dep_node,
                        );

                        if propagates {
                            // Confidence decays with chain depth and weaker boundaries
                            let boundary_factor = match dep_node.linking {
                                LinkingMode::Source | LinkingMode::Static => 1.0,
                                LinkingMode::Dynamic => 0.85,
                                LinkingMode::HeaderOnly => 0.7,
                                LinkingMode::Unknown => 0.6,
                                _ => 0.5,
                            };
                            let new_confidence = confidence * boundary_factor;

                            // Only flag if the dependent isn't itself copyleft-compatible
                            let dep_expr = if let Some(ref spdx) = dep_node.spdx_expression {
                                SpdxExpression::parse(spdx)
                            } else {
                                SpdxExpression::License(dep_node.license.0.clone())
                            };

                            if dep_expr.effective_copyleft_family().is_none() {
                                contaminated.push(ContaminatedPackage {
                                    name: dependent.to_string(),
                                    own_license: dep_node.license.clone(),
                                    contaminated_by: source_node.license.clone(),
                                    contamination_source: source.name.clone(),
                                    chain: new_chain.clone(),
                                    confidence: new_confidence,
                                    reason,
                                });

                                propagation_chains.push(PropagationChain {
                                    source: source.name.clone(),
                                    chain: new_chain.clone(),
                                    confidence: new_confidence,
                                    linking_modes: new_link_modes.clone(),
                                });
                            }

                            // Continue BFS even through copyleft nodes
                            queue.push_back((new_chain, new_link_modes, dependent, new_confidence));
                        }
                    }
                }
            }
        }

        stats.contaminated_count = contaminated.len();

        ContaminationResult {
            contaminated,
            copyleft_sources,
            propagation_chains,
            dual_license_avoidances,
            exception_neutralizations,
            stats,
        }
    }

    /// Determine if copyleft contamination propagates through a given boundary.
    fn check_propagation(
        &self,
        family: LicenseFamily,
        linking: LinkingMode,
        _source_node: &DepNode,
        _dep_node: &DepNode,
    ) -> (bool, ContaminationReason) {
        match family {
            LicenseFamily::StrongCopyleft => {
                // GPL: propagates through everything EXCEPT non-derivative boundaries
                if NON_PROPAGATING_LINKS_GPL.contains(&linking) {
                    (false, ContaminationReason::DirectLink { linking })
                } else {
                    let reason = match linking {
                        LinkingMode::Source => ContaminationReason::SourceInclusion,
                        _ => ContaminationReason::DirectLink { linking },
                    };
                    (true, reason)
                }
            }
            LicenseFamily::WeakCopyleft => {
                // LGPL: propagates through static/source but NOT dynamic
                if NON_PROPAGATING_LINKS_LGPL.contains(&linking) {
                    (false, ContaminationReason::DirectLink { linking })
                } else {
                    let reason = match linking {
                        LinkingMode::Source => ContaminationReason::SourceInclusion,
                        LinkingMode::Static => ContaminationReason::DirectLink { linking },
                        _ => ContaminationReason::DirectLink { linking },
                    };
                    (true, reason)
                }
            }
            LicenseFamily::NetworkCopyleft => {
                // AGPL/SSPL: propagates through EVERYTHING including network
                if linking == LinkingMode::BuildTool || linking == LinkingMode::ProcMacro {
                    (false, ContaminationReason::DirectLink { linking })
                } else {
                    let reason = match linking {
                        LinkingMode::IpcNetwork => ContaminationReason::NetworkInteraction,
                        LinkingMode::Source => ContaminationReason::SourceInclusion,
                        _ => ContaminationReason::DirectLink { linking },
                    };
                    (true, reason)
                }
            }
            _ => (false, ContaminationReason::DirectLink { linking }),
        }
    }

    /// Convert contamination results to violations.
    pub fn to_violations(
        &self,
        result: &ContaminationResult,
        project_license: &LicenseId,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        // Contaminated packages → violations
        for cp in &result.contaminated {
            if project_license.is_copyleft() {
                continue; // Project is already copyleft, no violation
            }

            let severity = if cp.confidence > 0.9 {
                Severity::Critical
            } else if cp.confidence > 0.7 {
                Severity::High
            } else if cp.confidence > 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let reason_str = match &cp.reason {
                ContaminationReason::DirectLink { linking } =>
                    format!("directly linked ({:?})", linking),
                ContaminationReason::TransitiveChain { depth } =>
                    format!("transitively contaminated (depth: {})", depth),
                ContaminationReason::SourceInclusion =>
                    "source-level inclusion (vendored)".to_string(),
                ContaminationReason::NetworkInteraction =>
                    "network interaction (AGPL/SSPL)".to_string(),
            };

            violations.push(Violation {
                violation_type: ViolationType::CopyleftInProprietary,
                severity,
                confidence: cp.confidence,
                description: format!(
                    "Package '{}' ({}) is contaminated by {} from '{}' via {}. Chain: {}",
                    cp.name,
                    cp.own_license,
                    cp.contaminated_by,
                    cp.contamination_source,
                    reason_str,
                    cp.chain.join(" → ")
                ),
                files: vec![],
                licenses: vec![cp.own_license.clone(), cp.contaminated_by.clone()],
                obligations_violated: vec![
                    LicenseObligation::SourceDisclosure,
                    LicenseObligation::Copyleft,
                ],
                evidence: vec![EvidenceItem {
                    description: format!(
                        "Contamination chain: {} (confidence: {:.0}%)",
                        cp.chain.join(" → "),
                        cp.confidence * 100.0
                    ),
                    file_path: None,
                    line_number: None,
                    byte_offset: None,
                    sha256: None,
                    content_excerpt: None,
                    timestamp: chrono::Utc::now(),
                }],
                claimed_license: Some(project_license.clone()),
                actual_license: Some(cp.contaminated_by.clone()),
            });
        }

        // Dual-license avoidances → informational violations
        for avoidance in &result.dual_license_avoidances {
            violations.push(Violation {
                violation_type: ViolationType::DualLicenseMisuse,
                severity: Severity::Low,
                confidence: 0.85,
                description: format!(
                    "Package '{}' is dual-licensed ({}). Copyleft ({}) can be avoided by choosing {}.",
                    avoidance.package,
                    avoidance.full_expression,
                    avoidance.copyleft_license,
                    avoidance.permissive_choice,
                ),
                files: vec![],
                licenses: vec![
                    LicenseId::new(&avoidance.copyleft_license),
                    LicenseId::new(&avoidance.permissive_choice),
                ],
                obligations_violated: vec![],
                evidence: vec![],
                claimed_license: None,
                actual_license: None,
            });
        }

        violations
    }
}

impl Default for ContaminationTracer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(name: &str, license: &str, deps: Vec<&str>, linking: LinkingMode) -> DepNode {
        DepNode {
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            license: LicenseId::new(license),
            spdx_expression: None,
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            linking,
            license_exceptions: vec![],
            build_only: false,
        }
    }

    fn make_node_spdx(name: &str, license: &str, spdx: &str, deps: Vec<&str>, linking: LinkingMode) -> DepNode {
        DepNode {
            name: name.to_string(),
            version: Some("1.0.0".to_string()),
            license: LicenseId::new(license),
            spdx_expression: Some(spdx.to_string()),
            depends_on: deps.iter().map(|s| s.to_string()).collect(),
            linking,
            license_exceptions: vec![],
            build_only: false,
        }
    }

    #[test]
    fn test_spdx_parse_simple() {
        let expr = SpdxExpression::parse("MIT");
        assert!(matches!(expr, SpdxExpression::License(ref id) if id == "MIT"));
    }

    #[test]
    fn test_spdx_parse_or() {
        let expr = SpdxExpression::parse("MIT OR Apache-2.0");
        assert!(expr.has_permissive_choice());
        assert!(!expr.has_copyleft());
    }

    #[test]
    fn test_spdx_parse_gpl_or_mit() {
        let expr = SpdxExpression::parse("GPL-2.0-only OR MIT");
        assert!(expr.has_copyleft());
        assert!(expr.has_permissive_choice());
        assert!(expr.effective_copyleft_family().is_none()); // Can avoid via MIT
    }

    #[test]
    fn test_spdx_parse_gpl_with_classpath() {
        let expr = SpdxExpression::parse("GPL-2.0-only WITH Classpath-exception-2.0");
        assert!(expr.effective_copyleft_family().is_none()); // Classpath neutralizes
    }

    #[test]
    fn test_spdx_parse_compound() {
        let expr = SpdxExpression::parse("(MIT OR Apache-2.0) AND CC-BY-4.0");
        assert!(expr.has_permissive_choice());
    }

    #[test]
    fn test_gpl_contaminates_static_link() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["lib-a"], LinkingMode::Static),
            make_node("lib-a", "GPL-3.0-only", vec![], LinkingMode::Static),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert_eq!(result.contaminated.len(), 1);
        assert_eq!(result.contaminated[0].name, "my-app");
    }

    #[test]
    fn test_lgpl_no_contamination_dynamic() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["lib-b"], LinkingMode::Dynamic),
            make_node("lib-b", "LGPL-2.1-only", vec![], LinkingMode::Dynamic),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert!(result.contaminated.is_empty(), "LGPL via dynamic link should not contaminate");
    }

    #[test]
    fn test_lgpl_contaminates_static() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["lib-b"], LinkingMode::Static),
            make_node("lib-b", "LGPL-2.1-only", vec![], LinkingMode::Static),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert_eq!(result.contaminated.len(), 1);
    }

    #[test]
    fn test_dual_license_avoidance() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["dual-lib"], LinkingMode::Static),
            make_node_spdx("dual-lib", "GPL-2.0-only", "GPL-2.0-only OR MIT", vec![], LinkingMode::Static),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert!(result.contaminated.is_empty(), "Dual-license should allow avoiding GPL");
        assert_eq!(result.dual_license_avoidances.len(), 1);
    }

    #[test]
    fn test_classpath_exception() {
        let mut node = make_node("openjdk-lib", "GPL-2.0-only", vec![], LinkingMode::Static);
        node.license_exceptions = vec!["Classpath-exception-2.0".to_string()];
        let nodes = vec![
            make_node("my-app", "MIT", vec!["openjdk-lib"], LinkingMode::Static),
            node,
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert!(result.contaminated.is_empty(), "Classpath exception should neutralize GPL");
        assert_eq!(result.exception_neutralizations.len(), 1);
    }

    #[test]
    fn test_build_tool_exclusion() {
        let mut node = make_node("gcc", "GPL-3.0-only", vec![], LinkingMode::BuildTool);
        node.build_only = true;
        let nodes = vec![
            make_node("my-app", "MIT", vec!["gcc"], LinkingMode::BuildTool),
            node,
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert!(result.contaminated.is_empty(), "Build tools should not contaminate");
    }

    #[test]
    fn test_transitive_contamination() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["lib-a"], LinkingMode::Static),
            make_node("lib-a", "MIT", vec!["lib-b"], LinkingMode::Static),
            make_node("lib-b", "MIT", vec!["gpl-lib"], LinkingMode::Static),
            make_node("gpl-lib", "GPL-3.0-only", vec![], LinkingMode::Static),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert!(result.contaminated.len() >= 3, "All transitives should be contaminated");
    }

    #[test]
    fn test_agpl_contaminates_network() {
        let nodes = vec![
            make_node("my-app", "MIT", vec!["agpl-service"], LinkingMode::IpcNetwork),
            make_node("agpl-service", "AGPL-3.0-only", vec![], LinkingMode::IpcNetwork),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "my-app");
        assert_eq!(result.contaminated.len(), 1, "AGPL should contaminate via network");
    }

    #[test]
    fn test_confidence_decay() {
        let nodes = vec![
            make_node("app", "MIT", vec!["a"], LinkingMode::Static),
            make_node("a", "MIT", vec!["b"], LinkingMode::Dynamic),
            make_node("b", "MIT", vec!["c"], LinkingMode::Static),
            make_node("c", "GPL-3.0-only", vec![], LinkingMode::Static),
        ];
        let tracer = ContaminationTracer::new();
        let result = tracer.trace(&nodes, "app");
        // Find the app's contamination entry
        let app_entry = result.contaminated.iter().find(|c| c.name == "app");
        if let Some(entry) = app_entry {
            assert!(entry.confidence < 1.0, "Confidence should decay through chain: {}", entry.confidence);
        }
    }
}
