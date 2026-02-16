//! Phase 3b-ii: JS bundle forensics — detects libraries inside minified/bundled JS

use crate::detection::js_bundle_forensics::JsBundleScanner;
use crate::detection::js_analysis;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct JsForensicsPhase {
    scanner: JsBundleScanner,
}

impl JsForensicsPhase {
    pub fn new() -> Self {
        Self {
            scanner: JsBundleScanner::new(),
        }
    }
}

impl ScanPhase for JsForensicsPhase {
    fn name(&self) -> &str {
        "JS Bundle Forensics"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        // Use FileIndex for large JS files (bundles typically >50KB)
        let bundles = ctx.file_index.large_js(50_000);

        let mut violations = Vec::new();
        for file in &bundles {
            // analyze_file takes a Path, reads the file itself, and returns Result<BundleForensicReport>
            if let Ok(report) = self.scanner.analyze_file(&file.path) {
                violations.extend(report.violations);
            }
        }

        // Run JS analysis on medium-sized files — detect obfuscation, fonts, endpoints
        let analysis_candidates = ctx.file_index.js_analysis_candidates();
        for file in &analysis_candidates {
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                let analysis = js_analysis::full_analysis(&content);

                // Obfuscation score above threshold → suspicious code hiding
                if analysis.obfuscation.score >= 0.5 {
                    let signals_desc: Vec<String> = analysis.obfuscation.signals.iter()
                        .map(|s| format!("{}: {}", s.kind, s.description))
                        .collect();
                    violations.push(Violation {
                        violation_type: ViolationType::ObfuscatedMatch,
                        severity: if analysis.obfuscation.score > 0.75 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        confidence: analysis.obfuscation.score,
                        description: format!(
                            "Obfuscation detected in {} (score={:.0}%, entropy={:.2}): {}",
                            file.path.display(),
                            analysis.obfuscation.score * 100.0,
                            analysis.entropy,
                            signals_desc.join("; ")
                        ),
                        files: vec![file.path.clone()],
                        licenses: vec![],
                        obligations_violated: vec![],
                        evidence: vec![EvidenceItem::from_file(
                            &file.path, 0,
                            &format!(
                                "Obfuscation: {:.2}, entropy: {:.2}, {} signals",
                                analysis.obfuscation.score,
                                analysis.entropy,
                                analysis.obfuscation.signals.len()
                            ),
                            "JS analysis detected deliberate code obfuscation",
                        )],
                        claimed_license: None,
                        actual_license: None,
                    });
                }

                // Commercial font references embedded in JS/CSS
                let commercial_fonts = ["Proxima Nova", "Gotham", "Helvetica Neue",
                    "Avenir", "Futura", "Frutiger", "Univers", "Didot",
                    "Gill Sans", "Brandon Grotesque", "Circular", "Graphik"];
                for font_ref in &analysis.font_references {
                    if commercial_fonts.iter().any(|&cf|
                        font_ref.name.to_lowercase().contains(&cf.to_lowercase()))
                    {
                        violations.push(Violation {
                            violation_type: ViolationType::CommercialFontUsage,
                            severity: Severity::High,
                            confidence: 0.80,
                            description: format!(
                                "Commercial font '{}' referenced in {} ({:?})",
                                font_ref.name, file.path.display(), font_ref.context
                            ),
                            files: vec![file.path.clone()],
                            licenses: vec![],
                            obligations_violated: vec![],
                            evidence: vec![EvidenceItem::from_file(
                                &file.path, 0,
                                &format!("Font: {} at offset {}", font_ref.name, font_ref.byte_offset),
                                "JS analysis found commercial font-family declaration",
                            )],
                            claimed_license: None,
                            actual_license: None,
                        });
                    }
                }
            }
        }

        let total = bundles.len() + analysis_candidates.len();
        Ok(PhaseOutput::with_violations(violations, total))
    }
}
