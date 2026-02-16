//! Phase 3b-vi: Web asset scanning — CDN refs, fonts, icon libraries

use crate::detection::web_asset_scanner::{WebAssetScanner, IconTier, FontLicense};
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use crate::SkeraResult;

pub struct WebAssetsPhase;

impl WebAssetsPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for WebAssetsPhase {
    fn name(&self) -> &str {
        "Web Asset Scanning"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let report = WebAssetScanner::scan(&ctx.source_dir);
        let mut violations = Vec::new();

        // CDN references without SRI
        for cdn in &report.cdn_references {
            if cdn.integrity_hash.is_none() {
                violations.push(Violation {
                    violation_type: ViolationType::MissingSriHash,
                    severity: Severity::Medium,
                    confidence: 0.90,
                    description: format!(
                        "CDN resource loaded without SRI (Subresource Integrity): {}",
                        cdn.library_name.as_deref().unwrap_or(&cdn.url)
                    ),
                    files: vec![cdn.file_path.clone()],
                    licenses: cdn.license.as_ref().map(|l| LicenseId::new(l)).into_iter().collect(),
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &cdn.file_path, cdn.line_number,
                        &format!("CDN: {} ({})", cdn.url, cdn.library_name.as_deref().unwrap_or("unknown")),
                        "No SRI hash — supply chain vulnerability",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        // Commercial web fonts
        for font in &report.web_fonts {
            if font.license == Some(FontLicense::Commercial) {
                violations.push(Violation {
                    violation_type: ViolationType::CommercialFontUsage,
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Commercial font '{}' detected in {}",
                        font.font_name, font.file_path.display()
                    ),
                    files: vec![font.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &font.file_path, font.line_number,
                        &format!("Font: {} ({:?})", font.font_name, font.source),
                        "Web font analysis detected commercial font",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        // Pro icon libraries
        for icon_lib in &report.icon_libraries {
            if icon_lib.tier == IconTier::Pro {
                violations.push(Violation {
                    violation_type: ViolationType::CommercialFontUsage,
                    severity: Severity::High,
                    confidence: 0.90,
                    description: format!(
                        "Pro/commercial icon library {:?} detected in {}",
                        icon_lib.library, icon_lib.file_path.display()
                    ),
                    files: vec![icon_lib.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &icon_lib.file_path, 0,
                        &format!("Icon library: {:?} ({} references)", icon_lib.library, icon_lib.references),
                        "Pro tier icons require commercial license",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        Ok(PhaseOutput::with_violations(violations, report.files_scanned))
    }
}
