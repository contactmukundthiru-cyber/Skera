//! Phase 3b-v: Asset fingerprinting — fonts, copyright notices in binaries

use crate::detection::asset_fingerprint;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct AssetScanPhase;

impl AssetScanPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for AssetScanPhase {
    fn name(&self) -> &str {
        "Asset Fingerprinting"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let assets = asset_fingerprint::scan_assets(&ctx.source_dir);
        let mut violations = Vec::new();

        for asset in &assets {
            // Check for commercial fonts
            if asset.metadata.is_commercial_font {
                let font_name = asset.metadata.font_family.as_deref().unwrap_or("unknown");
                violations.push(Violation {
                    violation_type: ViolationType::CommercialFontUsage,
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Commercial font '{}' detected in {}",
                        font_name, asset.file_path.display()
                    ),
                    files: vec![asset.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &asset.file_path, 0,
                        &format!("Asset: {} (type: {:?})", font_name, asset.asset_type),
                        "Binary asset fingerprint analysis",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }

            // Check for copyright strings without license info
            if !asset.metadata.copyright_strings.is_empty() && asset.metadata.license_info.is_none() {
                violations.push(Violation {
                    violation_type: ViolationType::StrippedLicense,
                    severity: Severity::Medium,
                    confidence: 0.65,
                    description: format!(
                        "Asset {} has copyright notice but no license: {}",
                        asset.file_path.display(),
                        asset.metadata.copyright_strings.first().unwrap_or(&String::new())
                    ),
                    files: vec![asset.file_path.clone()],
                    licenses: vec![],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &asset.file_path, 0,
                        &format!(
                            "Copyright: {} (no associated license)",
                            asset.metadata.copyright_strings.first().unwrap_or(&String::new())
                        ),
                        "Asset has copyright notice but missing license — possible stripped attribution",
                    )],
                    claimed_license: None,
                    actual_license: None,
                });
            }
        }

        Ok(PhaseOutput::with_violations(violations, assets.len()))
    }
}
