//! Cross-module violation correlation engine
//!
//! Cross-references findings from different detection modules to boost
//! or demote confidence. Multi-signal violations that no single detector
//! would catch alone get corroborated here.

use crate::detection::{DetectionResult, Severity, ViolationType};

/// Cross-reference findings and boost correlated violations
pub fn correlate_violations(result: &mut DetectionResult) {
    let violations = result.violations.clone();
    let mut boosted_indices: Vec<usize> = Vec::new();

    for (i, v) in violations.iter().enumerate() {
        for (j, w) in violations.iter().enumerate() {
            if i >= j {
                continue;
            }

            // Same file, different detectors → cross-corroboration
            let same_file = !v.files.is_empty()
                && !w.files.is_empty()
                && v.files.iter().any(|f| w.files.contains(f));

            if !same_file {
                continue;
            }

            let correlated = is_correlated(&v.violation_type, &w.violation_type);
            if correlated {
                boosted_indices.push(i);
                boosted_indices.push(j);
            }
        }
    }

    // Deduplicate so we don't double-boost
    boosted_indices.sort_unstable();
    boosted_indices.dedup();

    // Apply boost
    for idx in boosted_indices {
        if let Some(v) = result.violations.get_mut(idx) {
            v.confidence = (v.confidence * 1.3).min(1.0);
            if v.severity == Severity::Medium {
                v.severity = Severity::High;
            } else if v.severity == Severity::High {
                v.severity = Severity::Critical;
            }
            v.description
                .push_str(" [CORROBORATED by cross-module analysis]");
        }
    }
}

/// Check if two violation types are meaningfully correlated
fn is_correlated(a: &ViolationType, b: &ViolationType) -> bool {
    use ViolationType::*;

    let pair = (a, b);

    // Rule 1: Supply chain typosquatting + code fingerprint → license laundering
    matches!(
        pair,
        (Typosquatting, CodeFingerprintMismatch | ObfuscatedMatch)
            | (CodeFingerprintMismatch | ObfuscatedMatch, Typosquatting)
    )
    // Rule 2: Missing attribution + stripped license → deliberate infringement
    || matches!(
        pair,
        (MissingAttribution, StrippedLicense | LicenseTextTampering)
            | (StrippedLicense | LicenseTextTampering, MissingAttribution)
    )
    // Rule 3: Chimera license + homoglyph → sophisticated tampering
    || matches!(
        pair,
        (ChimeraLicense, HomoglyphTampering) | (HomoglyphTampering, ChimeraLicense)
    )
    // Rule 4: Obfuscated code + stock/font theft → hidden asset theft
    || matches!(
        pair,
        (ObfuscatedMatch, StockPhotoUsage | CommercialFontUsage)
            | (StockPhotoUsage | CommercialFontUsage, ObfuscatedMatch)
    )
    // Rule 5: PII + secrets on same file → data breach
    || matches!(
        pair,
        (PiiExposure, ExposedSecrets) | (ExposedSecrets, PiiExposure)
    )
    // Rule 6: Commercial font + non-commercial misuse
    || matches!(
        pair,
        (CommercialFontUsage, NonCommercialInCommercial | AcademicLicenseMisuse)
            | (NonCommercialInCommercial | AcademicLicenseMisuse, CommercialFontUsage)
    )
    // Rule 7: License tampering + chimera/homoglyph → systematic fraud
    || matches!(
        pair,
        (LicenseTextTampering, ChimeraLicense | HomoglyphTampering)
            | (ChimeraLicense | HomoglyphTampering, LicenseTextTampering)
    )
    // Rule 8: Typosquatting + version pinning/scope confusion → malicious package
    || matches!(
        pair,
        (Typosquatting, VersionPinningRisk | ScopeConfusion)
            | (VersionPinningRisk | ScopeConfusion, Typosquatting)
    )
    // Rule 9: CC non-commercial + CC no-derivatives → systematic CC abuse
    || matches!(
        pair,
        (CcNonCommercialViolation, CcNoDerivativesViolation | CcMissingAttribution)
            | (CcNoDerivativesViolation | CcMissingAttribution, CcNonCommercialViolation)
    )
    // Rule 10: Deprecated dependency + lockfile staleness → neglected supply chain
    || matches!(
        pair,
        (DeprecatedDependency, LockfileStaleness | VersionPinningRisk)
            | (LockfileStaleness | VersionPinningRisk, DeprecatedDependency)
    )
    // Rule 11: Binary GPL detection + copyleft-in-proprietary → binary-level contamination
    || matches!(
        pair,
        (CopyleftInProprietary, BinaryContainsGplSymbols)
            | (BinaryContainsGplSymbols, CopyleftInProprietary)
    )
    // Rule 12: ML dataset violation + unlicensed data → training data compliance failure
    || matches!(
        pair,
        (MlDatasetViolation, UnlicensedData | UnlicensedGeodata)
            | (UnlicensedData | UnlicensedGeodata, MlDatasetViolation)
    )
    // Rule 13: Missing SRI hash + typosquatting → CDN supply chain attack
    || matches!(
        pair,
        (MissingSriHash, Typosquatting | ScopeConfusion)
            | (Typosquatting | ScopeConfusion, MissingSriHash)
    )
    // Rule 14: License laundering + stripped license/fingerprint mismatch → coordinated laundering
    || matches!(
        pair,
        (LicenseLaundering, StrippedLicense | CodeFingerprintMismatch | ObfuscatedMatch)
            | (StrippedLicense | CodeFingerprintMismatch | ObfuscatedMatch, LicenseLaundering)
    )
    // Rule 15: Network service violation + copyleft → AGPL evasion
    || matches!(
        pair,
        (NetworkServiceWithoutDisclosure, CopyleftInProprietary | MissingSourceDisclosure)
            | (CopyleftInProprietary | MissingSourceDisclosure, NetworkServiceWithoutDisclosure)
    )

    // ── Digital Asset Correlation Rules ──────────────────────────────

    // Rule 16: DRM circumvention + stock watermark → commercial piracy ring
    || matches!(
        pair,
        (DrmCircumvention, StockWatermarkDetected | StockPhotoUsage)
            | (StockWatermarkDetected | StockPhotoUsage, DrmCircumvention)
    )
    // Rule 17: Unlicensed audio + sampling violation → systematic music piracy
    || matches!(
        pair,
        (UnlicensedAudioUsage, UnlicensedSampling | UnlicensedRemix)
            | (UnlicensedSampling | UnlicensedRemix, UnlicensedAudioUsage)
    )
    // Rule 18: AI model violation + training data contamination → AI supply chain corruption
    || matches!(
        pair,
        (AiModelLicenseViolation, TrainingDataContamination | UnauthorizedFineTuning)
            | (TrainingDataContamination | UnauthorizedFineTuning, AiModelLicenseViolation)
    )
    // Rule 19: Firmware GPL + embedded font → systematic embedded IP violation
    || matches!(
        pair,
        (FirmwareGplViolation, EmbeddedFontUnlicensed)
            | (EmbeddedFontUnlicensed, FirmwareGplViolation)
    )
    // Rule 20: Typeface infringement + icon pack piracy → design asset piracy
    || matches!(
        pair,
        (TypefaceDesignInfringement, IconPackPiracy | UiKitLicenseBreach)
            | (IconPackPiracy | UiKitLicenseBreach, TypefaceDesignInfringement)
    )
    // Rule 21: Ebook redistribution + document template piracy → publishing piracy
    || matches!(
        pair,
        (EbookRedistribution, DocumentTemplatePiracy | CourseMaterialRedistribution)
            | (DocumentTemplatePiracy | CourseMaterialRedistribution, EbookRedistribution)
    )
    // Rule 22: Stock watermark + image license scope exceeded → stock media fraud
    || matches!(
        pair,
        (StockWatermarkDetected, ImageLicenseScopeExceeded)
            | (ImageLicenseScopeExceeded, StockWatermarkDetected)
    )
    // Rule 23: OpenRAIL restriction + unauthorized fine-tuning → AI governance failure
    || matches!(
        pair,
        (OpenRailRestrictionBreach, UnauthorizedFineTuning | AiOutputAttributionMissing)
            | (UnauthorizedFineTuning | AiOutputAttributionMissing, OpenRailRestrictionBreach)
    )
    // Rule 24: ROM piracy + firmware GPL → embedded system piracy
    || matches!(
        pair,
        (RomImagePiracy, FirmwareGplViolation | EmbeddedFontUnlicensed)
            | (FirmwareGplViolation | EmbeddedFontUnlicensed, RomImagePiracy)
    )
    // Rule 25: DRM circumvention + audio/video piracy → DMCA criminal violation
    || matches!(
        pair,
        (DrmCircumvention, UnlicensedAudioUsage | UnlicensedVideoUsage)
            | (UnlicensedAudioUsage | UnlicensedVideoUsage, DrmCircumvention)
    )
    // Rule 26: 3D model + CAD drawing violation → design IP theft ring
    || matches!(
        pair,
        (ThreeDModelLicenseViolation, CadDrawingUnauthorized)
            | (CadDrawingUnauthorized, ThreeDModelLicenseViolation)
    )
    // Rule 27: Commercial font + typeface infringement → typography piracy
    || matches!(
        pair,
        (CommercialFontUsage, TypefaceDesignInfringement)
            | (TypefaceDesignInfringement, CommercialFontUsage)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::Violation;
    use std::path::PathBuf;

    fn make_violation_on_file(vtype: ViolationType, file: &str) -> Violation {
        Violation {
            violation_type: vtype,
            severity: Severity::Medium,
            confidence: 0.7,
            description: "test".to_string(),
            files: vec![PathBuf::from(file)],
            licenses: vec![],
            obligations_violated: vec![],
            evidence: vec![],
            claimed_license: None,
            actual_license: None,
        }
    }

    fn make_result_with(violations: Vec<Violation>) -> DetectionResult {
        let mut r = DetectionResult::default();
        r.violations = violations;
        r
    }

    #[test]
    fn test_same_file_correlated_boosts() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::MissingAttribution, "src/lib.rs"),
            make_violation_on_file(ViolationType::StrippedLicense, "src/lib.rs"),
        ]);
        correlate_violations(&mut result);
        // Both should be boosted
        assert!(result.violations[0].confidence > 0.7);
        assert!(result.violations[1].confidence > 0.7);
        assert!(result.violations[0].description.contains("CORROBORATED"));
    }

    #[test]
    fn test_different_files_not_correlated() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::MissingAttribution, "src/a.rs"),
            make_violation_on_file(ViolationType::StrippedLicense, "src/b.rs"),
        ]);
        correlate_violations(&mut result);
        // Neither should be boosted (different files)
        assert!((result.violations[0].confidence - 0.7).abs() < 0.001);
        assert!(!result.violations[0].description.contains("CORROBORATED"));
    }

    #[test]
    fn test_unrelated_types_not_correlated() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::MissingAttribution, "src/lib.rs"),
            make_violation_on_file(ViolationType::LockfileStaleness, "src/lib.rs"),
        ]);
        correlate_violations(&mut result);
        assert!((result.violations[0].confidence - 0.7).abs() < 0.001);
    }

    #[test]
    fn test_severity_upgrade_on_correlation() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::ChimeraLicense, "LICENSE"),
            make_violation_on_file(ViolationType::HomoglyphTampering, "LICENSE"),
        ]);
        correlate_violations(&mut result);
        // Medium should be upgraded to High
        assert_eq!(result.violations[0].severity, Severity::High);
    }

    #[test]
    fn test_drm_stock_watermark_correlation() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::DrmCircumvention, "assets/image.jpg"),
            make_violation_on_file(ViolationType::StockWatermarkDetected, "assets/image.jpg"),
        ]);
        correlate_violations(&mut result);
        assert!(result.violations[0].description.contains("CORROBORATED"));
        assert!(result.violations[1].description.contains("CORROBORATED"));
    }

    #[test]
    fn test_ai_model_training_data_correlation() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::AiModelLicenseViolation, "models/weights.safetensors"),
            make_violation_on_file(ViolationType::TrainingDataContamination, "models/weights.safetensors"),
        ]);
        correlate_violations(&mut result);
        assert!(result.violations[0].description.contains("CORROBORATED"));
    }

    #[test]
    fn test_firmware_embedded_font_correlation() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::FirmwareGplViolation, "firmware/main.bin"),
            make_violation_on_file(ViolationType::EmbeddedFontUnlicensed, "firmware/main.bin"),
        ]);
        correlate_violations(&mut result);
        assert!(result.violations[0].description.contains("CORROBORATED"));
    }

    #[test]
    fn test_drm_audio_dmca_criminal_correlation() {
        let mut result = make_result_with(vec![
            make_violation_on_file(ViolationType::DrmCircumvention, "audio/track.mp3"),
            make_violation_on_file(ViolationType::UnlicensedAudioUsage, "audio/track.mp3"),
        ]);
        correlate_violations(&mut result);
        // DRM + audio piracy = DMCA criminal — both should be corroborated
        assert!(result.violations[0].description.contains("CORROBORATED"));
        assert!(result.violations[1].description.contains("CORROBORATED"));
    }
}


