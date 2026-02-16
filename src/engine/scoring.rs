//! Context-aware risk scoring
//!
//! Calculates a 0-100 risk score that considers violation type + project
//! context, not just raw severity counts.

use crate::detection::{DetectionResult, Severity, ViolationType};
use super::SkeraConfig;

/// Calculate a 0-100 risk score with context-aware multipliers
pub fn calculate_risk_score(result: &DetectionResult, config: &SkeraConfig) -> u32 {
    let mut score: u32 = 0;

    for v in &result.violations {
        let base = match v.severity {
            Severity::Critical => 30,
            Severity::High => 15,
            Severity::Medium => 5,
            Severity::Low => 1,
        };

        let multiplier: f64 = match v.violation_type {
            // AGPL in SaaS = maximum risk
            ViolationType::NetworkServiceWithoutDisclosure if config.network_service => 3.5,
            // GPL contamination in commercial = very high risk
            ViolationType::CopyleftInProprietary if config.commercial => 2.5,
            // Deliberate malfeasance
            ViolationType::LicenseLaundering | ViolationType::LicenseTextTampering => 2.0,
            // Regulatory exposure
            ViolationType::PiiExposure | ViolationType::ExposedSecrets => 2.0,
            // DRM circumvention
            ViolationType::Custom(ref s) if s.contains("DRM") => 2.0,
            // Intentional tampering
            ViolationType::ChimeraLicense | ViolationType::HomoglyphTampering => 2.5,
            // Patent violations — high litigation risk
            ViolationType::PatentTermination => 2.0,
            ViolationType::MissingPatentGrant => 1.8,
            // License forensic findings
            ViolationType::StrippedLicense | ViolationType::MissingSourceDisclosure => 1.6,
            ViolationType::ManifestLicenseMismatch => 1.4,
            ViolationType::TyposquattedLicense => 1.8,
            // Code provenance matches
            ViolationType::DecompiledCodeMatch | ViolationType::CodeFingerprintMismatch => 1.5,
            // Supply chain attacks
            ViolationType::Typosquatting | ViolationType::ScopeConfusion => 2.0,
            ViolationType::VersionPinningRisk | ViolationType::DeprecatedDependency => 1.3,
            ViolationType::LockfileStaleness => 1.2,
            ViolationType::MissingSriHash => 1.4,
            // Dual-license abuse
            ViolationType::DualLicenseMisuse => 1.7,
            // Binary-level contamination
            ViolationType::BinaryContainsGplSymbols => 1.8,
            // Commercial asset misuse
            ViolationType::CommercialFontUsage | ViolationType::StockPhotoUsage => 1.5,
            // Evasion attempts
            ViolationType::ObfuscatedMatch => 1.5,
            // Creative Commons violations
            ViolationType::CcNonCommercialViolation | ViolationType::CcNoDerivativesViolation => 1.5,
            ViolationType::CcMissingAttribution | ViolationType::CcShareAlikeIncompatible => 1.3,
            // Data rights
            ViolationType::UnlicensedGeodata | ViolationType::MlDatasetViolation => 1.5,
            ViolationType::UnlicensedData => 1.5,
            // Network service without specific config
            ViolationType::NetworkServiceWithoutDisclosure => 1.8,
            ViolationType::CopyleftInProprietary => 1.5,
            // Remaining known code types
            ViolationType::IncompatibleLicenses => 1.4,
            ViolationType::MissingAttribution => 1.2,
            // ── Digital media rights ──
            // DRM circumvention is a federal offense under DMCA §1201
            ViolationType::DrmCircumvention => 3.0,
            ViolationType::UnlicensedAudioUsage | ViolationType::UnlicensedVideoUsage => 1.8,
            ViolationType::UnlicensedSampling => 2.0,
            ViolationType::StockWatermarkDetected => 1.6,
            ViolationType::ImageLicenseScopeExceeded => 1.5,
            ViolationType::UnlicensedRemix => 1.6,
            // ── AI & model rights ──
            ViolationType::AiModelLicenseViolation => 2.5,
            ViolationType::TrainingDataContamination => 2.5,
            ViolationType::OpenRailRestrictionBreach => 2.0,
            ViolationType::AiOutputAttributionMissing => 1.3,
            ViolationType::UnauthorizedFineTuning => 1.8,
            // ── Design & typography ──
            ViolationType::TypefaceDesignInfringement => 1.8,
            ViolationType::IconPackPiracy => 1.6,
            ViolationType::UiKitLicenseBreach => 1.4,
            ViolationType::ThreeDModelLicenseViolation => 1.6,
            ViolationType::CadDrawingUnauthorized => 1.5,
            // ── Document & publication ──
            ViolationType::EbookRedistribution => 1.7,
            ViolationType::DocumentTemplatePiracy => 1.4,
            ViolationType::CourseMaterialRedistribution => 1.5,
            // ── Firmware & embedded ──
            ViolationType::FirmwareGplViolation => 2.2,
            ViolationType::RomImagePiracy => 2.0,
            ViolationType::EmbeddedFontUnlicensed => 1.5,
            // Unknown / custom
            _ => 1.0,
        };

        score += (base as f64 * multiplier * v.confidence) as u32;
    }

    score.min(100)
}

/// Determine risk level from score
pub fn risk_level_from_score(score: u32) -> super::RiskLevel {
    match score {
        0 => super::RiskLevel::Clean,
        1..=20 => super::RiskLevel::Low,
        21..=50 => super::RiskLevel::Medium,
        51..=80 => super::RiskLevel::High,
        _ => super::RiskLevel::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::{DetectionResult, Violation};
    use std::path::PathBuf;

    fn make_violation(vtype: ViolationType, severity: Severity, confidence: f64) -> Violation {
        Violation {
            violation_type: vtype,
            severity,
            confidence,
            description: "test violation".into(),
            files: vec![PathBuf::from("test.rs")],
            licenses: vec![],
            obligations_violated: vec![],
            evidence: vec![],
            claimed_license: None,
            actual_license: None,
        }
    }

    fn default_config() -> SkeraConfig {
        SkeraConfig {
            network_service: false,
            commercial: false,
            ..Default::default()
        }
    }
    fn make_result(violations: Vec<Violation>) -> DetectionResult {
        DetectionResult {
            violations,
            total_violations: 0,
            files_scanned: 0,
            dependencies_analyzed: 0,
            dependency_licenses: Default::default(),
            duration_ms: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        }
    }

    #[test]
    fn test_clean_codebase_scores_zero() {
        let result = make_result(vec![]);
        assert_eq!(calculate_risk_score(&result, &default_config()), 0);
    }

    #[test]
    fn test_single_low_violation_scores_low() {
        let result = make_result(vec![make_violation(
                ViolationType::MissingAttribution, Severity::Low, 0.9
            )]);
        let score = calculate_risk_score(&result, &default_config());
        assert!(score > 0 && score <= 5, "Low severity should score 1-5, got {}", score);
    }

    #[test]
    fn test_critical_copyleft_in_commercial_scores_high() {
        let config = SkeraConfig {
            network_service: false,
            commercial: true,
            ..Default::default()
        };
        let result = make_result(vec![make_violation(
                ViolationType::CopyleftInProprietary, Severity::Critical, 0.95
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 2.5 (commercial GPL) * 0.95 confidence = 71
        assert!(score >= 50, "Critical copyleft in commercial should be high risk, got {}", score);
    }

    #[test]
    fn test_agpl_in_saas_gets_max_multiplier() {
        let config = SkeraConfig {
            network_service: true,
            commercial: true,
            ..Default::default()
        };
        let result = make_result(vec![make_violation(
                ViolationType::NetworkServiceWithoutDisclosure, Severity::Critical, 1.0
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 3.5 (AGPL in SaaS) * 1.0 = 100 (capped)
        assert_eq!(score, 100, "AGPL in SaaS should max out the score");
    }

    #[test]
    fn test_score_capped_at_100() {
        let config = SkeraConfig {
            network_service: true,
            commercial: true,
            ..Default::default()
        };
        let result = make_result(vec![
                make_violation(ViolationType::NetworkServiceWithoutDisclosure, Severity::Critical, 1.0),
                make_violation(ViolationType::CopyleftInProprietary, Severity::Critical, 1.0),
                make_violation(ViolationType::LicenseLaundering, Severity::Critical, 1.0),
            ]);
        let score = calculate_risk_score(&result, &config);
        assert_eq!(score, 100, "Score should be capped at 100");
    }

    #[test]
    fn test_confidence_modulates_score() {
        let config = default_config();
        let high_conf = make_result(vec![make_violation(ViolationType::StrippedLicense, Severity::High, 0.95)]);
        let low_conf = make_result(vec![make_violation(ViolationType::StrippedLicense, Severity::High, 0.3)]);
        let s_high = calculate_risk_score(&high_conf, &config);
        let s_low = calculate_risk_score(&low_conf, &config);
        assert!(s_high > s_low, "Higher confidence should produce higher score: {} vs {}", s_high, s_low);
    }

    #[test]
    fn test_risk_level_from_score() {
        assert!(matches!(risk_level_from_score(0), super::super::RiskLevel::Clean));
        assert!(matches!(risk_level_from_score(10), super::super::RiskLevel::Low));
        assert!(matches!(risk_level_from_score(30), super::super::RiskLevel::Medium));
        assert!(matches!(risk_level_from_score(60), super::super::RiskLevel::High));
        assert!(matches!(risk_level_from_score(90), super::super::RiskLevel::Critical));
    }

    #[test]
    fn test_patent_violations_score_high() {
        let config = default_config();
        let result = make_result(vec![make_violation(
                ViolationType::PatentTermination, Severity::Critical, 0.85
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 2.0 (patent) * 0.85 = 51
        assert!(score >= 40, "Patent termination should be high risk, got {}", score);
    }

    #[test]
    fn test_drm_circumvention_scores_highest() {
        let config = default_config();
        let result = make_result(vec![make_violation(
                ViolationType::DrmCircumvention, Severity::Critical, 1.0
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 3.0 (DRM = DMCA §1201 federal offense) * 1.0 = 90
        assert!(score >= 85, "DRM circumvention should be near-max risk, got {}", score);
    }

    #[test]
    fn test_ai_model_license_violation_scores_critical() {
        let config = default_config();
        let result = make_result(vec![make_violation(
                ViolationType::AiModelLicenseViolation, Severity::Critical, 0.9
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 2.5 * 0.9 = 67
        assert!(score >= 60, "AI model license violation should be critical risk, got {}", score);
    }

    #[test]
    fn test_firmware_gpl_violation() {
        let config = default_config();
        let result = make_result(vec![make_violation(
                ViolationType::FirmwareGplViolation, Severity::Critical, 1.0
            )]);
        let score = calculate_risk_score(&result, &config);
        // Critical (30) * 2.2 * 1.0 = 66
        assert!(score >= 60, "Firmware GPL violation should be high risk, got {}", score);
    }
}
