//! Detection engine — violation taxonomy and detection pipeline
//!
//! Defines every possible license violation type and provides the
//! detection pipeline that scans code for them.

pub mod header_detector;
pub mod snippet_matcher;
pub mod attribution_checker;
pub mod contamination;
pub mod js_bundle_forensics;
pub mod js_analysis;
pub mod js_signatures;
pub mod similarity;
pub mod license_identifier;
pub mod structural_fingerprint;
pub mod yara_scanner;
pub mod asset_fingerprint;
pub mod media_forensics;
pub mod deobfuscation;
pub mod advanced_deobfuscation;
pub mod scancode_bridge;
pub mod code_embeddings;
pub mod cross_language;
pub mod license_text_forensics;
pub mod supply_chain_audit;
pub mod web_asset_scanner;
pub mod creative_commons;
pub mod data_rights;
pub mod wasm_forensics;

pub use header_detector::HeaderDetector;
pub use snippet_matcher::SnippetMatcher;
pub use attribution_checker::AttributionChecker;
pub use contamination::ContaminationTracer;
pub use js_bundle_forensics::JsBundleScanner;

use crate::license::{LicenseId, LicenseObligation};
use crate::evidence::EvidenceItem;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ─── Violation Taxonomy ─────────────────────────────────────────────

/// Every type of license violation the engine can detect
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ViolationType {
    // ── Attribution violations ──
    /// Missing copyright notice (MIT, BSD, Apache require this)
    MissingAttribution,
    /// Missing NOTICE file (Apache 2.0 requires this)
    MissingNoticeFile,
    /// Copyright notice present but incomplete or incorrect
    IncorrectAttribution,
    /// SPDX header missing from source files
    MissingSpdxHeader,

    // ── Copyleft violations ──
    /// GPL/AGPL code used in proprietary/closed-source project
    CopyleftInProprietary,
    /// Source code not disclosed as required by GPL
    MissingSourceDisclosure,
    /// AGPL code used in network service without source disclosure
    NetworkServiceWithoutDisclosure,
    /// Modified GPL files without change documentation
    MissingChangeDocumentation,

    // ── Linking violations ──
    /// LGPL library statically linked (must be dynamic)
    LgplStaticLinking,
    /// GPL library dynamically linked into non-GPL binary
    GplDynamicLinking,

    // ── Compatibility violations ──
    /// Two incompatible licenses in the dependency graph
    IncompatibleLicenses,
    /// GPL-2.0 mixed with Apache-2.0 (patent clause conflict)
    Gpl2ApacheConflict,
    /// GPL-2.0 mixed with GPL-3.0 (not forward-compatible without "or later")
    Gpl2Gpl3Conflict,

    // ── License laundering ──
    /// License was changed from copyleft to permissive without authorization
    LicenseLaundering,
    /// License text modified to remove obligations
    LicenseTextTampering,
    /// Dual-license used under wrong tier (e.g., SSPL code used as if MIT)
    DualLicenseMisuse,
    /// Typosquatted license identifier (e.g., "MlT" instead of "MIT")
    TyposquattedLicense,
    /// Vendored code with license stripped
    StrippedLicense,

    // ── Commercial misuse ──
    /// CC-NC content used in commercial project  
    NonCommercialInCommercial,
    /// CC-ND content modified
    NoDerivativesModified,
    /// Academic/educational-only license used commercially
    AcademicLicenseMisuse,
    /// Commercial use of a non-commercial license (Prosperity, PolyForm, etc.)
    CommercialUseViolation,

    // ── Code provenance ──
    /// Code fingerprint matches GPL project but claims different license
    CodeFingerprintMismatch,
    /// Binary contains symbols from GPL library
    BinaryContainsGplSymbols,
    /// Decompiled binary matches known GPL source
    DecompiledCodeMatch,
    /// Obfuscated code that matches known open-source patterns
    ObfuscatedMatch,

    // ── Patent violations ──
    /// Apache 2.0 patent termination clause triggered
    PatentTermination,
    /// Using patented algorithms without license grant
    MissingPatentGrant,

    // ── Metadata mismatch ──
    /// package.json license doesn't match actual LICENSE file
    ManifestLicenseMismatch,
    /// README claims different license than LICENSE file
    ReadmeLicenseMismatch,
    /// Multiple conflicting license files in same package
    ConflictingLicenseFiles,

    // ── Supply chain risks ──
    /// Dependency name is suspiciously close to a popular package
    Typosquatting,
    /// Dependency is known-deprecated or known-compromised
    DeprecatedDependency,
    /// Dependency uses imprecise version pinning (e.g., "^" or "*")
    VersionPinningRisk,
    /// Scoped package wraps the name of a popular unscoped package
    ScopeConfusion,
    /// Lockfile is stale or missing
    LockfileStaleness,

    // ── Web asset copyright ──
    /// Commercial font used without an apparent license
    CommercialFontUsage,
    /// CDN library loaded with no license verification
    UnlicensedCdnLibrary,
    /// Script loaded without Subresource Integrity hash
    MissingSriHash,
    /// Font Awesome Pro icons used (requires paid license)
    FontAwesomeProUsage,
    /// Embedded asset resembles stock photography
    StockPhotoUsage,

    // ── Creative Commons compliance ──
    /// CC-NC content used in a commercial context
    CcNonCommercialViolation,
    /// CC-ND content modified
    CcNoDerivativesViolation,
    /// CC-BY attribution missing or incomplete
    CcMissingAttribution,
    /// CC-SA version incompatibility
    CcShareAlikeIncompatible,

    // ── Data rights ──
    /// Files contain unprotected PII (GDPR/CCPA)
    PiiExposure,
    /// Secrets (API keys, tokens) committed to repository
    ExposedSecrets,
    /// Database/dataset used without license compliance
    UnlicensedData,
    /// Geodata used without attribution (e.g., OSM ODbL)
    UnlicensedGeodata,
    /// ML dataset used outside its license terms
    MlDatasetViolation,

    // ── License text forensics ──
    /// License is a chimera (pasted-together fragments from different licenses)
    ChimeraLicense,
    /// License text contains Unicode homoglyphs (potential tampering)
    HomoglyphTampering,

    // ── Digital media rights ──
    /// Audio track used without proper license (sync, mechanical, master)
    UnlicensedAudioUsage,
    /// Video content redistributed without license or exceeding terms
    UnlicensedVideoUsage,
    /// Image used beyond the scope of its license (e.g., editorial-only in commercial)
    ImageLicenseScopeExceeded,
    /// Stock media watermark detected (unlicensed preview asset in production)
    StockWatermarkDetected,
    /// Audio sample used without clearance (sampling violation)
    UnlicensedSampling,
    /// DRM protection circumvented or markers removed (DMCA §1201)
    DrmCircumvention,
    /// Remix/derivative of copyrighted audio/video without license
    UnlicensedRemix,

    // ── AI & model rights ──
    /// AI model weights redistributed in violation of license (Llama, Mistral, etc.)
    AiModelLicenseViolation,
    /// Training data contains copyrighted material without license
    TrainingDataContamination,
    /// OpenRAIL use restriction violated (e.g., harmful use, military)
    OpenRailRestrictionBreach,
    /// Model output used without required attribution
    AiOutputAttributionMissing,
    /// Model fine-tuned on restricted data without authorization
    UnauthorizedFineTuning,

    // ── Design & typography ──
    /// Typeface design rights violated (font file redistributed without license)
    TypefaceDesignInfringement,
    /// Icon pack used without license (FontAwesome Pro, Streamline, etc.)
    IconPackPiracy,
    /// UI kit or design system used without license (Figma, Sketch kits)
    UiKitLicenseBreach,
    /// 3D model used without proper license
    ThreeDModelLicenseViolation,
    /// CAD drawing or blueprint used without authorization
    CadDrawingUnauthorized,

    // ── Document & publication ──
    /// Ebook or publication content redistributed without authorization
    EbookRedistribution,
    /// Document template used beyond license scope (Canva Pro, etc.)
    DocumentTemplatePiracy,
    /// Course material redistributed without permission
    CourseMaterialRedistribution,

    // ── Firmware & embedded ──
    /// Firmware contains GPL code without source disclosure
    FirmwareGplViolation,
    /// ROM image redistributed without authorization
    RomImagePiracy,
    /// Embedded system contains font files without licensing
    EmbeddedFontUnlicensed,

    // ── Binary forensics ──
    /// Opaque binary (WASM, shared lib) with embedded deps but no license docs
    OpaqueDistribution,

    /// Custom/unknown violation
    Custom(String),
}

impl std::fmt::Display for ViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{}", s),
            other => {
                let debug = format!("{:?}", other);
                // Convert CamelCase to kebab-case for human-friendly output
                let mut result = String::with_capacity(debug.len() + 4);
                for (i, ch) in debug.chars().enumerate() {
                    if ch.is_uppercase() && i > 0 {
                        result.push('-');
                    }
                    result.push(ch.to_ascii_lowercase());
                }
                write!(f, "{}", result)
            }
        }
    }
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {} ({:.0}% confidence)", self.severity, self.description, self.confidence * 100.0)
    }
}

impl ViolationType {
    /// Get the severity of this violation type
    pub fn default_severity(&self) -> Severity {
        match self {
            // Critical — immediate legal exposure
            Self::CopyleftInProprietary
            | Self::LicenseLaundering
            | Self::LicenseTextTampering
            | Self::CodeFingerprintMismatch
            | Self::BinaryContainsGplSymbols
            | Self::DecompiledCodeMatch
            | Self::ObfuscatedMatch
            | Self::CommercialUseViolation
            | Self::Typosquatting
            | Self::ExposedSecrets
            | Self::ChimeraLicense
            | Self::HomoglyphTampering
            | Self::DrmCircumvention
            | Self::AiModelLicenseViolation
            | Self::FirmwareGplViolation
            | Self::TrainingDataContamination
            | Self::OpaqueDistribution => Severity::Critical,

            // High — active violation, enforcement likely
            Self::MissingSourceDisclosure
            | Self::NetworkServiceWithoutDisclosure
            | Self::IncompatibleLicenses
            | Self::LgplStaticLinking
            | Self::GplDynamicLinking
            | Self::DualLicenseMisuse
            | Self::StrippedLicense
            | Self::NonCommercialInCommercial
            | Self::DeprecatedDependency
            | Self::ScopeConfusion
            | Self::CommercialFontUsage
            | Self::FontAwesomeProUsage
            | Self::CcNonCommercialViolation
            | Self::CcNoDerivativesViolation
            | Self::PiiExposure
            | Self::MlDatasetViolation
            | Self::UnlicensedAudioUsage
            | Self::UnlicensedVideoUsage
            | Self::StockWatermarkDetected
            | Self::UnlicensedSampling
            | Self::TypefaceDesignInfringement
            | Self::IconPackPiracy
            | Self::OpenRailRestrictionBreach
            | Self::EbookRedistribution
            | Self::RomImagePiracy
            | Self::ThreeDModelLicenseViolation => Severity::High,

            // Medium — violation but enforcement varies
            Self::MissingAttribution
            | Self::MissingNoticeFile
            | Self::Gpl2ApacheConflict
            | Self::Gpl2Gpl3Conflict
            | Self::MissingChangeDocumentation
            | Self::PatentTermination
            | Self::ManifestLicenseMismatch
            | Self::VersionPinningRisk
            | Self::UnlicensedCdnLibrary
            | Self::StockPhotoUsage
            | Self::CcMissingAttribution
            | Self::CcShareAlikeIncompatible
            | Self::UnlicensedData
            | Self::UnlicensedGeodata
            | Self::ImageLicenseScopeExceeded
            | Self::UnlicensedRemix
            | Self::AiOutputAttributionMissing
            | Self::UnauthorizedFineTuning
            | Self::UiKitLicenseBreach
            | Self::CadDrawingUnauthorized
            | Self::DocumentTemplatePiracy
            | Self::CourseMaterialRedistribution
            | Self::EmbeddedFontUnlicensed => Severity::Medium,

            // Low — best practice violation
            Self::IncorrectAttribution
            | Self::MissingSpdxHeader
            | Self::ReadmeLicenseMismatch
            | Self::ConflictingLicenseFiles
            | Self::TyposquattedLicense
            | Self::NoDerivativesModified
            | Self::AcademicLicenseMisuse
            | Self::MissingPatentGrant
            | Self::LockfileStaleness
            | Self::MissingSriHash => Severity::Low,

            Self::Custom(_) => Severity::Medium,
        }
    }

    /// Human-readable category
    pub fn category(&self) -> &str {
        match self {
            Self::MissingAttribution
            | Self::MissingNoticeFile
            | Self::IncorrectAttribution
            | Self::MissingSpdxHeader => "Attribution",

            Self::CopyleftInProprietary
            | Self::MissingSourceDisclosure
            | Self::NetworkServiceWithoutDisclosure
            | Self::MissingChangeDocumentation => "Copyleft Compliance",

            Self::LgplStaticLinking | Self::GplDynamicLinking => "Linking",

            Self::IncompatibleLicenses
            | Self::Gpl2ApacheConflict
            | Self::Gpl2Gpl3Conflict => "Compatibility",

            Self::LicenseLaundering
            | Self::LicenseTextTampering
            | Self::DualLicenseMisuse
            | Self::TyposquattedLicense
            | Self::StrippedLicense => "License Laundering",

            Self::NonCommercialInCommercial
            | Self::NoDerivativesModified
            | Self::AcademicLicenseMisuse
            | Self::CommercialUseViolation => "Commercial Misuse",

            Self::CodeFingerprintMismatch
            | Self::BinaryContainsGplSymbols
            | Self::DecompiledCodeMatch
            | Self::ObfuscatedMatch => "Code Provenance",

            Self::PatentTermination | Self::MissingPatentGrant => "Patent",

            Self::ManifestLicenseMismatch
            | Self::ReadmeLicenseMismatch
            | Self::ConflictingLicenseFiles => "Metadata Mismatch",

            Self::Typosquatting
            | Self::DeprecatedDependency
            | Self::VersionPinningRisk
            | Self::ScopeConfusion
            | Self::LockfileStaleness => "Supply Chain",

            Self::CommercialFontUsage
            | Self::UnlicensedCdnLibrary
            | Self::MissingSriHash
            | Self::FontAwesomeProUsage
            | Self::StockPhotoUsage => "Web Assets",

            Self::CcNonCommercialViolation
            | Self::CcNoDerivativesViolation
            | Self::CcMissingAttribution
            | Self::CcShareAlikeIncompatible => "Creative Commons",

            Self::PiiExposure
            | Self::ExposedSecrets
            | Self::UnlicensedData
            | Self::UnlicensedGeodata
            | Self::MlDatasetViolation => "Data Rights",

            Self::ChimeraLicense
            | Self::HomoglyphTampering => "License Forensics",

            Self::UnlicensedAudioUsage
            | Self::UnlicensedVideoUsage
            | Self::ImageLicenseScopeExceeded
            | Self::StockWatermarkDetected
            | Self::UnlicensedSampling
            | Self::DrmCircumvention
            | Self::UnlicensedRemix => "Digital Media Rights",

            Self::AiModelLicenseViolation
            | Self::TrainingDataContamination
            | Self::OpenRailRestrictionBreach
            | Self::AiOutputAttributionMissing
            | Self::UnauthorizedFineTuning => "AI & Model Rights",

            Self::TypefaceDesignInfringement
            | Self::IconPackPiracy
            | Self::UiKitLicenseBreach
            | Self::ThreeDModelLicenseViolation
            | Self::CadDrawingUnauthorized => "Design & Typography",

            Self::EbookRedistribution
            | Self::DocumentTemplatePiracy
            | Self::CourseMaterialRedistribution => "Document & Publication",

            Self::FirmwareGplViolation
            | Self::RomImagePiracy
            | Self::EmbeddedFontUnlicensed
            | Self::OpaqueDistribution => "Firmware & Embedded",

            Self::Custom(_) => "Other",
        }
    }
}

// ─── Severity ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    /// Best practice, unlikely to be enforced
    Low,
    /// Real violation with moderate risk
    Medium,
    /// Serious violation, enforcement likely
    High,
    /// Immediate legal exposure, litigation risk
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Detection Results ──────────────────────────────────────────────

/// A single detected violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// What type of violation
    pub violation_type: ViolationType,
    /// Severity (may override default based on context)
    pub severity: Severity,
    /// Confidence score 0.0 - 1.0
    pub confidence: f64,
    /// Human-readable description
    pub description: String,
    /// Which file(s) are involved
    pub files: Vec<PathBuf>,
    /// Which license(s) are involved
    pub licenses: Vec<LicenseId>,
    /// Which obligation(s) are being violated
    pub obligations_violated: Vec<LicenseObligation>,
    /// Supporting evidence
    pub evidence: Vec<EvidenceItem>,
    /// For license laundering: what the code actually is vs what it claims
    pub claimed_license: Option<LicenseId>,
    pub actual_license: Option<LicenseId>,
}

/// Complete detection result from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionResult {
    /// All violations found
    pub violations: Vec<Violation>,
    /// Total violations found (including suppressed)
    pub total_violations: usize,
    /// Total files scanned
    pub files_scanned: usize,
    /// Total dependencies analyzed
    pub dependencies_analyzed: usize,
    /// Dependency name → license mapping (for SBOM generation)
    pub dependency_licenses: BTreeMap<String, LicenseId>,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
    /// Summary counts by severity
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl DetectionResult {
    pub fn new() -> Self {
        Self {
            violations: Vec::new(),
            total_violations: 0,
            files_scanned: 0,
            dependencies_analyzed: 0,
            dependency_licenses: BTreeMap::new(),
            duration_ms: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
        }
    }

    pub fn add_violation(&mut self, violation: Violation) {
        match violation.severity {
            Severity::Critical => self.critical_count += 1,
            Severity::High => self.high_count += 1,
            Severity::Medium => self.medium_count += 1,
            Severity::Low => self.low_count += 1,
        }
        self.total_violations += 1;
        self.violations.push(violation);
    }

    /// Record a dependency's license for SBOM generation
    pub fn record_dependency(&mut self, name: String, license: LicenseId) {
        self.dependency_licenses.insert(name, license);
    }

    pub fn total_violations(&self) -> usize {
        self.violations.len()
    }

    pub fn has_critical(&self) -> bool {
        self.critical_count > 0
    }

    /// Filter violations by minimum severity
    pub fn above_severity(&self, min: Severity) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.severity >= min)
            .collect()
    }

    /// Filter violations by category
    pub fn by_category(&self, category: &str) -> Vec<&Violation> {
        self.violations
            .iter()
            .filter(|v| v.violation_type.category() == category)
            .collect()
    }

    /// Get unique violation types found
    pub fn violation_types(&self) -> Vec<&ViolationType> {
        let mut types: Vec<_> = self.violations.iter().map(|v| &v.violation_type).collect();
        types.dedup();
        types
    }
}

impl Default for DetectionResult {
    fn default() -> Self {
        Self::new()
    }
}
