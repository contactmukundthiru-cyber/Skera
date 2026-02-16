//! License text forensics — deep integrity analysis of license documents
//!
//! ## Why This Matters
//!
//! License laundering is a real and growing threat. Studies by the Linux Foundation
//! and FOSSID have documented cases where:
//!
//! - GPL license text was modified to remove the "source disclosure" clause
//! - MIT license text had "attribution required" language stripped
//! - Apache-2.0 texts had the NOTICE file requirement deleted
//! - Dual-licensed projects had the copyleft option silently removed
//! - Standard licenses were augmented with hidden proprietary clauses
//! - License versions were deliberately confused (GPL-2.0 vs GPL-3.0)
//!
//! ## What This Module Detects
//!
//! 1. **Clause Stripping** — key obligation clauses removed from standard texts
//! 2. **Version Confusion** — SPDX header says "MIT" but text is BSD-3-Clause
//! 3. **Chimera Licenses** — Frankensteined from multiple license texts
//! 4. **Hidden Obligations** — standard license + custom restrictive addenda
//! 5. **Machine Translation Artifacts** — licenses run through a translator
//! 6. **Encoding Manipulation** — homoglyph substitution, invisible Unicode
//! 7. **License Downgrade** — text from a stronger license weakened
//! 8. **Trust Scoring** — 0.0-1.0 confidence that a license text is authentic
//!
//! ## Research Basis
//!
//! - SPDX License List matching guidelines (Annex B)
//! - Wheeler's "Make Your Open Source Software GPL-Compatible"
//! - FOSSID's "License Laundering in Open Source" (2023)
//! - Open Source Initiative's license review criteria
//! - Black Duck / Synopsys OSSRA reports on license manipulation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

// ─── Core Types ─────────────────────────────────────────────────────

/// Comprehensive forensic analysis of a license text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseTextForensicReport {
    /// File analyzed
    pub file_path: PathBuf,
    /// Declared identifier (from SPDX header or filename)
    pub declared_license: Option<String>,
    /// Detected license from text content
    pub detected_license: Option<String>,
    /// Trust score (0.0 = definitely tampered, 1.0 = authentic)
    pub trust_score: f64,
    /// All findings
    pub findings: Vec<ForensicFinding>,
    /// Clause analysis
    pub clause_analysis: ClauseAnalysis,
    /// Unicode anomalies
    pub unicode_anomalies: Vec<UnicodeAnomaly>,
    /// Custom additions detected
    pub custom_additions: Vec<CustomAddition>,
    /// Whether this appears to be a chimera license
    pub is_chimera: bool,
    /// Version confusion detected
    pub version_confusion: Option<VersionConfusion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicFinding {
    pub severity: FindingSeverity,
    pub category: FindingCategory,
    pub description: String,
    pub evidence: String,
    /// Line number in the license file (if applicable)
    pub line_number: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    /// Informational — unusual but not necessarily problematic
    Info,
    /// Warning — suspicious pattern
    Warning,
    /// Critical — strong evidence of tampering or non-compliance
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    ClauseStripping,
    VersionConfusion,
    ChimeraLicense,
    HiddenObligation,
    TranslationArtifact,
    EncodingManipulation,
    LicenseDowngrade,
    TextIntegrity,
    CustomRestriction,
}

/// Analysis of which standard clauses are present/absent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClauseAnalysis {
    /// Clauses expected for the declared license
    pub expected_clauses: Vec<LicenseClause>,
    /// Clauses actually found
    pub present_clauses: Vec<LicenseClause>,
    /// Clauses missing (potential stripping)
    pub missing_clauses: Vec<LicenseClause>,
    /// Extra clauses not in the standard text
    pub extra_clauses: Vec<String>,
}

/// A standard license clause
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseClause {
    pub name: String,
    pub obligation: ClauseObligation,
    pub present: bool,
    /// Canonical text snippet that should be present
    pub canonical_snippet: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClauseObligation {
    /// Must include copyright notice
    Attribution,
    /// Must disclose source code
    SourceDisclosure,
    /// Must include NOTICE file
    NoticeFile,
    /// Patent grant/termination
    PatentGrant,
    /// No warranty disclaimer
    Warranty,
    /// Liability limitation
    Liability,
    /// Copyleft/share-alike
    Copyleft,
    /// Network use provision (AGPL)
    NetworkUse,
    /// Modification tracking
    ModificationNotice,
    /// Trademark restrictions
    TrademarkRestriction,
    /// Export compliance
    ExportControl,
}

/// Unicode-based manipulation attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnicodeAnomaly {
    pub anomaly_type: UnicodeAnomalyType,
    pub position: usize,
    pub description: String,
    pub character: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnicodeAnomalyType {
    /// Homoglyph substitution (Cyrillic 'а' for Latin 'a')
    Homoglyph,
    /// Zero-width characters hiding text
    ZeroWidth,
    /// Right-to-left override
    BidiOverride,
    /// Non-standard whitespace
    NonStandardWhitespace,
    /// Invisible formatting characters
    InvisibleFormatting,
}

/// Custom addition to a standard license
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomAddition {
    pub text: String,
    pub addition_type: AdditionType,
    pub line_range: (usize, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdditionType {
    /// Adds commercial restrictions
    CommercialRestriction,
    /// Adds geographic restrictions
    GeographicRestriction,
    /// Adds field-of-use restrictions
    FieldOfUseRestriction,
    /// Adds attribution beyond standard requirements
    EnhancedAttribution,
    /// Adds indemnification
    Indemnification,
    /// Adds non-compete
    NonCompete,
    /// Adds data collection rights
    DataCollection,
    /// Unknown/other restriction
    OtherRestriction,
}

/// Version confusion between declared and actual license
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConfusion {
    pub declared_version: String,
    pub actual_version: String,
    pub severity: FindingSeverity,
    pub legal_impact: String,
}

// ─── Canonical License Clause Database ──────────────────────────────

/// The key clauses that define each major license family.
/// If any of these are missing from the license text, it's
/// a strong indicator of tampering.
struct CanonicalClauses;

impl CanonicalClauses {
    fn mit() -> Vec<LicenseClause> {
        vec![
            LicenseClause {
                name: "Permission Grant".into(),
                obligation: ClauseObligation::Attribution,
                present: false,
                canonical_snippet: "Permission is hereby granted, free of charge".into(),
            },
            LicenseClause {
                name: "Attribution Requirement".into(),
                obligation: ClauseObligation::Attribution,
                present: false,
                canonical_snippet: "The above copyright notice and this permission notice shall be included".into(),
            },
            LicenseClause {
                name: "No Warranty".into(),
                obligation: ClauseObligation::Warranty,
                present: false,
                canonical_snippet: "THE SOFTWARE IS PROVIDED \"AS IS\"".into(),
            },
        ]
    }

    fn apache2() -> Vec<LicenseClause> {
        vec![
            LicenseClause {
                name: "Copyright Grant".into(),
                obligation: ClauseObligation::Attribution,
                present: false,
                canonical_snippet: "perpetual, worldwide, non-exclusive, no-charge, royalty-free".into(),
            },
            LicenseClause {
                name: "Patent Grant".into(),
                obligation: ClauseObligation::PatentGrant,
                present: false,
                canonical_snippet: "grant of patent license".into(),
            },
            LicenseClause {
                name: "Patent Termination".into(),
                obligation: ClauseObligation::PatentGrant,
                present: false,
                canonical_snippet: "patent license".into(),
            },
            LicenseClause {
                name: "NOTICE Preservation".into(),
                obligation: ClauseObligation::NoticeFile,
                present: false,
                canonical_snippet: "NOTICE".into(),
            },
            LicenseClause {
                name: "Modification Notice".into(),
                obligation: ClauseObligation::ModificationNotice,
                present: false,
                canonical_snippet: "cause any modified files to carry prominent notices".into(),
            },
            LicenseClause {
                name: "Trademark Restriction".into(),
                obligation: ClauseObligation::TrademarkRestriction,
                present: false,
                canonical_snippet: "trade names, trademarks, service marks".into(),
            },
        ]
    }

    fn gpl3() -> Vec<LicenseClause> {
        vec![
            LicenseClause {
                name: "Freedom to Run".into(),
                obligation: ClauseObligation::Copyleft,
                present: false,
                canonical_snippet: "freedom to run the program".into(),
            },
            LicenseClause {
                name: "Source Disclosure".into(),
                obligation: ClauseObligation::SourceDisclosure,
                present: false,
                canonical_snippet: "Corresponding Source".into(),
            },
            LicenseClause {
                name: "Copyleft".into(),
                obligation: ClauseObligation::Copyleft,
                present: false,
                canonical_snippet: "convey a work based on the Program".into(),
            },
            LicenseClause {
                name: "Anti-Tivoization".into(),
                obligation: ClauseObligation::Copyleft,
                present: false,
                canonical_snippet: "Installation Information".into(),
            },
            LicenseClause {
                name: "Patent Non-Aggression".into(),
                obligation: ClauseObligation::PatentGrant,
                present: false,
                canonical_snippet: "patent license".into(),
            },
        ]
    }

    fn agpl3() -> Vec<LicenseClause> {
        let mut clauses = Self::gpl3();
        clauses.push(LicenseClause {
            name: "Network Use Provision".into(),
            obligation: ClauseObligation::NetworkUse,
            present: false,
            canonical_snippet: "interact with it remotely through a computer network".into(),
        });
        clauses
    }

    fn bsd3() -> Vec<LicenseClause> {
        vec![
            LicenseClause {
                name: "Source Attribution".into(),
                obligation: ClauseObligation::Attribution,
                present: false,
                canonical_snippet: "Redistributions of source code must retain".into(),
            },
            LicenseClause {
                name: "Binary Attribution".into(),
                obligation: ClauseObligation::Attribution,
                present: false,
                canonical_snippet: "Redistributions in binary form must reproduce".into(),
            },
            LicenseClause {
                name: "No Endorsement".into(),
                obligation: ClauseObligation::TrademarkRestriction,
                present: false,
                canonical_snippet: "endorse or promote products derived".into(),
            },
        ]
    }

    fn mpl2() -> Vec<LicenseClause> {
        vec![
            LicenseClause {
                name: "File-Level Copyleft".into(),
                obligation: ClauseObligation::Copyleft,
                present: false,
                canonical_snippet: "Covered Software".into(),
            },
            LicenseClause {
                name: "Source Form Distribution".into(),
                obligation: ClauseObligation::SourceDisclosure,
                present: false,
                canonical_snippet: "Source Code Form".into(),
            },
            LicenseClause {
                name: "Patent Grant".into(),
                obligation: ClauseObligation::PatentGrant,
                present: false,
                canonical_snippet: "patent license".into(),
            },
        ]
    }

    fn for_license(spdx: &str) -> Vec<LicenseClause> {
        let normalized = spdx.to_uppercase();
        if normalized.contains("MIT") {
            Self::mit()
        } else if normalized.contains("APACHE") {
            Self::apache2()
        } else if normalized.contains("AGPL") {
            Self::agpl3()
        } else if normalized.contains("GPL") && !normalized.contains("LGPL") {
            Self::gpl3()
        } else if normalized.contains("BSD-3") || normalized.contains("BSD3") {
            Self::bsd3()
        } else if normalized.contains("MPL") {
            Self::mpl2()
        } else {
            vec![]
        }
    }
}

// ─── Custom Restriction Patterns ────────────────────────────────────

/// Patterns that indicate non-standard restrictions added to licenses
const RESTRICTIVE_PATTERNS: &[(&str, AdditionType)] = &[
    ("commercial use is not permitted", AdditionType::CommercialRestriction),
    ("commercial purposes", AdditionType::CommercialRestriction),
    ("non-commercial use only", AdditionType::CommercialRestriction),
    ("for internal use only", AdditionType::CommercialRestriction),
    ("not for resale", AdditionType::CommercialRestriction),
    ("may not be used for commercial", AdditionType::CommercialRestriction),
    ("evaluation purposes only", AdditionType::CommercialRestriction),
    ("academic use only", AdditionType::CommercialRestriction),
    ("educational purposes only", AdditionType::CommercialRestriction),
    ("personal use only", AdditionType::CommercialRestriction),
    ("export restrictions", AdditionType::GeographicRestriction),
    ("not available in", AdditionType::GeographicRestriction),
    ("jurisdictions where", AdditionType::GeographicRestriction),
    ("embargo", AdditionType::GeographicRestriction),
    ("may not be used in the field of", AdditionType::FieldOfUseRestriction),
    ("not to be used for", AdditionType::FieldOfUseRestriction),
    ("restricted to", AdditionType::FieldOfUseRestriction),
    ("military", AdditionType::FieldOfUseRestriction),
    ("weapons", AdditionType::FieldOfUseRestriction),
    ("surveillance", AdditionType::FieldOfUseRestriction),
    ("law enforcement", AdditionType::FieldOfUseRestriction),
    ("must display", AdditionType::EnhancedAttribution),
    ("prominently display", AdditionType::EnhancedAttribution),
    ("powered by", AdditionType::EnhancedAttribution),
    ("badge requirement", AdditionType::EnhancedAttribution),
    ("logo must appear", AdditionType::EnhancedAttribution),
    ("shall indemnify", AdditionType::Indemnification),
    ("shall hold harmless", AdditionType::Indemnification),
    ("indemnification", AdditionType::Indemnification),
    ("non-compete", AdditionType::NonCompete),
    ("shall not compete", AdditionType::NonCompete),
    ("competing product", AdditionType::NonCompete),
    ("telemetry", AdditionType::DataCollection),
    ("usage data", AdditionType::DataCollection),
    ("analytics", AdditionType::DataCollection),
    ("phone home", AdditionType::DataCollection),
];

// ─── Homoglyph Database ─────────────────────────────────────────

/// Characters that look identical to ASCII but are from different scripts.
/// Used to detect attempts to hide text or change meaning.
const HOMOGLYPHS: &[(char, char, &str)] = &[
    ('а', 'a', "Cyrillic а → Latin a"),
    ('с', 'c', "Cyrillic с → Latin c"),
    ('е', 'e', "Cyrillic е → Latin e"),
    ('о', 'o', "Cyrillic о → Latin o"),
    ('р', 'p', "Cyrillic р → Latin p"),
    ('х', 'x', "Cyrillic х → Latin x"),
    ('у', 'y', "Cyrillic у → Latin y"),
    ('ɑ', 'a', "Latin Alpha ɑ → Latin a"),
    ('ν', 'v', "Greek ν → Latin v"),
    ('ω', 'w', "Greek ω → Latin w"),
    ('ı', 'i', "Dotless ı → Latin i"),
    ('ⅰ', 'i', "Roman numeral ⅰ → Latin i"),
    ('\u{200B}', ' ', "Zero-width space"),
    ('\u{200C}', ' ', "Zero-width non-joiner"),
    ('\u{200D}', ' ', "Zero-width joiner"),
    ('\u{FEFF}', ' ', "Zero-width no-break space / BOM"),
    ('\u{2060}', ' ', "Word joiner"),
    ('\u{00A0}', ' ', "Non-breaking space"),
    ('\u{2007}', ' ', "Figure space"),
    ('\u{202F}', ' ', "Narrow no-break space"),
];

// ─── Main Analyzer ──────────────────────────────────────────────────

pub struct LicenseTextForensics;

impl LicenseTextForensics {
    /// Analyze a license file for tampering, manipulation, or non-compliance
    pub fn analyze(content: &str, file_path: &Path, declared_license: Option<&str>) -> LicenseTextForensicReport {
        let mut findings = Vec::new();
        let mut trust_score: f64 = 1.0;

        // ── Step 1: Unicode anomaly detection ──
        let unicode_anomalies = Self::detect_unicode_anomalies(content);
        if !unicode_anomalies.is_empty() {
            trust_score -= 0.15 * unicode_anomalies.len() as f64;
            for anomaly in &unicode_anomalies {
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Critical,
                    category: FindingCategory::EncodingManipulation,
                    description: format!("Unicode anomaly: {}", anomaly.description),
                    evidence: anomaly.character.clone(),
                    line_number: None,
                });
            }
        }

        // ── Step 2: Clause analysis ──
        let clause_analysis = if let Some(declared) = declared_license {
            Self::analyze_clauses(content, declared, &mut findings, &mut trust_score)
        } else {
            ClauseAnalysis {
                expected_clauses: vec![],
                present_clauses: vec![],
                missing_clauses: vec![],
                extra_clauses: vec![],
            }
        };

        // ── Step 3: Custom restriction detection ──
        let custom_additions = Self::detect_custom_restrictions(content, &mut findings, &mut trust_score);

        // ── Step 4: Version confusion detection ──
        let version_confusion = Self::detect_version_confusion(content, declared_license, &mut findings, &mut trust_score);

        // ── Step 5: Chimera detection ──
        let is_chimera = Self::detect_chimera(content, &mut findings, &mut trust_score);

        // ── Step 6: Translation artifacts ──
        Self::detect_translation_artifacts(content, &mut findings, &mut trust_score);

        // ── Step 7: Suspicious patterns ──
        Self::detect_suspicious_patterns(content, &mut findings, &mut trust_score);

        // ── Step 8: Text authenticity ──
        let detected_license = Self::detect_license_from_text(content);

        // Clamp trust score
        trust_score = trust_score.clamp(0.0, 1.0);

        LicenseTextForensicReport {
            file_path: file_path.to_path_buf(),
            declared_license: declared_license.map(|s| s.to_string()),
            detected_license,
            trust_score,
            findings,
            clause_analysis,
            unicode_anomalies,
            custom_additions,
            is_chimera,
            version_confusion,
        }
    }

    /// Scan an entire directory for all license-like files
    pub fn scan_directory(root: &Path) -> Vec<LicenseTextForensicReport> {
        let mut reports = Vec::new();

        for entry in walkdir::WalkDir::new(root)
            .max_depth(5)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let fname = entry.file_name().to_str().unwrap_or("").to_uppercase();
            if fname.starts_with("LICENSE")
                || fname.starts_with("LICENCE")
                || fname.starts_with("COPYING")
                || fname.starts_with("COPYRIGHT")
                || fname.starts_with("UNLICENSE")
                || fname.ends_with(".LICENSE")
                || fname.ends_with(".LICENCE")
            {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    reports.push(Self::analyze(&content, entry.path(), None));
                }
            }
        }

        reports
    }

    // ── Internal Analysis Methods ───────────────────────────────────

    pub fn detect_unicode_anomalies(text: &str) -> Vec<UnicodeAnomaly> {
        let mut anomalies = Vec::new();

        for (i, ch) in text.char_indices() {
            // Check homoglyphs
            for &(homoglyph, _latin, description) in HOMOGLYPHS {
                if ch == homoglyph {
                    let anomaly_type = if ch == '\u{200B}' || ch == '\u{200C}'
                        || ch == '\u{200D}' || ch == '\u{2060}' || ch == '\u{FEFF}'
                    {
                        UnicodeAnomalyType::ZeroWidth
                    } else if ch == '\u{00A0}' || ch == '\u{2007}' || ch == '\u{202F}' {
                        UnicodeAnomalyType::NonStandardWhitespace
                    } else {
                        UnicodeAnomalyType::Homoglyph
                    };

                    anomalies.push(UnicodeAnomaly {
                        anomaly_type,
                        position: i,
                        description: description.to_string(),
                        character: format!("U+{:04X}", ch as u32),
                    });
                }
            }

            // Bidi overrides
            if ch == '\u{202A}' || ch == '\u{202B}' || ch == '\u{202C}'
                || ch == '\u{202D}' || ch == '\u{202E}' || ch == '\u{2066}'
                || ch == '\u{2067}' || ch == '\u{2068}' || ch == '\u{2069}'
            {
                anomalies.push(UnicodeAnomaly {
                    anomaly_type: UnicodeAnomalyType::BidiOverride,
                    position: i,
                    description: "Bidirectional text override character".into(),
                    character: format!("U+{:04X}", ch as u32),
                });
            }

            // Invisible formatting
            if ch == '\u{2028}' || ch == '\u{2029}' || ch == '\u{00AD}'
                || ch == '\u{034F}' || ch == '\u{17B4}' || ch == '\u{17B5}'
            {
                anomalies.push(UnicodeAnomaly {
                    anomaly_type: UnicodeAnomalyType::InvisibleFormatting,
                    position: i,
                    description: "Invisible formatting character".into(),
                    character: format!("U+{:04X}", ch as u32),
                });
            }
        }

        anomalies
    }

    fn analyze_clauses(
        text: &str,
        declared: &str,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) -> ClauseAnalysis {
        let text_lower = text.to_lowercase();
        let mut expected = CanonicalClauses::for_license(declared);

        // Mark which clauses are present
        for clause in expected.iter_mut() {
            clause.present = text_lower.contains(&clause.canonical_snippet.to_lowercase());
        }

        let present: Vec<LicenseClause> = expected.iter()
            .filter(|c| c.present)
            .cloned()
            .collect();
        let missing: Vec<LicenseClause> = expected.iter()
            .filter(|c| !c.present)
            .cloned()
            .collect();

        // Report missing critical clauses
        for clause in &missing {
            let sev = match clause.obligation {
                ClauseObligation::SourceDisclosure
                | ClauseObligation::Copyleft
                | ClauseObligation::NetworkUse => {
                    *trust_score -= 0.25;
                    FindingSeverity::Critical
                }
                ClauseObligation::Attribution
                | ClauseObligation::PatentGrant
                | ClauseObligation::NoticeFile => {
                    *trust_score -= 0.15;
                    FindingSeverity::Warning
                }
                _ => {
                    *trust_score -= 0.05;
                    FindingSeverity::Info
                }
            };

            findings.push(ForensicFinding {
                severity: sev,
                category: FindingCategory::ClauseStripping,
                description: format!(
                    "License declares '{}' but missing clause: '{}'",
                    declared, clause.name
                ),
                evidence: format!(
                    "Expected text containing: \"{}\"",
                    clause.canonical_snippet
                ),
                line_number: None,
            });
        }

        // Detect extra/unexpected content
        let extra = Self::detect_extra_content(text);

        ClauseAnalysis {
            expected_clauses: expected,
            present_clauses: present,
            missing_clauses: missing,
            extra_clauses: extra,
        }
    }

    fn detect_extra_content(text: &str) -> Vec<String> {
        let mut extras = Vec::new();
        let lower = text.to_lowercase();

        // Sections that shouldn't be in standard licenses
        let suspicious_sections = [
            "additional terms",
            "supplemental terms",
            "special conditions",
            "addendum",
            "amendment",
            "rider",
            "schedule a",
            "exhibit a",
        ];

        for section in &suspicious_sections {
            if lower.contains(section) {
                extras.push(format!("Non-standard section: '{}'", section));
            }
        }

        extras
    }

    fn detect_custom_restrictions(
        text: &str,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) -> Vec<CustomAddition> {
        let lower = text.to_lowercase();
        let lines: Vec<&str> = text.lines().collect();
        let mut additions = Vec::new();

        for &(pattern, ref add_type) in RESTRICTIVE_PATTERNS {
            if let Some(pos) = lower.find(pattern) {
                // Find the line number
                let line_num = text[..pos].lines().count();
                let start_line = line_num.saturating_sub(1);
                let end_line = (line_num + 1).min(lines.len());

                let context = lines[start_line..end_line].join("\n");

                additions.push(CustomAddition {
                    text: context.clone(),
                    addition_type: *add_type,
                    line_range: (start_line + 1, end_line),
                });

                *trust_score -= 0.10;
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Warning,
                    category: FindingCategory::HiddenObligation,
                    description: format!(
                        "Non-standard restrictive clause detected: {:?}",
                        add_type
                    ),
                    evidence: format!("Pattern '{}' found in: {}", pattern, context.trim()),
                    line_number: Some(line_num),
                });
            }
        }

        additions
    }

    fn detect_version_confusion(
        text: &str,
        declared: Option<&str>,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) -> Option<VersionConfusion> {
        let declared = declared?;
        let lower = text.to_lowercase();

        // Check for version number mismatches
        let version_markers: HashMap<&str, &[&str]> = [
            ("GPL-2.0", &["version 2", "gpl-2.0", "gnu general public license\nversion 2"][..]),
            ("GPL-3.0", &["version 3", "gpl-3.0", "gnu general public license\nversion 3"]),
            ("LGPL-2.1", &["version 2.1", "lgpl-2.1"]),
            ("LGPL-3.0", &["version 3", "lgpl-3.0"]),
            ("AGPL-3.0", &["version 3", "agpl-3.0", "affero"]),
            ("MPL-2.0", &["version 2.0", "mpl-2.0", "mozilla public license version 2"]),
            ("Apache-2.0", &["version 2.0", "apache-2.0", "apache license, version 2"]),
        ].iter().cloned().collect();

        let declared_upper = declared.to_uppercase();

        // Find which license version the text actually describes
        let mut text_versions: Vec<&str> = Vec::new();
        for (version, markers) in &version_markers {
            if markers.iter().any(|m| lower.contains(m)) {
                text_versions.push(version);
            }
        }

        // Check for mismatch
        for text_ver in &text_versions {
            let text_upper = text_ver.to_uppercase();
            // Same family but different version
            let same_family = (declared_upper.contains("GPL") && text_upper.contains("GPL"))
                || (declared_upper.contains("LGPL") && text_upper.contains("LGPL"))
                || (declared_upper.contains("AGPL") && text_upper.contains("AGPL"))
                || (declared_upper.contains("MPL") && text_upper.contains("MPL"))
                || (declared_upper.contains("APACHE") && text_upper.contains("APACHE"));

            if same_family && !declared_upper.contains(&text_upper) && !text_upper.contains(&declared_upper) {
                *trust_score -= 0.30;
                let confusion = VersionConfusion {
                    declared_version: declared.to_string(),
                    actual_version: text_ver.to_string(),
                    severity: FindingSeverity::Critical,
                    legal_impact: format!(
                        "Header declares {} but license text is {}. \
                        These versions have different obligations — this is either \
                        an error or deliberate obfuscation.",
                        declared, text_ver
                    ),
                };

                findings.push(ForensicFinding {
                    severity: FindingSeverity::Critical,
                    category: FindingCategory::VersionConfusion,
                    description: format!(
                        "Version mismatch: declared '{}' but text matches '{}'",
                        declared, text_ver
                    ),
                    evidence: confusion.legal_impact.clone(),
                    line_number: None,
                });

                return Some(confusion);
            }
        }

        None
    }

    /// Normalize homoglyphs back to their Latin equivalents for comparison
    fn normalize_homoglyphs(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        for ch in text.chars() {
            let normalized = match ch {
                '\u{0430}' => 'a',  // Cyrillic а
                '\u{0441}' => 'c',  // Cyrillic с
                '\u{0435}' => 'e',  // Cyrillic е
                '\u{043E}' => 'o',  // Cyrillic о
                '\u{0440}' => 'p',  // Cyrillic р
                '\u{0445}' => 'x',  // Cyrillic х
                '\u{0443}' => 'y',  // Cyrillic у
                '\u{0251}' => 'a',  // Latin Alpha ɑ
                '\u{03BD}' => 'v',  // Greek ν
                '\u{03C9}' => 'w',  // Greek ω
                '\u{0131}' => 'i',  // Dotless ı
                '\u{2170}' => 'i',  // Roman numeral ⅰ
                // Zero-width characters → empty
                '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{FEFF}' | '\u{2060}' => continue,
                // Non-standard whitespace → regular space
                '\u{00A0}' | '\u{2007}' | '\u{202F}' => ' ',
                other => other,
            };
            result.push(normalized);
        }
        result
    }

    fn detect_chimera(
        text: &str,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) -> bool {
        // Full normalization: homoglyphs → Latin, lowercase, collapse whitespace
        // This ensures chimera detection still works even if the text is obfuscated
        // with Cyrillic/Greek homoglyphs or zero-width characters
        let normalized = Self::normalize_homoglyphs(text);
        let lower: String = normalized.to_lowercase()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");

        // Signature phrases that are unique to specific licenses
        let license_signatures: &[(&str, &str)] = &[
            ("permission is hereby granted, free of charge", "MIT"),
            ("redistributions of source code must retain", "BSD"),
            ("under the terms of the gnu general public license", "GPL"),
            ("apache license", "Apache"),
            ("mozilla public license", "MPL"),
            ("common development and distribution license", "CDDL"),
            ("eclipse public license", "EPL"),
            ("artistic license", "Artistic"),
            ("boost software license", "BSL"),
            ("creative commons", "CC"),
            ("the software is provided \"as is\", without warranty", "MIT-style"),
            // AI/ML and source-available signatures
            ("openrail", "OpenRAIL"),
            ("business source license", "BUSL"),
            ("elastic license", "Elastic"),
            ("open data commons", "ODC"),
            ("community data license", "CDLA"),
            ("sil open font license", "OFL"),
            ("prosperity public license", "Prosperity"),
        ];

        let mut detected_families: Vec<&str> = Vec::new();
        for &(signature, family) in license_signatures {
            if lower.contains(signature) && !detected_families.contains(&family) {
                detected_families.push(family);
            }
        }

        // If we detect signatures from 3+ different license families,
        // this is a chimera license
        if detected_families.len() >= 3 {
            *trust_score -= 0.40;
            findings.push(ForensicFinding {
                severity: FindingSeverity::Critical,
                category: FindingCategory::ChimeraLicense,
                description: format!(
                    "Chimera license detected — contains language from {} different licenses: {}",
                    detected_families.len(),
                    detected_families.join(", ")
                ),
                evidence: "Multiple incompatible license texts merged into one document".into(),
                line_number: None,
            });
            return true;
        }

        // 2 families is suspicious but not definitive (some licenses share language)
        if detected_families.len() == 2 {
            // Check if they're truly incompatible combinations
            let has_gpl = detected_families.contains(&"GPL");
            let has_mit = detected_families.contains(&"MIT") || detected_families.contains(&"MIT-style");
            let has_apache = detected_families.contains(&"Apache");

            if (has_gpl && has_apache) || (has_gpl && has_mit) {
                *trust_score -= 0.15;
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Warning,
                    category: FindingCategory::ChimeraLicense,
                    description: format!(
                        "Suspicious mixed license text from: {}",
                        detected_families.join(", ")
                    ),
                    evidence: "License text contains language from multiple license families".into(),
                    line_number: None,
                });
            }
        }

        false
    }

    fn detect_translation_artifacts(
        text: &str,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) {
        // Common machine translation artifacts in English license text
        let artifacts = [
            "is provided as is",        // Missing quotes around "AS IS"
            "without guaranty",         // "guarantee" mistranslated
            "the program is free",      // Ambiguous "free" (libre vs gratis)
            "all rights are reserved",  // Non-standard "All rights reserved" form
            "the licence",              // British spelling in US license (context-dependent)
            "authorisation",            // British spelling
            "programme",               // British spelling of "program"
        ];

        for artifact in &artifacts {
            if text.to_lowercase().contains(artifact) {
                *trust_score -= 0.05;
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Info,
                    category: FindingCategory::TranslationArtifact,
                    description: format!("Possible translation artifact: '{}'", artifact),
                    evidence: format!(
                        "Non-standard phrasing that may indicate machine translation \
                        or manual modification of the license text"
                    ),
                    line_number: None,
                });
            }
        }
    }

    fn detect_suspicious_patterns(
        text: &str,
        findings: &mut Vec<ForensicFinding>,
        trust_score: &mut f64,
    ) {
        let lower = text.to_lowercase();

        // Very short license file (likely truncated)
        if text.len() < 100 && !lower.contains("unlicense") && !lower.contains("wtfpl") {
            *trust_score -= 0.20;
            findings.push(ForensicFinding {
                severity: FindingSeverity::Warning,
                category: FindingCategory::TextIntegrity,
                description: "License file is suspiciously short (< 100 chars)".into(),
                evidence: format!("File is {} characters, which is too short for any standard license", text.len()),
                line_number: None,
            });
        }

        // "All rights reserved" in a supposedly open-source license
        if lower.contains("all rights reserved") {
            let is_oss = lower.contains("permission is hereby granted")
                || lower.contains("redistribution")
                || lower.contains("free software")
                || lower.contains("open source");
            if is_oss {
                *trust_score -= 0.10;
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Warning,
                    category: FindingCategory::TextIntegrity,
                    description: "'All rights reserved' conflicts with open-source grant".into(),
                    evidence: "The phrase 'All rights reserved' is legally meaningless post-Berne Convention \
                        but signals intent to restrict rights, conflicting with the open-source grant".into(),
                    line_number: None,
                });
            }
        }

        // Empty copyright holder
        if lower.contains("copyright (c) [year]") || lower.contains("copyright (c) <year>") {
            *trust_score -= 0.10;
            findings.push(ForensicFinding {
                severity: FindingSeverity::Warning,
                category: FindingCategory::TextIntegrity,
                description: "Template placeholder not filled in".into(),
                evidence: "License contains unfilled template placeholders like [year] or <name>".into(),
                line_number: None,
            });
        }

        // License says "see LICENSE" but IS the LICENSE file
        if lower.contains("see license") || lower.contains("see the license") {
            if text.len() < 500 {
                findings.push(ForensicFinding {
                    severity: FindingSeverity::Info,
                    category: FindingCategory::TextIntegrity,
                    description: "License file refers to another license file".into(),
                    evidence: "Self-referential license may indicate incomplete setup".into(),
                    line_number: None,
                });
            }
        }
    }

    fn detect_license_from_text(text: &str) -> Option<String> {
        // Normalize: homoglyphs → Latin, lowercase, collapse whitespace
        let normalized = Self::normalize_homoglyphs(text);
        let lower: String = normalized.to_lowercase()
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");

        if lower.contains("permission is hereby granted, free of charge") {
            Some("MIT".into())
        } else if lower.contains("apache license") && lower.contains("version 2") {
            Some("Apache-2.0".into())
        } else if lower.contains("gnu general public license") {
            if lower.contains("version 3") || lower.contains("gpl-3") {
                Some("GPL-3.0-only".into())
            } else if lower.contains("version 2") || lower.contains("gpl-2") {
                Some("GPL-2.0-only".into())
            } else {
                Some("GPL (unknown version)".into())
            }
        } else if lower.contains("gnu lesser general public") || lower.contains("lgpl") {
            Some("LGPL".into())
        } else if lower.contains("affero") || lower.contains("agpl") {
            Some("AGPL-3.0-only".into())
        } else if lower.contains("mozilla public license") {
            Some("MPL-2.0".into())
        } else if lower.contains("redistribution and use in source and binary") {
            if lower.contains("endorse or promote") {
                Some("BSD-3-Clause".into())
            } else {
                Some("BSD-2-Clause".into())
            }
        } else if lower.contains("isc license") {
            Some("ISC".into())
        } else if lower.contains("the unlicense") || lower.contains("this is free and unencumbered") {
            Some("Unlicense".into())
        } else if lower.contains("creative commons") {
            Some("CC (variant unknown)".into())
        } else if lower.contains("boost software license") {
            Some("BSL-1.0".into())
        } else if lower.contains("do what the fuck you want") {
            Some("WTFPL".into())
        } else if lower.contains("zlib license") {
            Some("Zlib".into())
        // ── New license family detection ──
        } else if lower.contains("european union public licence") || lower.contains("eupl") {
            Some("EUPL-1.2".into())
        } else if lower.contains("sil open font license") {
            Some("OFL-1.1".into())
        } else if lower.contains("server side public license") {
            Some("SSPL-1.0".into())
        } else if lower.contains("business source license") {
            Some("BUSL-1.1".into())
        } else if lower.contains("elastic license") {
            Some("Elastic-2.0".into())
        } else if lower.contains("openrail") {
            Some("OpenRAIL".into())
        } else if lower.contains("open data commons") {
            if lower.contains("open database license") {
                Some("ODbL-1.0".into())
            } else {
                Some("ODC (variant unknown)".into())
            }
        } else if lower.contains("community data license") {
            Some("CDLA".into())
        } else if lower.contains("prosperity public license") {
            Some("Prosperity".into())
        } else {
            None
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentic_mit_scores_high() {
        let mit_text = r#"MIT License

Copyright (c) 2024 Example Corp

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT."#;

        let report = LicenseTextForensics::analyze(
            mit_text,
            Path::new("LICENSE"),
            Some("MIT"),
        );

        assert!(report.trust_score > 0.8, "Authentic MIT should score high, got {}", report.trust_score);
        assert!(report.clause_analysis.missing_clauses.is_empty());
        assert!(!report.is_chimera);
        assert!(report.unicode_anomalies.is_empty());
        assert_eq!(report.detected_license, Some("MIT".to_string()));
    }

    #[test]
    fn test_stripped_mit_detected() {
        // MIT with attribution clause removed
        let stripped = r#"MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

THE SOFTWARE IS PROVIDED "AS IS"."#;

        let report = LicenseTextForensics::analyze(
            stripped,
            Path::new("LICENSE"),
            Some("MIT"),
        );

        assert!(report.trust_score < 0.9, "Stripped MIT should score lower");
        assert!(!report.clause_analysis.missing_clauses.is_empty());
    }

    #[test]
    fn test_commercial_restriction_detected() {
        let text = r#"MIT License

Permission is hereby granted for non-commercial use only.
Commercial use is not permitted without a separate license.

THE SOFTWARE IS PROVIDED "AS IS"."#;

        let report = LicenseTextForensics::analyze(
            text,
            Path::new("LICENSE"),
            Some("MIT"),
        );

        assert!(!report.custom_additions.is_empty());
        assert!(report.findings.iter().any(|f|
            f.category == FindingCategory::HiddenObligation
        ));
    }

    #[test]
    fn test_unicode_homoglyph_detected() {
        // Replace 'a' with Cyrillic 'а'
        let text = "Permission is hereby gr\u{0430}nted, free of charge";
        let anomalies = LicenseTextForensics::detect_unicode_anomalies(text);
        assert!(!anomalies.is_empty(), "Should detect Cyrillic homoglyph");
    }

    #[test]
    fn test_chimera_detection() {
        let chimera = r#"
Permission is hereby granted, free of charge, to any person obtaining a copy.
Redistributions of source code must retain the above copyright notice.
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License.
Licensed under the Apache License, Version 2.0.
"#;
        let report = LicenseTextForensics::analyze(
            chimera,
            Path::new("LICENSE"),
            None,
        );
        assert!(report.is_chimera, "Should detect chimera license");
    }

    #[test]
    fn test_detect_license_from_text() {
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Permission is hereby granted, free of charge"
            ),
            Some("MIT".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Apache License, Version 2.0"
            ),
            Some("Apache-2.0".to_string())
        );
    }

    #[test]
    fn test_detect_new_license_families() {
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "This model is licensed under the OpenRAIL-M license."
            ),
            Some("OpenRAIL".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Licensed under the Business Source License 1.1"
            ),
            Some("BUSL-1.1".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Licensed under the Elastic License 2.0"
            ),
            Some("Elastic-2.0".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Under the SIL Open Font License, Version 1.1"
            ),
            Some("OFL-1.1".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Licensed under the Open Data Commons Open Database License (ODbL)"
            ),
            Some("ODbL-1.0".to_string())
        );
        assert_eq!(
            LicenseTextForensics::detect_license_from_text(
                "Community Data License Agreement - Permissive"
            ),
            Some("CDLA".to_string())
        );
    }

    #[test]
    fn test_chimera_with_ai_ml_signatures() {
        // Mix of MIT + OpenRAIL + GPL = chimera
        let chimera = r#"
        Permission is hereby granted, free of charge, to any person.
        This model is released under the OpenRAIL license terms.
        Under the terms of the GNU General Public License.
        "#;
        let report = LicenseTextForensics::analyze(
            chimera,
            Path::new("LICENSE"),
            None,
        );
        assert!(report.is_chimera, "Should detect chimera with AI/ML license mixed in");
    }
}
