//! License type system and SPDX database
//!
//! Contains the full taxonomy of open-source and proprietary license types,
//! their obligations, and a compatibility matrix for detecting conflicts.

pub mod spdx;
pub mod compatibility;
pub mod classifier;
pub mod spdx_expression;

pub use spdx::*;
pub use compatibility::*;
pub use classifier::*;

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── License Identity ───────────────────────────────────────────────

/// Canonical license identifier (SPDX where possible)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LicenseId(pub String);

impl LicenseId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is a copyleft/viral license
    pub fn is_copyleft(&self) -> bool {
        self.family().is_copyleft()
    }

    /// Check if this is a permissive license
    pub fn is_permissive(&self) -> bool {
        self.family().is_permissive()
    }

    /// Get the license family
    pub fn family(&self) -> LicenseFamily {
        LicenseFamily::from_spdx(&self.0)
    }
}

impl fmt::Display for LicenseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── License Families ───────────────────────────────────────────────

/// Broad license classification families
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LicenseFamily {
    /// GPL — strong copyleft, derivative works must use same license
    StrongCopyleft,
    /// LGPL, MPL, EPL — weak copyleft, modified files must be disclosed
    WeakCopyleft,
    /// AGPL, SSPL — copyleft that propagates across network boundaries
    NetworkCopyleft,
    /// MIT, BSD, ISC, Zlib — permissive, few obligations beyond attribution
    Permissive,
    /// Apache 2.0 — permissive with patent grant
    PermissivePatent,
    /// CC-BY, CC-BY-SA — creative commons for non-code assets
    CreativeCommons,
    /// CC-NC, CC-ND — creative commons with commercial/derivative restrictions
    CreativeCommonsRestricted,
    /// Unlicense, CC0, WTFPL — public domain equivalent
    PublicDomain,
    /// Proprietary, commercial, all-rights-reserved
    Proprietary,
    /// AI/ML model licenses (OpenRAIL, Llama Community License, RAIL-M)
    AiMl,
    /// Open data licenses (ODbL, CDLA-Permissive, ODC-By)
    DataOpen,
    /// Source-available but not open-source (BSL, Elastic, PolyForm)
    SourceAvailable,
    /// Media/creative asset license (Royalty-Free, Rights-Managed, Editorial-Only)
    MediaAsset,
    /// Custom/unknown license text
    Custom,
    /// No license detected (implicit all-rights-reserved in most jurisdictions)
    None,
}

impl LicenseFamily {
    pub fn is_copyleft(&self) -> bool {
        matches!(
            self,
            Self::StrongCopyleft | Self::WeakCopyleft | Self::NetworkCopyleft
        )
    }

    pub fn is_permissive(&self) -> bool {
        matches!(
            self,
            Self::Permissive | Self::PermissivePatent | Self::PublicDomain
                | Self::DataOpen
        )
    }

    pub fn is_restrictive(&self) -> bool {
        matches!(
            self,
            Self::Proprietary | Self::CreativeCommonsRestricted | Self::NetworkCopyleft
                | Self::SourceAvailable
        )
    }

    /// Determine family from SPDX identifier
    pub fn from_spdx(spdx: &str) -> Self {
        // Normalize: strip -only/-or-later/+ suffixes for family classification
        let upper = spdx.to_uppercase();
        let normalized = upper
            .trim_end_matches("-ONLY")
            .trim_end_matches("-OR-LATER")
            .trim_end_matches('+');

        match normalized {
            // ── Strong copyleft ──
            s if s.starts_with("GPL-") || s == "GPL" => Self::StrongCopyleft,
            s if s.starts_with("CECILL-2") => Self::StrongCopyleft,
            s if s == "SLEEPYCAT" || s == "RPL-1.5" => Self::StrongCopyleft,

            // ── Network copyleft (true AGPL/SSPL-like: requires source disclosure
            //    when users interact over a network) ──
            s if s.starts_with("AGPL-") || s == "AGPL" => Self::NetworkCopyleft,
            s if s.contains("SSPL") => Self::NetworkCopyleft,
            s if s.starts_with("OSL-") || s == "OSL" => Self::NetworkCopyleft,

            // ── Weak copyleft ──
            s if s.starts_with("LGPL-") || s == "LGPL" => Self::WeakCopyleft,
            s if s.starts_with("MPL-") || s == "MPL" => Self::WeakCopyleft,
            s if s.starts_with("EPL-") || s == "EPL" => Self::WeakCopyleft,
            s if s.starts_with("EUPL-") || s == "EUPL" => Self::WeakCopyleft,
            s if s.starts_with("CDDL-") || s == "CDDL" => Self::WeakCopyleft,
            s if s.starts_with("CPL-") || s == "CPL" => Self::WeakCopyleft,
            s if s.starts_with("CECILL-") => Self::WeakCopyleft,
            s if s == "CPAL-1.0" || s == "CPAL" => Self::WeakCopyleft,
            s if s.starts_with("APSL-") => Self::WeakCopyleft,

            // ── Source-available / non-compete / commercial restriction ──
            // These are NOT copyleft — they restrict USE, not derivative distribution
            s if s.contains("COMMONS-CLAUSE") => Self::SourceAvailable,
            s if s.contains("ELASTIC") && s.contains("2.0") => Self::SourceAvailable,
            s if s.contains("POLYFORM") => Self::SourceAvailable,
            s if s.contains("FSL-") || s == "FSL" => Self::SourceAvailable,
            s if s.contains("PROSPERITY") => Self::SourceAvailable,
            // BSL = Business Source License (source-available, converts to open after delay)
            // BUT BSL-1.0 = Boost Software License (permissive!) — check Boost FIRST
            s if s.starts_with("BSL-1") => Self::Permissive, // Boost
            s if s.contains("BSL") || s.contains("BUSL") => Self::SourceAvailable,

            // ── Permissive with patent grant ──
            s if s.starts_with("APACHE-") || s == "APACHE" => Self::PermissivePatent,

            // ── Permissive ──
            s if s.starts_with("MIT") => Self::Permissive,
            s if s.starts_with("BSD-") || s == "BSD" => Self::Permissive,
            s if s == "ISC" => Self::Permissive,
            s if s == "ZLIB" || s == "LIBPNG" || s == "LIBPNG-2.0" => Self::Permissive,
            s if s.starts_with("ARTISTIC-") => Self::Permissive,
            s if s == "POSTGRESQL" => Self::Permissive,
            s if s == "NCSA" => Self::Permissive,
            s if s == "CURL" || s == "JSON" => Self::Permissive,
            s if s == "X11" || s == "HPND" => Self::Permissive,
            s if s == "PSF-2.0" || s.starts_with("PYTHON-") => Self::Permissive,
            s if s == "UNICODE-DFS-2016" || s == "UNICODE-TOU" => Self::Permissive,
            s if s.starts_with("OFL-") || s.starts_with("SIL-OFL") => Self::Permissive,

            // ── Creative Commons ──
            s if s.contains("CC-BY-SA") => Self::CreativeCommons,
            s if s.contains("CC-BY-NC") || s.contains("CC-BY-ND") => {
                Self::CreativeCommonsRestricted
            }
            s if s.contains("CC-BY") && !s.contains("NC") && !s.contains("ND") => {
                Self::CreativeCommons
            }

            // ── Public domain ──
            s if s == "UNLICENSE" || s == "CC0-1.0" || s == "CC0" => Self::PublicDomain,
            s if s == "WTFPL" || s == "0BSD" => Self::PublicDomain,
            s if s == "BLESSING" || s == "SAX-PD" => Self::PublicDomain,

            // ── Proprietary ──
            s if s.contains("PROPRIETARY") || s.contains("ALL-RIGHTS-RESERVED") => {
                Self::Proprietary
            }
            // No license detected — default copyright applies
            s if s == "NONE" || s == "NOASSERTION" || s.is_empty() => Self::None,

            // ── AI / ML model licenses ──
            s if s.contains("OPENRAIL") || s.contains("RAIL-M") => Self::AiMl,
            s if s.contains("LLAMA") || s.contains("LLAMA-COMMUNITY") => Self::AiMl,
            s if s.contains("BIGSCIENCE") || s.contains("BLOOM") => Self::AiMl,
            s if s.contains("BIGCODE") || s.contains("STARCODER") => Self::AiMl,
            s if s.contains("CREATIVEML") || s.contains("STABLE-DIFFUSION") => Self::AiMl,
            s if s.contains("DEEPSEEK") || s.contains("QWEN") || s.contains("GEMMA") => Self::AiMl,
            s if s.contains("OPT-175B") || s.contains("FALCON") => Self::AiMl,

            // ── Open data licenses ──
            s if s.contains("ODBL") || s == "ODB-1.0" => Self::DataOpen,
            s if s.starts_with("CDLA-") || s == "CDLA" => Self::DataOpen,
            s if s.starts_with("ODC-BY") || s.starts_with("ODC-PDDL") => Self::DataOpen,
            s if s == "PDDL-1.0" || s == "PDDL" => Self::DataOpen,
            s if s.starts_with("DL-DE-") => Self::DataOpen, // German data license
            s if s.starts_with("OGL-") => Self::DataOpen,   // UK Open Govt License

            // ── Media/creative asset licenses ──
            s if s.contains("RF") && s.contains("LICENSE") => Self::MediaAsset,
            s if s.contains("RIGHTS-MANAGED") || s.contains("EDITORIAL") => Self::MediaAsset,
            s if s.contains("SYNC-LICENSE") || s.contains("SYNC") => Self::MediaAsset,

            _ => Self::Custom,
        }
    }
}

impl fmt::Display for LicenseFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StrongCopyleft => write!(f, "Strong Copyleft (GPL/AGPL)"),
            Self::WeakCopyleft => write!(f, "Weak Copyleft (LGPL/MPL)"),
            Self::NetworkCopyleft => write!(f, "Network/Service Copyleft (SSPL)"),
            Self::Permissive => write!(f, "Permissive (MIT/BSD/ISC)"),
            Self::PermissivePatent => write!(f, "Permissive + Patent (Apache)"),
            Self::CreativeCommons => write!(f, "Creative Commons"),
            Self::CreativeCommonsRestricted => write!(f, "Creative Commons (Restricted)"),
            Self::PublicDomain => write!(f, "Public Domain"),
            Self::Proprietary => write!(f, "Proprietary"),
            Self::AiMl => write!(f, "AI/ML Model License"),
            Self::DataOpen => write!(f, "Open Data License"),
            Self::SourceAvailable => write!(f, "Source-Available (Restricted)"),
            Self::MediaAsset => write!(f, "Media/Creative Asset License"),
            Self::Custom => write!(f, "Custom/Unknown"),
            Self::None => write!(f, "No License"),
        }
    }
}

// ─── License Obligations ────────────────────────────────────────────

/// What a license requires you to do
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LicenseObligation {
    /// Must include copyright notice and license text
    Attribution,
    /// Must provide source code of the entire derivative work
    SourceDisclosure,
    /// Must provide source code only for modified files
    ModifiedFileDisclosure,
    /// Must use the same license for derivative works
    Copyleft,
    /// Must provide source code for network-accessible services
    NetworkDisclosure,
    /// Must include a NOTICE file
    NoticeFile,
    /// Patent grant — grants patent rights to users
    PatentGrant,
    /// Cannot use for commercial purposes
    NonCommercial,
    /// Cannot create derivative works
    NoDerivatives,
    /// Must share under same or compatible license
    ShareAlike,
    /// Must preserve specific copyright headers
    HeaderPreservation,
    /// Must state significant changes made to the code
    ChangeDocumentation,
    /// Cannot use project name/trademarks for endorsement
    TrademarkRestriction,
    /// Must dynamically link (not statically) to preserve LGPL
    DynamicLinkingRequired,
}

/// Full license descriptor with all metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseDescriptor {
    pub id: LicenseId,
    pub name: String,
    pub family: LicenseFamily,
    pub obligations: Vec<LicenseObligation>,
    /// Is this license OSI-approved?
    pub osi_approved: bool,
    /// Is this license FSF-approved as free?
    pub fsf_free: bool,
    /// Can this be used in proprietary/closed-source projects?
    pub proprietary_compatible: bool,
    /// SPDX expression patterns that match this license
    pub spdx_patterns: Vec<String>,
    /// Common file name patterns (LICENSE, COPYING, etc.)
    pub file_patterns: Vec<String>,
    /// Header patterns found in source code
    pub header_patterns: Vec<String>,
}

// ─── License Database ───────────────────────────────────────────────

/// In-memory license database with all known licenses
pub struct LicenseDb {
    licenses: Vec<LicenseDescriptor>,
}

impl LicenseDb {
    /// Build the complete license database
    pub fn new() -> Self {
        Self {
            licenses: Self::build_database(),
        }
    }

    /// Look up a license by SPDX ID
    pub fn lookup(&self, id: &str) -> Option<&LicenseDescriptor> {
        let upper = id.to_uppercase();
        self.licenses.iter().find(|l| l.id.0.to_uppercase() == upper)
    }

    /// Look up a license by family
    pub fn by_family(&self, family: LicenseFamily) -> Vec<&LicenseDescriptor> {
        self.licenses.iter().filter(|l| l.family == family).collect()
    }

    /// Get all known licenses
    pub fn all(&self) -> &[LicenseDescriptor] {
        &self.licenses
    }

    /// Get obligations for a license
    pub fn obligations(&self, id: &str) -> Vec<LicenseObligation> {
        self.lookup(id)
            .map(|l| l.obligations.clone())
            .unwrap_or_default()
    }

    fn build_database() -> Vec<LicenseDescriptor> {
        vec![
            // ── Strong Copyleft ──
            LicenseDescriptor {
                id: LicenseId::new("GPL-2.0-only"),
                name: "GNU General Public License v2.0".into(),
                family: LicenseFamily::StrongCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::SourceDisclosure,
                    LicenseObligation::Copyleft,
                    LicenseObligation::ChangeDocumentation,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: false,
                spdx_patterns: vec!["GPL-2.0-only".into(), "GPL-2.0".into(), "GPLv2".into()],
                file_patterns: vec!["COPYING".into(), "LICENSE".into()],
                header_patterns: vec![
                    "GNU General Public License".into(),
                    "version 2".into(),
                    "Free Software Foundation".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("GPL-3.0-only"),
                name: "GNU General Public License v3.0".into(),
                family: LicenseFamily::StrongCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::SourceDisclosure,
                    LicenseObligation::Copyleft,
                    LicenseObligation::ChangeDocumentation,
                    LicenseObligation::PatentGrant,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: false,
                spdx_patterns: vec!["GPL-3.0-only".into(), "GPL-3.0".into(), "GPLv3".into()],
                file_patterns: vec!["COPYING".into(), "LICENSE".into()],
                header_patterns: vec![
                    "GNU General Public License".into(),
                    "version 3".into(),
                    "either version 3".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("AGPL-3.0-only"),
                name: "GNU Affero General Public License v3.0".into(),
                family: LicenseFamily::NetworkCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::SourceDisclosure,
                    LicenseObligation::Copyleft,
                    LicenseObligation::NetworkDisclosure,
                    LicenseObligation::ChangeDocumentation,
                    LicenseObligation::PatentGrant,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: false,
                spdx_patterns: vec!["AGPL-3.0-only".into(), "AGPL-3.0".into(), "AGPLv3".into()],
                file_patterns: vec!["COPYING".into(), "LICENSE".into()],
                header_patterns: vec![
                    "GNU Affero General Public License".into(),
                    "Affero".into(),
                    "interact with it remotely".into(),
                ],
            },
            // ── Weak Copyleft ──
            LicenseDescriptor {
                id: LicenseId::new("LGPL-2.1-only"),
                name: "GNU Lesser General Public License v2.1".into(),
                family: LicenseFamily::WeakCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::ModifiedFileDisclosure,
                    LicenseObligation::DynamicLinkingRequired,
                    LicenseObligation::ChangeDocumentation,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true, // via dynamic linking
                spdx_patterns: vec!["LGPL-2.1-only".into(), "LGPL-2.1".into(), "LGPLv2.1".into()],
                file_patterns: vec!["COPYING.LESSER".into(), "LICENSE".into()],
                header_patterns: vec![
                    "GNU Lesser General Public License".into(),
                    "Lesser General Public".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("MPL-2.0"),
                name: "Mozilla Public License 2.0".into(),
                family: LicenseFamily::WeakCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::ModifiedFileDisclosure,
                    LicenseObligation::PatentGrant,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["MPL-2.0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "Mozilla Public License".into(),
                    "MPL".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("EPL-2.0"),
                name: "Eclipse Public License 2.0".into(),
                family: LicenseFamily::WeakCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::ModifiedFileDisclosure,
                    LicenseObligation::PatentGrant,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["EPL-2.0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "Eclipse Public License".into(),
                ],
            },
            // ── Network/Service Copyleft ──
            LicenseDescriptor {
                id: LicenseId::new("SSPL-1.0"),
                name: "Server Side Public License v1".into(),
                family: LicenseFamily::NetworkCopyleft,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::SourceDisclosure,
                    LicenseObligation::Copyleft,
                    LicenseObligation::NetworkDisclosure,
                ],
                osi_approved: false,
                fsf_free: false,
                proprietary_compatible: false,
                spdx_patterns: vec!["SSPL-1.0".into(), "SSPL".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "Server Side Public License".into(),
                    "SSPL".into(),
                ],
            },
            // ── Permissive + Patent ──
            LicenseDescriptor {
                id: LicenseId::new("Apache-2.0"),
                name: "Apache License 2.0".into(),
                family: LicenseFamily::PermissivePatent,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::NoticeFile,
                    LicenseObligation::PatentGrant,
                    LicenseObligation::ChangeDocumentation,
                    LicenseObligation::TrademarkRestriction,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["Apache-2.0".into()],
                file_patterns: vec!["LICENSE".into(), "NOTICE".into()],
                header_patterns: vec![
                    "Apache License".into(),
                    "Version 2.0".into(),
                    "Licensed under the Apache License".into(),
                ],
            },
            // ── Permissive ──
            LicenseDescriptor {
                id: LicenseId::new("MIT"),
                name: "MIT License".into(),
                family: LicenseFamily::Permissive,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::HeaderPreservation,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["MIT".into()],
                file_patterns: vec!["LICENSE".into(), "LICENSE.md".into()],
                header_patterns: vec![
                    "Permission is hereby granted".into(),
                    "MIT License".into(),
                    "The MIT License".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("BSD-2-Clause"),
                name: "BSD 2-Clause \"Simplified\" License".into(),
                family: LicenseFamily::Permissive,
                obligations: vec![
                    LicenseObligation::Attribution,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["BSD-2-Clause".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "Redistribution and use in source and binary".into(),
                    "2-Clause".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("BSD-3-Clause"),
                name: "BSD 3-Clause \"New\" License".into(),
                family: LicenseFamily::Permissive,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::TrademarkRestriction,
                ],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["BSD-3-Clause".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "Redistribution and use in source and binary".into(),
                    "Neither the name".into(),
                    "3-Clause".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("ISC"),
                name: "ISC License".into(),
                family: LicenseFamily::Permissive,
                obligations: vec![LicenseObligation::Attribution],
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["ISC".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec!["ISC License".into(), "Permission to use, copy, modify".into()],
            },
            // ── Public Domain ──
            LicenseDescriptor {
                id: LicenseId::new("Unlicense"),
                name: "The Unlicense".into(),
                family: LicenseFamily::PublicDomain,
                obligations: vec![], // No obligations
                osi_approved: true,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["Unlicense".into()],
                file_patterns: vec!["UNLICENSE".into(), "LICENSE".into()],
                header_patterns: vec![
                    "This is free and unencumbered software".into(),
                    "released into the public domain".into(),
                ],
            },
            LicenseDescriptor {
                id: LicenseId::new("CC0-1.0"),
                name: "Creative Commons Zero v1.0 Universal".into(),
                family: LicenseFamily::PublicDomain,
                obligations: vec![],
                osi_approved: false,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["CC0-1.0".into(), "CC0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec![
                    "CC0".into(),
                    "Creative Commons Zero".into(),
                    "No Copyright".into(),
                ],
            },
            // ── Creative Commons ──
            LicenseDescriptor {
                id: LicenseId::new("CC-BY-4.0"),
                name: "Creative Commons Attribution 4.0".into(),
                family: LicenseFamily::CreativeCommons,
                obligations: vec![LicenseObligation::Attribution],
                osi_approved: false,
                fsf_free: true,
                proprietary_compatible: true,
                spdx_patterns: vec!["CC-BY-4.0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec!["Creative Commons Attribution".into()],
            },
            LicenseDescriptor {
                id: LicenseId::new("CC-BY-SA-4.0"),
                name: "Creative Commons Attribution-ShareAlike 4.0".into(),
                family: LicenseFamily::CreativeCommons,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::ShareAlike,
                ],
                osi_approved: false,
                fsf_free: true,
                proprietary_compatible: false,
                spdx_patterns: vec!["CC-BY-SA-4.0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec!["Attribution-ShareAlike".into()],
            },
            LicenseDescriptor {
                id: LicenseId::new("CC-BY-NC-4.0"),
                name: "Creative Commons Attribution-NonCommercial 4.0".into(),
                family: LicenseFamily::CreativeCommonsRestricted,
                obligations: vec![
                    LicenseObligation::Attribution,
                    LicenseObligation::NonCommercial,
                ],
                osi_approved: false,
                fsf_free: false,
                proprietary_compatible: false,
                spdx_patterns: vec!["CC-BY-NC-4.0".into()],
                file_patterns: vec!["LICENSE".into()],
                header_patterns: vec!["NonCommercial".into()],
            },
        ]
    }
}

impl Default for LicenseDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── License Family Classification ──────────────────────────────

    #[test]
    fn test_bsl_boost_is_permissive() {
        // BSL-1.0 = Boost Software License, NOT Business Source License
        assert_eq!(LicenseFamily::from_spdx("BSL-1.0"), LicenseFamily::Permissive);
    }

    #[test]
    fn test_bsl_business_is_proprietary() {
        // Business Source License (BUSL) is source-available, not copyleft
        assert_eq!(LicenseFamily::from_spdx("BUSL-1.1"), LicenseFamily::SourceAvailable);
    }

    #[test]
    fn test_commons_clause_is_proprietary() {
        // Commons Clause is a commercial restriction, source-available
        assert_eq!(LicenseFamily::from_spdx("MIT WITH Commons-Clause"), LicenseFamily::SourceAvailable);
    }

    #[test]
    fn test_elastic_license_is_proprietary() {
        assert_eq!(LicenseFamily::from_spdx("Elastic-2.0"), LicenseFamily::SourceAvailable);
    }

    #[test]
    fn test_gpl_or_later_normalizes() {
        assert_eq!(LicenseFamily::from_spdx("GPL-2.0-or-later"), LicenseFamily::StrongCopyleft);
        assert_eq!(LicenseFamily::from_spdx("GPL-3.0+"), LicenseFamily::StrongCopyleft);
    }

    #[test]
    fn test_gpl_only_normalizes() {
        assert_eq!(LicenseFamily::from_spdx("GPL-2.0-only"), LicenseFamily::StrongCopyleft);
        assert_eq!(LicenseFamily::from_spdx("GPL-3.0-only"), LicenseFamily::StrongCopyleft);
    }

    #[test]
    fn test_agpl_is_network_copyleft() {
        assert_eq!(LicenseFamily::from_spdx("AGPL-3.0-only"), LicenseFamily::NetworkCopyleft);
        assert_eq!(LicenseFamily::from_spdx("AGPL-3.0-or-later"), LicenseFamily::NetworkCopyleft);
    }

    #[test]
    fn test_sspl_is_network_copyleft() {
        assert_eq!(LicenseFamily::from_spdx("SSPL-1.0"), LicenseFamily::NetworkCopyleft);
    }

    #[test]
    fn test_lgpl_is_weak_copyleft() {
        assert_eq!(LicenseFamily::from_spdx("LGPL-2.1-only"), LicenseFamily::WeakCopyleft);
        assert_eq!(LicenseFamily::from_spdx("LGPL-3.0-or-later"), LicenseFamily::WeakCopyleft);
    }

    #[test]
    fn test_mpl_is_weak_copyleft() {
        assert_eq!(LicenseFamily::from_spdx("MPL-2.0"), LicenseFamily::WeakCopyleft);
    }

    #[test]
    fn test_epl_is_weak_copyleft() {
        assert_eq!(LicenseFamily::from_spdx("EPL-2.0"), LicenseFamily::WeakCopyleft);
    }

    #[test]
    fn test_permissive_licenses() {
        assert_eq!(LicenseFamily::from_spdx("MIT"), LicenseFamily::Permissive);
        assert_eq!(LicenseFamily::from_spdx("BSD-3-Clause"), LicenseFamily::Permissive);
        assert_eq!(LicenseFamily::from_spdx("BSD-2-Clause"), LicenseFamily::Permissive);
        assert_eq!(LicenseFamily::from_spdx("ISC"), LicenseFamily::Permissive);
        assert_eq!(LicenseFamily::from_spdx("Zlib"), LicenseFamily::Permissive);
    }

    #[test]
    fn test_apache_is_permissive_patent() {
        assert_eq!(LicenseFamily::from_spdx("Apache-2.0"), LicenseFamily::PermissivePatent);
    }

    #[test]
    fn test_public_domain_licenses() {
        assert_eq!(LicenseFamily::from_spdx("Unlicense"), LicenseFamily::PublicDomain);
        assert_eq!(LicenseFamily::from_spdx("CC0-1.0"), LicenseFamily::PublicDomain);
        assert_eq!(LicenseFamily::from_spdx("WTFPL"), LicenseFamily::PublicDomain);
        assert_eq!(LicenseFamily::from_spdx("0BSD"), LicenseFamily::PublicDomain);
    }

    #[test]
    fn test_cc_restricted_licenses() {
        assert_eq!(LicenseFamily::from_spdx("CC-BY-NC-4.0"), LicenseFamily::CreativeCommonsRestricted);
        assert_eq!(LicenseFamily::from_spdx("CC-BY-ND-4.0"), LicenseFamily::CreativeCommonsRestricted);
        assert_eq!(LicenseFamily::from_spdx("CC-BY-NC-SA-4.0"), LicenseFamily::CreativeCommonsRestricted);
    }

    #[test]
    fn test_cc_permissive_licenses() {
        assert_eq!(LicenseFamily::from_spdx("CC-BY-4.0"), LicenseFamily::CreativeCommons);
        assert_eq!(LicenseFamily::from_spdx("CC-BY-SA-4.0"), LicenseFamily::CreativeCommons);
    }

    #[test]
    fn test_copyleft_classification() {
        assert!(LicenseId::new("GPL-3.0-only").is_copyleft());
        assert!(LicenseId::new("AGPL-3.0-only").is_copyleft());
        assert!(LicenseId::new("LGPL-2.1-only").is_copyleft());
        assert!(!LicenseId::new("MIT").is_copyleft());
        assert!(!LicenseId::new("Apache-2.0").is_copyleft());
    }

    #[test]
    fn test_permissive_classification() {
        assert!(LicenseId::new("MIT").is_permissive());
        assert!(LicenseId::new("BSD-3-Clause").is_permissive());
        assert!(LicenseId::new("Apache-2.0").is_permissive());
        assert!(!LicenseId::new("GPL-3.0-only").is_permissive());
    }

    #[test]
    fn test_unknown_license_is_custom() {
        assert_eq!(LicenseFamily::from_spdx("CoolNewLicense-1.0"), LicenseFamily::Custom);
    }

    #[test]
    fn test_no_license_is_none() {
        assert_eq!(LicenseFamily::from_spdx("NONE"), LicenseFamily::None);
        assert_eq!(LicenseFamily::from_spdx("NOASSERTION"), LicenseFamily::None);
    }

    // ─── License Compatibility ──────────────────────────────────────

    #[test]
    fn test_permissive_compatible_with_anything() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext::default();
        let mit = LicenseId::new("MIT");
        let gpl = LicenseId::new("GPL-3.0-only");
        let result = check_compatibility(&mit, &gpl, &ctx);
        // MIT upstream -> GPL downstream: conditionally compatible (attribution)
        assert!(matches!(result, Compatibility::ConditionallyCompatible(_)));
    }

    #[test]
    fn test_gpl_incompatible_with_proprietary() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext::default();
        let gpl = LicenseId::new("GPL-3.0-only");
        let prop = LicenseId::new("Proprietary");
        let result = check_compatibility(&gpl, &prop, &ctx);
        assert!(matches!(result, Compatibility::Incompatible(_)));
    }

    #[test]
    fn test_agpl_incompatible_with_network_service() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext {
            network_service: true,
            ..Default::default()
        };
        let agpl = LicenseId::new("AGPL-3.0-only");
        let mit = LicenseId::new("MIT");
        let result = check_compatibility(&agpl, &mit, &ctx);
        assert!(matches!(result, Compatibility::Incompatible(_)));
    }

    #[test]
    fn test_lgpl_static_linking_incompatible() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext {
            static_linking: true,
            ..Default::default()
        };
        let lgpl = LicenseId::new("LGPL-2.1-only");
        let mit = LicenseId::new("MIT");
        let result = check_compatibility(&lgpl, &mit, &ctx);
        assert!(matches!(result, Compatibility::Incompatible(_)));
    }

    #[test]
    fn test_apache2_incompatible_with_gpl2() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext::default();
        let gpl2 = LicenseId::new("GPL-2.0-only");
        let apache = LicenseId::new("Apache-2.0");
        let result = check_compatibility(&gpl2, &apache, &ctx);
        assert!(matches!(result, Compatibility::Incompatible(_)));
    }

    #[test]
    fn test_public_domain_compatible_with_everything() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext::default();
        let pd = LicenseId::new("CC0-1.0");
        let gpl = LicenseId::new("GPL-3.0-only");
        let result = check_compatibility(&pd, &gpl, &ctx);
        assert!(matches!(result, Compatibility::Compatible));
    }

    #[test]
    fn test_cc_nc_incompatible_commercial() {
        use crate::license::compatibility::*;
        let ctx = InteractionContext {
            commercial: true,
            ..Default::default()
        };
        let ccnc = LicenseId::new("CC-BY-NC-4.0");
        let mit = LicenseId::new("MIT");
        let result = check_compatibility(&ccnc, &mit, &ctx);
        assert!(matches!(result, Compatibility::Incompatible(_)));
    }

    // ─── License Database ───────────────────────────────────────────

    #[test]
    fn test_license_db_has_major_licenses() {
        let db = LicenseDb::new();
        assert!(db.lookup("MIT").is_some());
        assert!(db.lookup("Apache-2.0").is_some());
        assert!(db.lookup("GPL-3.0-only").is_some());
        assert!(db.lookup("BSD-3-Clause").is_some());
    }

    #[test]
    fn test_license_db_obligations() {
        let db = LicenseDb::new();
        let mit = db.obligations("MIT");
        assert!(mit.contains(&LicenseObligation::Attribution));
        let gpl = db.obligations("GPL-3.0-only");
        assert!(gpl.contains(&LicenseObligation::SourceDisclosure));
    }

    #[test]
    fn test_ai_ml_license_classification() {
        assert_eq!(LicenseFamily::from_spdx("OpenRAIL-M"), LicenseFamily::AiMl);
        assert_eq!(LicenseFamily::from_spdx("Llama-Community"), LicenseFamily::AiMl);
        assert_eq!(LicenseFamily::from_spdx("BigScience-BLOOM-RAIL-1.0"), LicenseFamily::AiMl);
        assert_eq!(LicenseFamily::from_spdx("CreativeML-OpenRAIL-M"), LicenseFamily::AiMl);
        assert_eq!(LicenseFamily::from_spdx("Gemma"), LicenseFamily::AiMl);
    }

    #[test]
    fn test_data_license_classification() {
        assert_eq!(LicenseFamily::from_spdx("ODbL-1.0"), LicenseFamily::DataOpen);
        assert_eq!(LicenseFamily::from_spdx("CDLA-Permissive-2.0"), LicenseFamily::DataOpen);
        assert_eq!(LicenseFamily::from_spdx("ODC-By-1.0"), LicenseFamily::DataOpen);
        assert_eq!(LicenseFamily::from_spdx("PDDL-1.0"), LicenseFamily::DataOpen);
        assert_eq!(LicenseFamily::from_spdx("OGL-UK-3.0"), LicenseFamily::DataOpen);
    }

    #[test]
    fn test_source_available_classification() {
        assert_eq!(LicenseFamily::from_spdx("PolyForm-Small-Business-1.0"), LicenseFamily::SourceAvailable);
        assert_eq!(LicenseFamily::from_spdx("FSL-1.0-MIT"), LicenseFamily::SourceAvailable);
        assert_eq!(LicenseFamily::from_spdx("Prosperity-3.0"), LicenseFamily::SourceAvailable);
    }

    #[test]
    fn test_source_available_is_restrictive() {
        assert!(LicenseFamily::SourceAvailable.is_restrictive());
        assert!(!LicenseFamily::SourceAvailable.is_permissive());
        assert!(!LicenseFamily::SourceAvailable.is_copyleft());
    }
}
