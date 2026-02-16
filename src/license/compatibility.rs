//! License compatibility matrix
//!
//! Determines whether two licenses can coexist in the same project,
//! factoring in linking mode, distribution type, and network exposure.

use super::{LicenseFamily, LicenseId};
use serde::{Deserialize, Serialize};

/// Compatibility verdict between two licenses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Compatibility {
    /// Fully compatible, no issues
    Compatible,
    /// Compatible only under specific conditions
    ConditionallyCompatible(Vec<String>),
    /// Incompatible — using these together is a violation
    Incompatible(String),
    /// Unknown — not enough information to determine
    Unknown,
}

/// The context in which two licenses interact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractionContext {
    /// Is the downstream project distributed as a binary?
    pub binary_distribution: bool,
    /// Is the downstream project a network service (SaaS)?
    pub network_service: bool,
    /// Is the library statically linked?
    pub static_linking: bool,
    /// Is this a commercial project?
    pub commercial: bool,
    /// Is source code being modified?
    pub modified: bool,
}

impl Default for InteractionContext {
    fn default() -> Self {
        Self {
            binary_distribution: true,
            network_service: false,
            static_linking: false,
            commercial: true,
            modified: false,
        }
    }
}

/// Check compatibility between two licenses
pub fn check_compatibility(
    upstream: &LicenseId,
    downstream: &LicenseId,
    ctx: &InteractionContext,
) -> Compatibility {
    let up_family = upstream.family();
    let down_family = downstream.family();

    match (&up_family, &down_family) {
        // ── Public domain is compatible with everything ──
        (LicenseFamily::PublicDomain, _) | (_, LicenseFamily::PublicDomain) => {
            Compatibility::Compatible
        }

        // ── Permissive upstream → anything downstream is fine ──
        (LicenseFamily::Permissive | LicenseFamily::PermissivePatent, _) => {
            // Check attribution obligation is met
            Compatibility::ConditionallyCompatible(vec![
                "Attribution and license notice must be preserved".into(),
            ])
        }

        // ── GPL upstream → downstream must also be GPL-compatible ──
        (LicenseFamily::StrongCopyleft, LicenseFamily::StrongCopyleft) => {
            // GPL-2 and GPL-3 are NOT compatible with each other
            let up = upstream.as_str().to_uppercase();
            let down = downstream.as_str().to_uppercase();
            if up.contains("GPL-2") && down.contains("GPL-3") {
                Compatibility::Incompatible(
                    "GPL-2.0 and GPL-3.0 are not directly compatible. \
                     GPL-2.0-only code cannot be relicensed under GPL-3.0."
                        .into(),
                )
            } else {
                Compatibility::Compatible
            }
        }

        (LicenseFamily::StrongCopyleft, LicenseFamily::Permissive) => {
            // GPL can consume permissive — the result is GPL
            Compatibility::Compatible
        }

        (LicenseFamily::StrongCopyleft, LicenseFamily::PermissivePatent) => {
            // Apache-2.0 is compatible with GPL-3.0 but NOT GPL-2.0
            let up = upstream.as_str().to_uppercase();
            if up.contains("GPL-2") {
                Compatibility::Incompatible(
                    "Apache-2.0 patent clause is incompatible with GPL-2.0. \
                     Only GPL-3.0+ is compatible with Apache-2.0."
                        .into(),
                )
            } else {
                Compatibility::Compatible
            }
        }

        (LicenseFamily::StrongCopyleft, LicenseFamily::Proprietary) => {
            Compatibility::Incompatible(
                "Copyleft (GPL/AGPL) code cannot be incorporated into \
                 proprietary/closed-source software."
                    .into(),
            )
        }

        (LicenseFamily::StrongCopyleft, LicenseFamily::WeakCopyleft) => {
            // LGPL can be consumed by GPL, but not the reverse
            Compatibility::ConditionallyCompatible(vec![
                "LGPL code can be incorporated into GPL projects.".into(),
                "The combined work inherits the GPL license.".into(),
            ])
        }

        // ── AGPL / Network copyleft ──
        (LicenseFamily::NetworkCopyleft, _) if ctx.network_service => {
            Compatibility::Incompatible(
                "SSPL/AGPL code used in a network service requires the ENTIRE \
                 service stack source code to be disclosed."
                    .into(),
            )
        }

        // ── LGPL + static linking ──
        (LicenseFamily::WeakCopyleft, _) if ctx.static_linking => {
            let up = upstream.as_str().to_uppercase();
            if up.contains("LGPL") {
                Compatibility::Incompatible(
                    "LGPL code that is statically linked requires the downstream \
                     project to allow relinking. Dynamic linking is required."
                        .into(),
                )
            } else {
                Compatibility::ConditionallyCompatible(vec![
                    "Modifications to the weak-copyleft component must be disclosed.".into(),
                ])
            }
        }

        // ── CC-NC in commercial project ──
        (LicenseFamily::CreativeCommonsRestricted, _) if ctx.commercial => {
            Compatibility::Incompatible(
                "Creative Commons NonCommercial content cannot be used in commercial projects."
                    .into(),
            )
        }

        // ── Proprietary upstream → anything downstream ──
        (LicenseFamily::Proprietary, _) => Compatibility::Incompatible(
            "Proprietary code cannot be redistributed under an open-source license.".into(),
        ),

        // ── Fallback: assume conditional ──
        _ => Compatibility::ConditionallyCompatible(vec![
            "Review license terms carefully for specific obligations.".into(),
        ]),
    }
}

/// Check if a set of licenses in a dependency tree are all compatible
pub fn check_tree_compatibility(
    licenses: &[(String, LicenseId)],
    root_license: &LicenseId,
    ctx: &InteractionContext,
) -> Vec<IncompatibilityReport> {
    let mut reports = Vec::new();

    for (dep_name, dep_license) in licenses {
        let compat = check_compatibility(dep_license, root_license, ctx);
        if let Compatibility::Incompatible(reason) = compat {
            reports.push(IncompatibilityReport {
                dependency: dep_name.clone(),
                dependency_license: dep_license.clone(),
                project_license: root_license.clone(),
                reason,
                severity: IncompatibilitySeverity::Critical,
            });
        }
    }

    reports
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompatibilityReport {
    pub dependency: String,
    pub dependency_license: LicenseId,
    pub project_license: LicenseId,
    pub reason: String,
    pub severity: IncompatibilitySeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncompatibilitySeverity {
    /// Legal action likely if discovered
    Critical,
    /// Violation but enforcement is rare
    High,
    /// Potential issue depending on interpretation
    Medium,
    /// Best practice violation
    Low,
}
