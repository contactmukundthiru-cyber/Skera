//! Phase 3c: Supply chain auditing — typosquatting, deprecated deps, version pinning

use crate::detection::supply_chain_audit::SupplyChainAuditor;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::SkeraResult;

pub struct SupplyChainPhase;

impl SupplyChainPhase {
    pub fn new() -> Self { Self }
}

impl ScanPhase for SupplyChainPhase {
    fn name(&self) -> &str {
        "Supply Chain Audit"
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let audit = SupplyChainAuditor::audit(&ctx.source_dir);
        let mut violations = Vec::new();

        for finding in &audit.findings {
            let (vtype, severity) = match finding.category {
                crate::detection::supply_chain_audit::SupplyChainCategory::Typosquatting
                    => (ViolationType::Typosquatting, Severity::Critical),
                crate::detection::supply_chain_audit::SupplyChainCategory::DeprecatedPackage 
                    => (ViolationType::DeprecatedDependency, Severity::High),
                crate::detection::supply_chain_audit::SupplyChainCategory::VersionPinning
                    => (ViolationType::VersionPinningRisk, Severity::Medium),
                crate::detection::supply_chain_audit::SupplyChainCategory::ScopeConfusion
                    => (ViolationType::ScopeConfusion, Severity::High),
                crate::detection::supply_chain_audit::SupplyChainCategory::LockfileTampering
                    => (ViolationType::LockfileStaleness, Severity::Low),
                _ => (ViolationType::Custom(format!("{:?}", finding.category)), Severity::Medium),
            };

            violations.push(Violation {
                violation_type: vtype,
                severity,
                confidence: 0.85,
                description: finding.description.clone(),
                files: vec![ctx.source_dir.to_path_buf()],
                licenses: vec![],
                obligations_violated: vec![],
                evidence: vec![EvidenceItem::from_file(
                    &ctx.source_dir, 0,
                    &finding.description,
                    format!("Supply chain audit: {:?}", finding.category),
                )],
                claimed_license: None,
                actual_license: None,
            });
        }

        Ok(PhaseOutput::with_violations(violations, audit.dependency_audits.len()))
    }
}
