//! Phase 3: Dependency analysis — resolution, contamination, compatibility

use crate::analysis::dependency_graph::DependencyResolver;
use crate::detection::attribution_checker::AttributionChecker;
use crate::detection::contamination::ContaminationTracer;
use crate::detection::{Violation, ViolationType, Severity};
use crate::engine::pipeline::{PhaseOutput, ScanContext, ScanPhase};
use crate::evidence::EvidenceItem;
use crate::license::LicenseId;
use crate::SkeraResult;

pub struct DependencyPhase {
    resolver: DependencyResolver,
    attribution: AttributionChecker,
    contamination: ContaminationTracer,
}

impl DependencyPhase {
    pub fn new() -> Self {
        Self {
            resolver: DependencyResolver::new(),
            attribution: AttributionChecker::new(),
            contamination: ContaminationTracer::new(),
        }
    }
}

impl ScanPhase for DependencyPhase {
    fn name(&self) -> &str {
        "Dependency Analysis"
    }

    fn should_run(&self, config: &crate::engine::SkeraConfig) -> bool {
        config.dependency_analysis
    }

    fn run(&self, ctx: &ScanContext) -> SkeraResult<PhaseOutput> {
        let mut output = PhaseOutput::new();

        let dep_graph = match self.resolver.resolve(&ctx.source_dir) {
            Some(g) => g,
            None => return Ok(output),
        };

        let deps: Vec<(String, LicenseId)> = dep_graph
            .nodes
            .iter()
            .map(|n| (n.name.clone(), n.license.clone()))
            .collect();

        output.dependencies = deps.clone();

        // Attribution check
        let attr_violations = self.attribution.check_project(
            &ctx.source_dir,
            &ctx.project_license,
            &deps,
        );
        output.violations.extend(attr_violations);

        // Contamination tracing
        let contamination = self.contamination.trace(&dep_graph.nodes, &dep_graph.root);
        let cont_violations = self.contamination.to_violations(&contamination, &ctx.project_license);
        output.violations.extend(cont_violations);

        // Pairwise license compatibility
        let compat_ctx = crate::license::compatibility::InteractionContext {
            binary_distribution: true,
            network_service: ctx.config.network_service,
            static_linking: false,
            commercial: ctx.config.commercial,
            modified: false,
        };

        for node in &dep_graph.nodes {
            let compat = crate::license::compatibility::check_compatibility(
                &node.license,
                &ctx.project_license,
                &compat_ctx,
            );
            if let crate::license::compatibility::Compatibility::Incompatible(reason) = compat {
                output.violations.push(Violation {
                    violation_type: ViolationType::IncompatibleLicenses,
                    severity: Severity::High,
                    confidence: 0.85,
                    description: format!(
                        "Dependency '{}' ({}) is incompatible with project ({}): {}",
                        node.name, node.license, ctx.project_license, reason
                    ),
                    files: vec![ctx.source_dir.to_path_buf()],
                    licenses: vec![node.license.clone(), ctx.project_license.clone()],
                    obligations_violated: vec![],
                    evidence: vec![EvidenceItem::from_file(
                        &ctx.source_dir, 0,
                        &format!("dep={} license={} vs project={}", node.name, node.license, ctx.project_license),
                        format!("License incompatibility: {}", reason),
                    )],
                    claimed_license: Some(ctx.project_license.clone()),
                    actual_license: Some(node.license.clone()),
                });
            }
        }

        output.files_processed = dep_graph.total_deps;
        Ok(output)
    }
}
