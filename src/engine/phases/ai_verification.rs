//! Phase 5: AI verification -- multi-model consensus for violation validation

use crate::ai::{AIVerifier, AIVerifierConfig};
use crate::detection::Violation;
use crate::evidence::EvidenceItem;

/// AI verification is a special post-processing phase that runs after all
/// detection phases. It takes the accumulated violations and sends them to
/// AI models for validation, boosting or reducing confidence.
pub struct AiVerificationPhase {
    verifier: AIVerifier,
}

impl AiVerificationPhase {
    pub fn new(_config: &crate::engine::SkeraConfig) -> Self {
        // AIVerifier::new takes AIVerifierConfig, not SkeraConfig
        // Use default config which discovers API keys from environment
        Self {
            verifier: AIVerifier::new(AIVerifierConfig::default()),
        }
    }

    pub fn is_available(&self) -> bool {
        self.verifier.is_available()
    }

    /// Run AI verification on all violations, modifying them in place
    pub async fn verify(&self, violations: &mut Vec<Violation>) {
        if violations.is_empty() || !self.verifier.is_available() {
            return;
        }

        tracing::info!("AI verification: {} violations to verify", violations.len());
        let verifications = self.verifier.batch_verify(violations).await;

        let mut ai_confirmed = 0usize;
        let mut ai_contested = 0usize;
        let mut ai_upgraded = 0usize;
        let mut ai_downgraded = 0usize;

        for (violation, verification) in violations.iter_mut().zip(verifications.iter()) {
            // Track severity adjustments
            if let Some(ref suggested) = verification.suggested_severity {
                if *suggested > violation.severity {
                    ai_upgraded += 1;
                } else if *suggested < violation.severity {
                    ai_downgraded += 1;
                }
                violation.severity = suggested.clone();
            }

            // Adjust confidence based on AI agreement
            if verification.confirmed {
                ai_confirmed += 1;
                violation.confidence = (violation.confidence * 0.4 + verification.confidence * 0.6)
                    .max(violation.confidence)
                    .min(1.0);
            } else if verification.confidence > 0.5 {
                ai_contested += 1;
                // AI disagrees with high confidence -- reduce but don't destroy
                let new_confidence = violation.confidence * (1.0 - (verification.confidence * 0.5));
                // Floor: never let AI reduce confidence below 0.1 so humans
                // can still review contested violations
                violation.confidence = new_confidence.max(0.1);
                violation.description.push_str(" [AI-CONTESTED]");
            } else {
                // AI uncertain -- slight reduction
                violation.confidence = (violation.confidence * 0.85).max(0.1);
            }

            // Add AI reasoning as evidence
            if !verification.reasoning.is_empty() {
                violation.evidence.push(EvidenceItem::from_file(
                    violation
                        .files
                        .first()
                        .map(|p| p.as_path())
                        .unwrap_or(std::path::Path::new(".")),
                    0,
                    &verification.reasoning,
                    format!(
                        "AI verification by {}",
                        verification.models_used.join(", ")
                    ),
                ));
            }
        }

        tracing::info!(
            "AI verification complete: {} confirmed, {} contested, {} upgraded, {} downgraded",
            ai_confirmed, ai_contested, ai_upgraded, ai_downgraded
        );
    }
}
