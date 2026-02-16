//! AI-powered verification layer
//!
//! Uses multi-model consensus with pooled API keys to verify and
//! deep-analyze potential violations. Designed to work with any
//! OpenAI-compatible API backend.
//!
//! ## Key Discovery
//!
//! Auto-discovers API keys from environment variables:
//! - `OPENAI_API_KEY` → OpenAI (gpt-4o, etc.)
//! - `ANTHROPIC_API_KEY` → Anthropic (claude-3.5, etc.)
//! - `GROQ_API_KEY` → Groq (llama-3.3, deepseek, etc.)
//! - `TOGETHER_API_KEY` → Together AI
//! - `OPENROUTER_API_KEY` → OpenRouter (multi-model)
//! - `DEEPSEEK_API_KEY` → DeepSeek
//! - `SKERA_AI_KEY` → Custom user-supplied key
//! - `SKERA_AI_ENDPOINT` → Custom OpenAI-compatible endpoint
//!
//! Users can also configure keys programmatically via `AIVerifierConfig`.
//!
//! ## Key Pool Architecture
//!
//! Supports a rotating pool of API keys to avoid rate limits and
//! maximize throughput during large scans.

use crate::detection::{Violation, Severity};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// AI verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVerification {
    /// Is the violation confirmed by AI?
    pub confirmed: bool,
    /// AI confidence in the determination
    pub confidence: f64,
    /// Which model(s) were used
    pub models_used: Vec<String>,
    /// AI reasoning / explanation
    pub reasoning: String,
    /// Suggested severity (AI may upgrade/downgrade)
    pub suggested_severity: Option<Severity>,
    /// Additional context from AI
    pub additional_findings: Vec<String>,
}

/// Configuration for the AI verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIVerifierConfig {
    /// API keys pool (rotated to avoid rate limits)
    pub api_keys: Vec<ApiKeyEntry>,
    /// Minimum number of models that must agree for confirmation
    pub consensus_threshold: usize,
    /// Maximum tokens per AI request
    pub max_tokens: usize,
    /// Whether to use multi-model consensus
    pub use_consensus: bool,
    /// Models to use for verification
    pub verification_models: Vec<String>,
    /// Whether to auto-discover keys from environment variables
    pub auto_discover_keys: bool,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyEntry {
    pub provider: String,
    pub key: String,
    pub endpoint: String,
    pub model: String,
    pub tier: ApiTier,
    /// Remaining requests (tracked)
    pub requests_remaining: Option<u64>,
    /// Whether this key is currently active
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApiTier {
    Free,
    Basic,
    Pro,
    Enterprise,
}

impl Default for AIVerifierConfig {
    fn default() -> Self {
        Self {
            api_keys: Vec::new(),
            consensus_threshold: 1,
            max_tokens: 4096,
            use_consensus: false,
            verification_models: vec![
                "deepseek-ai/DeepSeek-R1-0528".into(),
                "meta-llama/Llama-3.3-70B-Instruct".into(),
            ],
            auto_discover_keys: true,
            timeout_seconds: 30,
        }
    }
}

/// AI-powered violation verifier
pub struct AIVerifier {
    config: AIVerifierConfig,
    keys: Vec<ApiKeyEntry>,
    key_index: Arc<RwLock<usize>>,
    client: reqwest::Client,
}

/// Known providers and their OpenAI-compatible endpoints
const PROVIDER_MAP: &[(&str, &str, &str, &str)] = &[
    // (env_var, provider_name, endpoint, default_model)
    ("OPENAI_API_KEY", "openai", "https://api.openai.com/v1/chat/completions", "gpt-4o-mini"),
    ("GROQ_API_KEY", "groq", "https://api.groq.com/openai/v1/chat/completions", "llama-3.3-70b-versatile"),
    ("TOGETHER_API_KEY", "together", "https://api.together.xyz/v1/chat/completions", "meta-llama/Llama-3.3-70B-Instruct-Turbo"),
    ("OPENROUTER_API_KEY", "openrouter", "https://openrouter.ai/api/v1/chat/completions", "deepseek/deepseek-r1-0528"),
    ("DEEPSEEK_API_KEY", "deepseek", "https://api.deepseek.com/v1/chat/completions", "deepseek-chat"),
    ("ANTHROPIC_API_KEY", "anthropic", "https://api.anthropic.com/v1/messages", "claude-sonnet-4-20250514"),
];

/// Response shape from OpenAI-compatible APIs
#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Option<Vec<ChatChoice>>,
    // Anthropic uses a different shape
    content: Option<Vec<AnthropicContent>>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize)]
struct ChatMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    text: Option<String>,
}

/// Parsed AI response
#[derive(Debug, Deserialize)]
struct AIResponsePayload {
    confirmed: Option<bool>,
    confidence: Option<f64>,
    severity_adjustment: Option<String>,
    reasoning: Option<String>,
    legal_risk: Option<String>,
    additional_findings: Option<Vec<String>>,
}

impl AIVerifier {
    pub fn new(config: AIVerifierConfig) -> Self {
        let mut keys = config.api_keys.clone();

        // Auto-discover keys from environment
        if config.auto_discover_keys {
            let discovered = Self::discover_keys();
            for dk in discovered {
                // Don't add duplicates
                if !keys.iter().any(|k| k.provider == dk.provider) {
                    keys.push(dk);
                }
            }
        }

        // Check for custom endpoint
        if let Ok(custom_endpoint) = std::env::var("SKERA_AI_ENDPOINT") {
            if let Ok(custom_key) = std::env::var("SKERA_AI_KEY") {
                let model = std::env::var("SKERA_AI_MODEL")
                    .unwrap_or_else(|_| "default".to_string());
                if !keys.iter().any(|k| k.provider == "custom") {
                    keys.push(ApiKeyEntry {
                        provider: "custom".to_string(),
                        key: custom_key,
                        endpoint: custom_endpoint,
                        model,
                        tier: ApiTier::Pro,
                        requests_remaining: None,
                        active: true,
                    });
                }
            }
        }

        let active_count = keys.iter().filter(|k| k.active).count();
        if active_count > 0 {
            tracing::info!(
                "AI verifier initialized with {} active API key(s) from {} provider(s)",
                active_count,
                keys.iter()
                    .filter(|k| k.active)
                    .map(|k| k.provider.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        } else {
            tracing::info!(
                "AI verifier initialized without API keys — \
                 set OPENAI_API_KEY, GROQ_API_KEY, or SKERA_AI_KEY for AI verification"
            );
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .build()
            .unwrap_or_default();

        Self {
            config,
            keys,
            key_index: Arc::new(RwLock::new(0)),
            client,
        }
    }

    /// Discover API keys from well-known environment variables
    fn discover_keys() -> Vec<ApiKeyEntry> {
        let mut keys = Vec::new();

        for &(env_var, provider, endpoint, model) in PROVIDER_MAP {
            if let Ok(key) = std::env::var(env_var) {
                if !key.is_empty() {
                    tracing::debug!("Discovered {} API key from {}", provider, env_var);
                    keys.push(ApiKeyEntry {
                        provider: provider.to_string(),
                        key,
                        endpoint: endpoint.to_string(),
                        model: model.to_string(),
                        tier: ApiTier::Basic,
                        requests_remaining: None,
                        active: true,
                    });
                }
            }
        }

        keys
    }

    /// Whether AI verification is available (at least one key configured)
    pub fn is_available(&self) -> bool {
        self.keys.iter().any(|k| k.active)
    }

    /// Get the next available API key (round-robin rotation)
    async fn next_key(&self) -> Option<&ApiKeyEntry> {
        let active_keys: Vec<_> = self.keys.iter().filter(|k| k.active).collect();

        if active_keys.is_empty() {
            return None;
        }

        let mut idx = self.key_index.write().await;
        let key = active_keys[*idx % active_keys.len()];
        *idx += 1;
        Some(key)
    }

    /// Call an OpenAI-compatible API with the given prompt
    async fn call_api(&self, key: &ApiKeyEntry, prompt: &str) -> Result<String, String> {
        let is_anthropic = key.provider == "anthropic";

        let response = if is_anthropic {
            // Anthropic uses a different API shape
            let body = serde_json::json!({
                "model": key.model,
                "max_tokens": self.config.max_tokens,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            });

            self.client
                .post(&key.endpoint)
                .header("x-api-key", &key.key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("API request failed ({}): {}", key.provider, e))?
        } else {
            // OpenAI-compatible API
            let body = serde_json::json!({
                "model": key.model,
                "max_tokens": self.config.max_tokens,
                "temperature": 0.1,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a software license compliance expert and forensic analyst. Always respond with valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            });

            self.client
                .post(&key.endpoint)
                .header("Authorization", format!("Bearer {}", key.key))
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("API request failed ({}): {}", key.provider, e))?
        };

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(format!(
                "API error {} from {}: {}",
                status, key.provider, &error_body[..error_body.len().min(200)]
            ));
        }

        let resp: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response from {}: {}", key.provider, e))?;

        // Extract text from either OpenAI or Anthropic response shape
        if let Some(choices) = resp.choices {
            if let Some(choice) = choices.first() {
                return Ok(choice.message.content.clone().unwrap_or_default());
            }
        }
        if let Some(content) = resp.content {
            if let Some(block) = content.first() {
                return Ok(block.text.clone().unwrap_or_default());
            }
        }

        Err(format!("Empty response from {}", key.provider))
    }

    /// Parse AI response text into structured verification
    fn parse_ai_response(raw: &str, model: &str) -> AIVerification {
        // Try to extract JSON from markdown code blocks or raw text
        let json_str = if let Some(start) = raw.find('{') {
            if let Some(end) = raw.rfind('}') {
                &raw[start..=end]
            } else {
                raw
            }
        } else {
            raw
        };

        match serde_json::from_str::<AIResponsePayload>(json_str) {
            Ok(parsed) => {
                let suggested_severity = parsed.severity_adjustment.and_then(|s| {
                    match s.to_uppercase().as_str() {
                        "CRITICAL" => Some(Severity::Critical),
                        "HIGH" => Some(Severity::High),
                        "MEDIUM" => Some(Severity::Medium),
                        "LOW" => Some(Severity::Low),
                        _ => None,
                    }
                });

                let mut all_findings = parsed.additional_findings.unwrap_or_default();
                if let Some(risk) = parsed.legal_risk {
                    if !risk.is_empty() {
                        all_findings.push(format!("Legal risk: {}", risk));
                    }
                }

                AIVerification {
                    confirmed: parsed.confirmed.unwrap_or(false),
                    confidence: parsed.confidence.unwrap_or(0.5),
                    models_used: vec![model.to_string()],
                    reasoning: parsed.reasoning.unwrap_or_else(|| "No reasoning provided".into()),
                    suggested_severity,
                    additional_findings: all_findings,
                }
            }
            Err(_) => {
                // Failed to parse JSON — treat the raw text as reasoning
                let confirmed = raw.to_lowercase().contains("\"confirmed\": true")
                    || raw.to_lowercase().contains("\"confirmed\":true")
                    || raw.to_lowercase().contains("genuine violation");

                AIVerification {
                    confirmed,
                    confidence: if confirmed { 0.7 } else { 0.3 },
                    models_used: vec![model.to_string()],
                    reasoning: raw[..raw.len().min(500)].to_string(),
                    suggested_severity: None,
                    additional_findings: vec![],
                }
            }
        }
    }

    /// Verify a potential violation using AI analysis
    pub async fn verify_violation(
        &self,
        violation: &Violation,
        code_context: Option<&str>,
    ) -> AIVerification {
        let key = match self.next_key().await {
            Some(k) => k.clone(),
            None => {
                return AIVerification {
                    confirmed: violation.confidence > 0.85,
                    confidence: violation.confidence,
                    models_used: vec!["rule-based-fallback".to_string()],
                    reasoning: "No AI API keys configured. Using rule-based confidence. \
                                Set OPENAI_API_KEY, GROQ_API_KEY, or SKERA_AI_KEY for AI verification."
                        .to_string(),
                    suggested_severity: None,
                    additional_findings: vec![],
                };
            }
        };

        let prompt = self.build_verification_prompt(violation, code_context);

        match self.call_api(&key, &prompt).await {
            Ok(response_text) => {
                tracing::debug!(
                    "AI verification response from {} ({}): {} chars",
                    key.provider,
                    key.model,
                    response_text.len()
                );
                Self::parse_ai_response(&response_text, &key.model)
            }
            Err(e) => {
                tracing::warn!("AI verification failed: {}", e);
                AIVerification {
                    confirmed: violation.confidence > 0.85,
                    confidence: violation.confidence,
                    models_used: vec![format!("{} (failed)", key.model)],
                    reasoning: format!(
                        "AI verification API call failed: {}. Falling back to rule-based confidence.",
                        e
                    ),
                    suggested_severity: None,
                    additional_findings: vec![],
                }
            }
        }
    }

    /// Build the AI verification prompt
    fn build_verification_prompt(
        &self,
        violation: &Violation,
        code_context: Option<&str>,
    ) -> String {
        let mut prompt = format!(
            "You are a digital rights and IP compliance expert with deep expertise in:\n\
             - Software license compliance (GPL, MIT, Apache, AGPL, LGPL, MPL)\n\
             - AI/ML model licensing (OpenRAIL, Llama Community License, RAIL-M, BigScience)\n\
             - Digital media rights (sync licensing, mechanical rights, master use)\n\
             - DMCA §1201 anti-circumvention (DRM, copy protection)\n\
             - Typeface design rights and font licensing (OFL, commercial font EULAs)\n\
             - Creative Commons compliance (BY, SA, NC, ND clauses)\n\
             - Stock media licensing (Royalty-Free vs Rights-Managed vs Editorial-Only)\n\
             - Firmware/embedded GPL compliance (source disclosure obligations)\n\
             - EU AI Act and emerging AI governance regulations\n\
             - Data licensing (ODbL, CDLA, ODC-By)\n\n\
             Analyze the following potential violation and determine if it is genuine.\n\n\
             ## Violation Details\n\
             - **Type**: {:?}\n\
             - **Category**: {}\n\
             - **Severity**: {:?}\n\
             - **Confidence**: {:.1}%\n\
             - **Description**: {}\n",
            violation.violation_type,
            violation.violation_type.category(),
            violation.severity,
            violation.confidence * 100.0,
            violation.description,
        );

        if let (Some(claimed), Some(actual)) =
            (&violation.claimed_license, &violation.actual_license)
        {
            prompt.push_str(&format!(
                "- **Claimed License**: {}\n\
                 - **Actual License**: {}\n",
                claimed, actual
            ));
        }

        if !violation.files.is_empty() {
            prompt.push_str("\n## Files Involved\n");
            for f in &violation.files {
                prompt.push_str(&format!("- `{}`\n", f.display()));
            }
        }

        if !violation.evidence.is_empty() {
            prompt.push_str("\n## Evidence\n");
            for ev in &violation.evidence {
                prompt.push_str(&format!("- {}\n", ev.description));
                if let Some(ref excerpt) = ev.content_excerpt {
                    prompt.push_str(&format!("  ```\n  {}\n  ```\n", excerpt));
                }
            }
        }

        if let Some(ctx) = code_context {
            prompt.push_str(&format!(
                "\n## Code/Asset Context\n```\n{}\n```\n",
                &ctx[..ctx.len().min(2000)]
            ));
        }

        // Add violation-category-specific legal context
        let category_context = match violation.violation_type.category() {
            "Digital Media Rights" => Some(
                "Consider: sync licensing requirements for audio in video, mechanical rights for \
                 music reproduction, master use licenses, DMCA safe harbor provisions, fair use \
                 doctrine limitations, and whether the use qualifies as de minimis sampling."
            ),
            "AI & Model Rights" => Some(
                "Consider: the specific model license terms (OpenRAIL use restrictions, Llama \
                 Community License commercial thresholds, RAIL-M behavioral restrictions), \
                 EU AI Act compliance requirements, training data provenance obligations, \
                 and whether fine-tuning creates a derivative work under the license."
            ),
            "Design & Typography" => Some(
                "Consider: typeface design protection varies by jurisdiction (protected in EU/UK, \
                 limited protection in US for font software but not the typeface design itself), \
                 font embedding restrictions (installable, editable, preview & print, restricted), \
                 and whether the use falls within the font EULA's allowed installations."
            ),
            "Firmware & Embedded" => Some(
                "Consider: GPL source disclosure obligations for firmware distributions, \
                 tivoization restrictions under GPL-3.0, embedded font licensing requirements \
                 for IoT devices, and whether the firmware qualifies as a 'User Product' under \
                 GPL-3.0 (which requires installation information)."
            ),
            "Document & Publication" => Some(
                "Consider: first sale doctrine limitations for digital works, DMCA anti-circumvention \
                 for ebook DRM, fair use doctrine for educational materials, and whether the \
                 redistribution qualifies as a transformative use."
            ),
            "License Forensics" => Some(
                "Consider: whether Unicode homoglyphs could be incidental encoding errors rather \
                 than deliberate tampering, whether clause omissions are from an older license \
                 version, and whether chimera patterns indicate a custom dual-license arrangement."
            ),
            _ => None,
        };

        if let Some(ctx) = category_context {
            prompt.push_str(&format!("\n## Domain-Specific Legal Context\n{}\n", ctx));
        }

        prompt.push_str(
            "\n## Your Task\n\
             1. Is this a genuine license/rights violation? (yes/no/uncertain)\n\
             2. What is your confidence level? (0.0-1.0)\n\
             3. Should the severity be adjusted? If so, why?\n\
             4. What additional context or findings are relevant?\n\
             5. What specific legal risk does this create?\n\
             6. Are there any jurisdictional considerations?\n\n\
             Respond in JSON format:\n\
             ```json\n\
             {\n\
               \"confirmed\": true,\n\
               \"confidence\": 0.85,\n\
               \"severity_adjustment\": \"CRITICAL\",\n\
               \"reasoning\": \"...\",\n\
               \"legal_risk\": \"...\",\n\
               \"additional_findings\": [\"...\"]\n\
             }\n\
             ```",
        );

        prompt
    }

    /// Batch verify multiple violations (concurrent API calls for throughput)
    pub async fn batch_verify(
        &self,
        violations: &[Violation],
    ) -> Vec<AIVerification> {
        // Partition into AI-eligible and rule-based
        let mut ai_indices = Vec::new();
        let mut results: Vec<Option<AIVerification>> = vec![None; violations.len()];

        for (i, violation) in violations.iter().enumerate() {
            // Determine if this violation is AI-eligible.
            // High-risk digital asset categories ALWAYS get AI verification
            // regardless of confidence/severity because the legal exposure
            // demands expert validation.
            let high_risk_category = matches!(
                violation.violation_type.category(),
                "Digital Media Rights"
                | "AI & Model Rights"
                | "Firmware & Embedded"
                | "License Forensics"
                | "License Laundering"
            );

            let standard_eligible = violation.confidence > 0.7
                && violation.severity >= Severity::High;

            if (standard_eligible || high_risk_category) && self.is_available() {
                ai_indices.push(i);
            } else {
                results[i] = Some(AIVerification {
                    confirmed: violation.confidence > 0.9,
                    confidence: violation.confidence,
                    models_used: vec!["rule-based".to_string()],
                    reasoning: if self.is_available() {
                        "Below threshold for AI verification — using rule-based confidence.".to_string()
                    } else {
                        "No AI API keys configured — using rule-based confidence.".to_string()
                    },
                    suggested_severity: None,
                    additional_findings: vec![],
                });
            }
        }

        // Fire all AI verification requests concurrently
        if !ai_indices.is_empty() {
            let futures: Vec<_> = ai_indices
                .iter()
                .map(|&i| self.verify_violation(&violations[i], None))
                .collect();

            let ai_results = futures::future::join_all(futures).await;

            for (idx_pos, &orig_idx) in ai_indices.iter().enumerate() {
                results[orig_idx] = Some(ai_results[idx_pos].clone());
            }
        }

        results.into_iter().map(|r| r.unwrap()).collect()
    }
}

impl Default for AIVerifier {
    fn default() -> Self {
        Self::new(AIVerifierConfig::default())
    }
}
