//! SPDX expression parser
//!
//! Parses SPDX license expressions like "MIT OR Apache-2.0" or
//! "(GPL-2.0-only WITH Classpath-exception-2.0) AND MIT"

use super::LicenseId;
use serde::{Deserialize, Serialize};

/// Parsed SPDX expression tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpdxExpression {
    /// Single license identifier
    License(LicenseId),
    /// License with exception (e.g., GPL-2.0-only WITH Classpath-exception-2.0)
    WithException(LicenseId, String),
    /// Disjunction — either license is acceptable
    Or(Box<SpdxExpression>, Box<SpdxExpression>),
    /// Conjunction — both licenses apply simultaneously
    And(Box<SpdxExpression>, Box<SpdxExpression>),
}

impl SpdxExpression {
    /// Parse an SPDX expression string
    pub fn parse(expr: &str) -> Option<Self> {
        let trimmed = expr.trim();
        if trimmed.is_empty() {
            return None;
        }

        // Handle parenthesized expressions
        let trimmed = if trimmed.starts_with('(') && trimmed.ends_with(')') {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };

        // Split on OR (lowest precedence)
        if let Some(pos) = find_operator(trimmed, " OR ") {
            let left = Self::parse(&trimmed[..pos])?;
            let right = Self::parse(&trimmed[pos + 4..])?;
            return Some(Self::Or(Box::new(left), Box::new(right)));
        }

        // Split on AND
        if let Some(pos) = find_operator(trimmed, " AND ") {
            let left = Self::parse(&trimmed[..pos])?;
            let right = Self::parse(&trimmed[pos + 5..])?;
            return Some(Self::And(Box::new(left), Box::new(right)));
        }

        // Handle WITH exception
        if let Some(pos) = find_operator(trimmed, " WITH ") {
            let license = trimmed[..pos].trim();
            let exception = trimmed[pos + 6..].trim();
            return Some(Self::WithException(
                LicenseId::new(license),
                exception.to_string(),
            ));
        }

        // Single license identifier
        Some(Self::License(LicenseId::new(trimmed)))
    }

    /// Extract all license IDs from the expression
    pub fn license_ids(&self) -> Vec<&LicenseId> {
        match self {
            Self::License(id) => vec![id],
            Self::WithException(id, _) => vec![id],
            Self::Or(left, right) | Self::And(left, right) => {
                let mut ids = left.license_ids();
                ids.extend(right.license_ids());
                ids
            }
        }
    }

    /// Check if any license in the expression is copyleft
    pub fn has_copyleft(&self) -> bool {
        self.license_ids().iter().any(|id| id.is_copyleft())
    }
}

/// Find operator position outside of parentheses
fn find_operator(expr: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let bytes = expr.as_bytes();

    for i in 0..expr.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && expr[i..].starts_with(op) {
            return Some(i);
        }
    }
    None
}
