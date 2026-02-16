//! SPDX License Expression Parser
//!
//! Parses compound SPDX expressions like:
//!   `MIT OR Apache-2.0`
//!   `GPL-2.0-only WITH Classpath-exception-2.0`
//!   `(MIT AND BSD-2-Clause) OR Apache-2.0`
//!
//! Required for real-world license compliance — most projects declare
//! compound expressions, not simple identifiers.

use crate::license::{LicenseFamily, LicenseId};
use serde::{Deserialize, Serialize};

/// A parsed SPDX license expression
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpdxExpression {
    /// Simple license identifier (e.g., "MIT")
    Simple(String),
    /// License with exception (e.g., "GPL-2.0 WITH Classpath-exception-2.0")
    WithException {
        license: String,
        exception: String,
    },
    /// Conjunction — both must be satisfied (e.g., "MIT AND BSD-2-Clause")
    And(Box<SpdxExpression>, Box<SpdxExpression>),
    /// Disjunction — either may be chosen (e.g., "MIT OR Apache-2.0")
    Or(Box<SpdxExpression>, Box<SpdxExpression>),
}

impl SpdxExpression {
    /// Parse an SPDX expression string
    pub fn parse(input: &str) -> Result<Self, String> {
        let tokens = tokenize(input)?;
        let (expr, rest) = parse_or(&tokens)?;
        if !rest.is_empty() {
            return Err(format!("Unexpected tokens after expression: {:?}", rest));
        }
        Ok(expr)
    }

    /// Extract all simple license identifiers from the expression
    pub fn licenses(&self) -> Vec<&str> {
        match self {
            SpdxExpression::Simple(id) => vec![id.as_str()],
            SpdxExpression::WithException { license, .. } => vec![license.as_str()],
            SpdxExpression::And(a, b) | SpdxExpression::Or(a, b) => {
                let mut r = a.licenses();
                r.extend(b.licenses());
                r
            }
        }
    }

    /// Convert all identifiers to LicenseId
    pub fn license_ids(&self) -> Vec<LicenseId> {
        self.licenses()
            .into_iter()
            .map(|s| LicenseId::new(s))
            .collect()
    }

    /// Check if any license in the expression is copyleft
    pub fn has_copyleft(&self) -> bool {
        self.licenses()
            .iter()
            .any(|l| LicenseFamily::from_spdx(l).is_copyleft())
    }

    /// Check if the expression allows choosing a permissive option (via OR)
    pub fn has_permissive_option(&self) -> bool {
        match self {
            SpdxExpression::Simple(id) => LicenseFamily::from_spdx(id).is_permissive(),
            SpdxExpression::WithException { license, .. } => {
                LicenseFamily::from_spdx(license).is_permissive()
            }
            SpdxExpression::Or(a, b) => a.has_permissive_option() || b.has_permissive_option(),
            SpdxExpression::And(a, b) => a.has_permissive_option() && b.has_permissive_option(),
        }
    }

    /// Check if a given license satisfies this expression
    pub fn satisfied_by(&self, license: &str) -> bool {
        let upper = license.to_uppercase();
        match self {
            SpdxExpression::Simple(id) => id.to_uppercase() == upper,
            SpdxExpression::WithException { license: l, .. } => l.to_uppercase() == upper,
            SpdxExpression::Or(a, b) => a.satisfied_by(license) || b.satisfied_by(license),
            SpdxExpression::And(a, b) => a.satisfied_by(license) && b.satisfied_by(license),
        }
    }

    /// Pretty-print the expression
    pub fn display(&self) -> String {
        match self {
            SpdxExpression::Simple(id) => id.clone(),
            SpdxExpression::WithException { license, exception } => {
                format!("{} WITH {}", license, exception)
            }
            SpdxExpression::And(a, b) => format!("({} AND {})", a.display(), b.display()),
            SpdxExpression::Or(a, b) => format!("({} OR {})", a.display(), b.display()),
        }
    }
}

impl std::fmt::Display for SpdxExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ─── Tokenizer ─────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Identifier(String),
    And,
    Or,
    With,
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                tokens.push(Token::LParen);
                chars.next();
            }
            ')' => {
                tokens.push(Token::RParen);
                chars.next();
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ' ' || c == '\t' || c == '(' || c == ')' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                match word.to_uppercase().as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "WITH" => tokens.push(Token::With),
                    _ => tokens.push(Token::Identifier(word)),
                }
            }
        }
    }

    Ok(tokens)
}

// ─── Recursive Descent Parser ──────────────────────────────────────
// Precedence: WITH > AND > OR (WITH binds tightest)

fn parse_or<'a>(tokens: &'a [Token]) -> Result<(SpdxExpression, &'a [Token]), String> {
    let (mut left, mut rest) = parse_and(tokens)?;

    while !rest.is_empty() && rest[0] == Token::Or {
        let (right, r) = parse_and(&rest[1..])?;
        left = SpdxExpression::Or(Box::new(left), Box::new(right));
        rest = r;
    }

    Ok((left, rest))
}

fn parse_and<'a>(tokens: &'a [Token]) -> Result<(SpdxExpression, &'a [Token]), String> {
    let (mut left, mut rest) = parse_with(tokens)?;

    while !rest.is_empty() && rest[0] == Token::And {
        let (right, r) = parse_with(&rest[1..])?;
        left = SpdxExpression::And(Box::new(left), Box::new(right));
        rest = r;
    }

    Ok((left, rest))
}

fn parse_with<'a>(tokens: &'a [Token]) -> Result<(SpdxExpression, &'a [Token]), String> {
    let (base, rest) = parse_primary(tokens)?;

    if !rest.is_empty() && rest[0] == Token::With {
        if rest.len() < 2 {
            return Err("Expected exception identifier after WITH".to_string());
        }
        if let Token::Identifier(exception) = &rest[1] {
            if let SpdxExpression::Simple(license) = base {
                return Ok((
                    SpdxExpression::WithException {
                        license,
                        exception: exception.clone(),
                    },
                    &rest[2..],
                ));
            }
        }
        return Err("WITH must follow a simple license identifier".to_string());
    }

    Ok((base, rest))
}

fn parse_primary<'a>(tokens: &'a [Token]) -> Result<(SpdxExpression, &'a [Token]), String> {
    if tokens.is_empty() {
        return Err("Unexpected end of expression".to_string());
    }

    match &tokens[0] {
        Token::LParen => {
            let (expr, rest) = parse_or(&tokens[1..])?;
            if rest.is_empty() || rest[0] != Token::RParen {
                return Err("Missing closing parenthesis".to_string());
            }
            Ok((expr, &rest[1..]))
        }
        Token::Identifier(id) => Ok((SpdxExpression::Simple(id.clone()), &tokens[1..])),
        other => Err(format!("Unexpected token: {:?}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() {
        let expr = SpdxExpression::parse("MIT").unwrap();
        assert_eq!(expr, SpdxExpression::Simple("MIT".into()));
        assert_eq!(expr.licenses(), vec!["MIT"]);
    }

    #[test]
    fn test_or() {
        let expr = SpdxExpression::parse("MIT OR Apache-2.0").unwrap();
        assert_eq!(expr.licenses().len(), 2);
        assert!(expr.satisfied_by("MIT"));
        assert!(expr.satisfied_by("Apache-2.0"));
        assert!(!expr.satisfied_by("GPL-3.0"));
    }

    #[test]
    fn test_and() {
        let expr = SpdxExpression::parse("MIT AND BSD-2-Clause").unwrap();
        assert_eq!(expr.licenses().len(), 2);
    }

    #[test]
    fn test_with_exception() {
        let expr = SpdxExpression::parse("GPL-2.0-only WITH Classpath-exception-2.0").unwrap();
        assert!(matches!(expr, SpdxExpression::WithException { .. }));
        assert_eq!(expr.licenses(), vec!["GPL-2.0-only"]);
    }

    #[test]
    fn test_complex_nested() {
        let expr = SpdxExpression::parse("(MIT AND BSD-2-Clause) OR Apache-2.0").unwrap();
        assert_eq!(expr.licenses().len(), 3);
        assert!(expr.has_permissive_option());
    }

    #[test]
    fn test_dual_license_or() {
        let expr = SpdxExpression::parse("MIT OR GPL-3.0-only").unwrap();
        assert!(expr.has_permissive_option());
        assert!(expr.has_copyleft()); // GPL-3.0 is copyleft
    }

    #[test]
    fn test_display() {
        let expr = SpdxExpression::parse("MIT OR Apache-2.0").unwrap();
        assert_eq!(expr.to_string(), "(MIT OR Apache-2.0)");
    }
}
