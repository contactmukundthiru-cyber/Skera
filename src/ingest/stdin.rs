//! Stdin handler — buffers raw input, detects language, writes to temp file

use std::path::PathBuf;

pub struct StdinResult {
    pub output_dir: PathBuf,
    pub total_bytes: u64,
    pub detected_language: String,
    pub _temp_dir: tempfile::TempDir,
}

/// Buffer stdin content and prepare for scanning
pub async fn buffer_stdin(
    content: &str,
    filename_hint: Option<&str>,
) -> Result<StdinResult, String> {
    let temp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let output_dir = temp_dir.path().join("stdin");
    std::fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output dir: {}", e))?;

    // Detect language from content
    let detected_language = detect_language(content);

    // Determine filename
    let filename = filename_hint.unwrap_or_else(|| {
        match detected_language.as_str() {
            "javascript" => "input.js",
            "typescript" => "input.ts",
            "python" => "input.py",
            "rust" => "input.rs",
            "go" => "input.go",
            "java" => "input.java",
            "c" => "input.c",
            "cpp" => "input.cpp",
            "ruby" => "input.rb",
            "php" => "input.php",
            "css" => "input.css",
            "html" => "input.html",
            "json" => "input.json",
            _ => "input.txt",
        }
    });

    let file_path = output_dir.join(filename);
    std::fs::write(&file_path, content)
        .map_err(|e| format!("Failed to write stdin content: {}", e))?;

    Ok(StdinResult {
        output_dir,
        total_bytes: content.len() as u64,
        detected_language,
        _temp_dir: temp_dir,
    })
}

/// Heuristic language detection from source content
fn detect_language(content: &str) -> String {
    let first_1k = &content[..content.len().min(1000)];

    // JavaScript indicators
    if first_1k.contains("function ") || first_1k.contains("const ") || first_1k.contains("=>")
        || first_1k.contains("require(") || first_1k.contains("module.exports")
        || first_1k.contains("import ") && first_1k.contains(" from ")
    {
        // Could be TypeScript
        if first_1k.contains(": string") || first_1k.contains(": number")
            || first_1k.contains("interface ") || first_1k.contains("<T>")
        {
            return "typescript".to_string();
        }
        return "javascript".to_string();
    }

    // Python
    if first_1k.contains("def ") || first_1k.contains("import ") && first_1k.contains("from ")
        || first_1k.contains("class ") && first_1k.contains("self")
        || first_1k.starts_with("#!/usr/bin/env python")
        || first_1k.starts_with("#!/usr/bin/python")
    {
        return "python".to_string();
    }

    // Rust
    if first_1k.contains("fn ") || first_1k.contains("let mut ")
        || first_1k.contains("impl ") || first_1k.contains("pub fn")
        || first_1k.contains("use std::")
    {
        return "rust".to_string();
    }

    // Go
    if first_1k.contains("func ") || first_1k.contains("package ")
        || first_1k.contains("import (") || first_1k.contains(":= ")
    {
        return "go".to_string();
    }

    // Java
    if first_1k.contains("public class ") || first_1k.contains("public static void main")
        || first_1k.contains("System.out.println")
    {
        return "java".to_string();
    }

    // C/C++
    if first_1k.contains("#include") || first_1k.contains("int main(")
        || first_1k.contains("printf(")
    {
        if first_1k.contains("cout") || first_1k.contains("namespace")
            || first_1k.contains("class ") && first_1k.contains("{")
        {
            return "cpp".to_string();
        }
        return "c".to_string();
    }

    // Ruby
    if first_1k.contains("def ") && first_1k.contains("end")
        || first_1k.starts_with("#!/usr/bin/env ruby")
    {
        return "ruby".to_string();
    }

    // PHP
    if first_1k.contains("<?php") || first_1k.contains("<?=") {
        return "php".to_string();
    }

    // CSS
    if first_1k.contains("{") && (first_1k.contains("font-") || first_1k.contains("color:")
        || first_1k.contains("margin:") || first_1k.contains("padding:"))
    {
        return "css".to_string();
    }

    // HTML
    if first_1k.contains("<html") || first_1k.contains("<!DOCTYPE")
        || first_1k.contains("<head>") || first_1k.contains("<body>")
    {
        return "html".to_string();
    }

    // JSON
    if first_1k.starts_with('{') || first_1k.starts_with('[') {
        return "json".to_string();
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_javascript() {
        assert_eq!(detect_language("const x = () => { return 42; }"), "javascript");
    }

    #[test]
    fn test_detect_typescript() {
        assert_eq!(detect_language("function greet(name: string): void { }"), "typescript");
    }

    #[test]
    fn test_detect_python() {
        assert_eq!(detect_language("def hello():\n    print('hello')"), "python");
    }

    #[test]
    fn test_detect_rust() {
        assert_eq!(detect_language("fn main() {\n    let mut x = 5;\n}"), "rust");
    }

    #[test]
    fn test_detect_go() {
        assert_eq!(detect_language("package main\n\nfunc main() { }"), "go");
    }
}
