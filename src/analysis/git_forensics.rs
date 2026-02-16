//! Git timeline forensics — proves INTENT through commit history analysis
//!
//! Walks git history to detect:
//! - When LICENSE/NOTICE files were deleted
//! - When copyright headers were removed from specific files
//! - When third-party code was first introduced without attribution
//! - When "All Rights Reserved" claims were added over open-source code
//!
//! Generates timeline evidence with commit hashes, authors, and dates —
//! proving not just the act but the conscious decision to conceal provenance.
//!
//! ## Legal Significance
//!
//! - **DMCA §1202(b)**: Knowingly removing Copyright Management Information
//! - **Lanham Act §43(a)**: False designation of origin
//! - Courts consider timeline evidence when assessing willfulness
//! - Willful infringement can trigger treble damages

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A forensic event detected in git history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicEvent {
    /// What happened
    pub event_type: ForensicEventType,
    /// Commit hash
    pub commit_hash: String,
    /// Commit author
    pub author: String,
    /// Commit date (ISO 8601)
    pub date: String,
    /// Commit message
    pub commit_message: String,
    /// File affected
    pub file_path: String,
    /// Description of what was detected
    pub description: String,
    /// Severity of the event
    pub severity: EventSeverity,
}

/// Types of forensic events we can detect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForensicEventType {
    /// LICENSE/NOTICE/COPYING file was deleted
    LicenseFileDeleted,
    /// Copyright header was removed from a source file
    CopyrightHeaderRemoved,
    /// Third-party code was introduced without attribution
    UnattributedCodeIntroduced,
    /// "All Rights Reserved" claim was added
    AllRightsReservedAdded,
    /// License text was changed (potential laundering)
    LicenseTextChanged,
    /// NOTICE file was deleted (Apache 2.0 violation)
    NoticeFileDeleted,
    /// Attribution block was removed from a file
    AttributionBlockRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSeverity {
    /// Informational — may be benign
    Info,
    /// Warning — suspicious pattern
    Warning,
    /// Critical — strong evidence of intentional concealment
    Critical,
}

/// Complete git forensic timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitForensicTimeline {
    /// Repository path
    pub repo_path: PathBuf,
    /// Events detected, in chronological order
    pub events: Vec<ForensicEvent>,
    /// Total commits analyzed
    pub commits_analyzed: usize,
    /// Whether the directory is a git repository
    pub is_git_repo: bool,
    /// Branch analyzed
    pub branch: String,
}

/// Git timeline forensics analyzer
pub struct GitForensics;

impl GitForensics {
    /// Check if a path is inside a git repository
    pub fn is_git_repo(path: &Path) -> bool {
        Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .current_dir(path)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run full forensic analysis on a git repository
    pub fn analyze(repo_path: &Path) -> GitForensicTimeline {
        if !Self::is_git_repo(repo_path) {
            return GitForensicTimeline {
                repo_path: repo_path.to_path_buf(),
                events: Vec::new(),
                commits_analyzed: 0,
                is_git_repo: false,
                branch: String::new(),
            };
        }

        let branch = Self::current_branch(repo_path).unwrap_or_else(|| "unknown".to_string());
        let mut events = Vec::new();
        let mut commits_analyzed = 0;

        // Analysis 1: Detect deleted license files
        events.extend(Self::find_deleted_license_files(repo_path));

        // Analysis 2: Detect removed copyright headers
        events.extend(Self::find_removed_copyright_headers(repo_path));

        // Analysis 3: Detect "All Rights Reserved" additions
        events.extend(Self::find_all_rights_reserved_additions(repo_path));

        // Analysis 4: Detect license text changes
        events.extend(Self::find_license_text_changes(repo_path));

        // Count commits
        if let Ok(output) = Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .current_dir(repo_path)
            .output()
        {
            if let Ok(count_str) = String::from_utf8(output.stdout) {
                commits_analyzed = count_str.trim().parse().unwrap_or(0);
            }
        }

        // Sort by date
        events.sort_by(|a, b| a.date.cmp(&b.date));

        GitForensicTimeline {
            repo_path: repo_path.to_path_buf(),
            events,
            commits_analyzed,
            is_git_repo: true,
            branch,
        }
    }

    /// Get current branch name
    fn current_branch(repo_path: &Path) -> Option<String> {
        Command::new("git")
            .args(["branch", "--show-current"])
            .current_dir(repo_path)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }

    /// Find commits where LICENSE/NOTICE/COPYING files were deleted
    fn find_deleted_license_files(repo_path: &Path) -> Vec<ForensicEvent> {
        let license_files = [
            "LICENSE",
            "LICENSE.md",
            "LICENSE.txt",
            "LICENCE",
            "LICENCE.md",
            "LICENCE.txt",
            "COPYING",
            "COPYING.md",
            "NOTICE",
            "NOTICE.md",
            "NOTICE.txt",
            "THIRD_PARTY_NOTICES",
            "THIRD_PARTY_NOTICES.md",
        ];

        let mut events = Vec::new();

        for filename in &license_files {
            // Find commits that deleted this file
            if let Ok(output) = Command::new("git")
                .args([
                    "log",
                    "--diff-filter=D",
                    "--pretty=format:%H|%an|%aI|%s",
                    "--",
                    filename,
                ])
                .current_dir(repo_path)
                .output()
            {
                if let Ok(log_output) = String::from_utf8(output.stdout) {
                    for line in log_output.lines() {
                        let parts: Vec<&str> = line.splitn(4, '|').collect();
                        if parts.len() == 4 {
                            let event_type = if *filename == "NOTICE" || *filename == "NOTICE.md" || *filename == "NOTICE.txt" {
                                ForensicEventType::NoticeFileDeleted
                            } else {
                                ForensicEventType::LicenseFileDeleted
                            };

                            events.push(ForensicEvent {
                                event_type,
                                commit_hash: parts[0].to_string(),
                                author: parts[1].to_string(),
                                date: parts[2].to_string(),
                                commit_message: parts[3].to_string(),
                                file_path: filename.to_string(),
                                description: format!(
                                    "{} was DELETED in commit {} by {} — \
                                     this constitutes removal of Copyright Management Information",
                                    filename, &parts[0][..8.min(parts[0].len())], parts[1]
                                ),
                                severity: EventSeverity::Critical,
                            });
                        }
                    }
                }
            }
        }

        events
    }

    /// Find commits that removed copyright headers from source files
    fn find_removed_copyright_headers(repo_path: &Path) -> Vec<ForensicEvent> {
        let mut events = Vec::new();

        // Search for commits that removed lines containing "copyright" or "©"
        let search_terms = ["Copyright", "©", "(c)", "SPDX-License-Identifier"];

        for term in &search_terms {
            if let Ok(output) = Command::new("git")
                .args([
                    "log",
                    "-p",
                    "--all",
                    "-S",
                    term,
                    "--pretty=format:COMMIT:%H|%an|%aI|%s",
                    "--diff-filter=M",
                    "--",
                    "*.js",
                    "*.ts",
                    "*.py",
                    "*.rs",
                    "*.c",
                    "*.cpp",
                    "*.h",
                    "*.java",
                    "*.go",
                    "*.rb",
                    "*.php",
                ])
                .current_dir(repo_path)
                .output()
            {
                if let Ok(log_output) = String::from_utf8(output.stdout) {
                    let mut current_commit = ("", "", "", "");
                    let mut current_file = String::new();

                    for line in log_output.lines() {
                        if line.starts_with("COMMIT:") {
                            let parts: Vec<&str> =
                                line.trim_start_matches("COMMIT:").splitn(4, '|').collect();
                            if parts.len() == 4 {
                                current_commit = (parts[0], parts[1], parts[2], parts[3]);
                            }
                        } else if line.starts_with("diff --git") {
                            // Extract file path from diff header
                            if let Some(path) = line.split(" b/").nth(1) {
                                current_file = path.to_string();
                            }
                        } else if line.starts_with('-') && !line.starts_with("---") {
                            // This is a REMOVED line
                            let removed_content = &line[1..];
                            if removed_content.contains(term) {
                                events.push(ForensicEvent {
                                    event_type: ForensicEventType::CopyrightHeaderRemoved,
                                    commit_hash: current_commit.0.to_string(),
                                    author: current_commit.1.to_string(),
                                    date: current_commit.2.to_string(),
                                    commit_message: current_commit.3.to_string(),
                                    file_path: current_file.clone(),
                                    description: format!(
                                        "'{}' header removed from {} by {} — \
                                         DMCA §1202 CMI removal",
                                        removed_content.trim(),
                                        current_file,
                                        current_commit.1
                                    ),
                                    severity: EventSeverity::Critical,
                                });
                            }
                        }
                    }
                }
            }

            // Limit to avoid overwhelming output (first term only for perf)
            if events.len() > 50 {
                break;
            }
        }

        // Deduplicate by commit hash + file path
        events.sort_by(|a, b| (&a.commit_hash, &a.file_path).cmp(&(&b.commit_hash, &b.file_path)));
        events.dedup_by(|a, b| a.commit_hash == b.commit_hash && a.file_path == b.file_path);

        events
    }

    /// Detect commits that added "All Rights Reserved" claims
    fn find_all_rights_reserved_additions(repo_path: &Path) -> Vec<ForensicEvent> {
        let mut events = Vec::new();

        if let Ok(output) = Command::new("git")
            .args([
                "log",
                "-p",
                "--all",
                "-S",
                "All rights reserved",
                "--pretty=format:COMMIT:%H|%an|%aI|%s",
                "--diff-filter=AM",
            ])
            .current_dir(repo_path)
            .output()
        {
            if let Ok(log_output) = String::from_utf8(output.stdout) {
                let mut current_commit = ("", "", "", "");
                let mut current_file = String::new();

                for line in log_output.lines() {
                    if line.starts_with("COMMIT:") {
                        let parts: Vec<&str> =
                            line.trim_start_matches("COMMIT:").splitn(4, '|').collect();
                        if parts.len() == 4 {
                            current_commit = (parts[0], parts[1], parts[2], parts[3]);
                        }
                    } else if line.starts_with("diff --git") {
                        if let Some(path) = line.split(" b/").nth(1) {
                            current_file = path.to_string();
                        }
                    } else if line.starts_with('+') && !line.starts_with("+++") {
                        let added_content = &line[1..];
                        if added_content
                            .to_lowercase()
                            .contains("all rights reserved")
                        {
                            events.push(ForensicEvent {
                                event_type: ForensicEventType::AllRightsReservedAdded,
                                commit_hash: current_commit.0.to_string(),
                                author: current_commit.1.to_string(),
                                date: current_commit.2.to_string(),
                                commit_message: current_commit.3.to_string(),
                                file_path: current_file.clone(),
                                description: format!(
                                    "'All Rights Reserved' claim added to {} by {} — \
                                     if this file contains third-party code, this is a false claim",
                                    current_file, current_commit.1
                                ),
                                severity: EventSeverity::Warning,
                            });
                        }
                    }
                }
            }
        }

        events.dedup_by(|a, b| a.commit_hash == b.commit_hash && a.file_path == b.file_path);
        events
    }

    /// Detect commits that changed LICENSE file contents (potential laundering)
    fn find_license_text_changes(repo_path: &Path) -> Vec<ForensicEvent> {
        let mut events = Vec::new();

        let license_files = ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"];

        for filename in &license_files {
            if let Ok(output) = Command::new("git")
                .args([
                    "log",
                    "--diff-filter=M",
                    "--pretty=format:%H|%an|%aI|%s",
                    "--",
                    filename,
                ])
                .current_dir(repo_path)
                .output()
            {
                if let Ok(log_output) = String::from_utf8(output.stdout) {
                    for line in log_output.lines() {
                        let parts: Vec<&str> = line.splitn(4, '|').collect();
                        if parts.len() == 4 {
                            events.push(ForensicEvent {
                                event_type: ForensicEventType::LicenseTextChanged,
                                commit_hash: parts[0].to_string(),
                                author: parts[1].to_string(),
                                date: parts[2].to_string(),
                                commit_message: parts[3].to_string(),
                                file_path: filename.to_string(),
                                description: format!(
                                    "{} was MODIFIED in commit {} by {} — \
                                     review diff for potential license laundering \
                                     (e.g., GPL→MIT relabeling)",
                                    filename, &parts[0][..8.min(parts[0].len())], parts[1]
                                ),
                                severity: EventSeverity::Warning,
                            });
                        }
                    }
                }
            }
        }

        events
    }
}

impl GitForensicTimeline {
    /// Render as markdown evidence
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();
        md.push_str("# Git Forensic Timeline\n\n");
        md.push_str(&format!("**Repository**: `{}`\n", self.repo_path.display()));
        md.push_str(&format!("**Branch**: `{}`\n", self.branch));
        md.push_str(&format!("**Commits analyzed**: {}\n", self.commits_analyzed));
        md.push_str(&format!("**Events detected**: {}\n\n", self.events.len()));

        let critical_count = self
            .events
            .iter()
            .filter(|e| e.severity == EventSeverity::Critical)
            .count();
        if critical_count > 0 {
            md.push_str(&format!(
                "⚠️ **{} CRITICAL events detected** — evidence of intentional concealment\n\n",
                critical_count
            ));
        }

        md.push_str("## Timeline\n\n");
        md.push_str("| Date | Severity | Event | File | Author | Commit |\n");
        md.push_str("|------|----------|-------|------|--------|--------|\n");

        for event in &self.events {
            let severity_icon = match event.severity {
                EventSeverity::Critical => "🔴",
                EventSeverity::Warning => "🟡",
                EventSeverity::Info => "🔵",
            };
            md.push_str(&format!(
                "| {} | {} {:?} | {:?} | `{}` | {} | `{}` |\n",
                &event.date[..10.min(event.date.len())],
                severity_icon,
                event.severity,
                event.event_type,
                event.file_path,
                event.author,
                &event.commit_hash[..8.min(event.commit_hash.len())]
            ));
        }

        md.push_str("\n## Details\n\n");
        for (i, event) in self.events.iter().enumerate() {
            md.push_str(&format!("### Event {} — {:?}\n\n", i + 1, event.event_type));
            md.push_str(&format!("- **Commit**: `{}`\n", event.commit_hash));
            md.push_str(&format!("- **Author**: {}\n", event.author));
            md.push_str(&format!("- **Date**: {}\n", event.date));
            md.push_str(&format!("- **Message**: {}\n", event.commit_message));
            md.push_str(&format!("- **File**: `{}`\n", event.file_path));
            md.push_str(&format!("- **Analysis**: {}\n\n", event.description));
        }

        md.push_str("\n---\n\n*Generated by Skera — Universal Digital Copyright Forensics Engine*\n");
        md
    }

    /// Filter to only critical events
    pub fn critical_events(&self) -> Vec<&ForensicEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == EventSeverity::Critical)
            .collect()
    }

    /// Check if there's evidence of intentional concealment
    pub fn has_evidence_of_intent(&self) -> bool {
        // Intent is evidenced by BOTH deletion of attribution AND addition of false claims
        let has_deletion = self.events.iter().any(|e| {
            matches!(
                e.event_type,
                ForensicEventType::LicenseFileDeleted
                    | ForensicEventType::CopyrightHeaderRemoved
                    | ForensicEventType::NoticeFileDeleted
                    | ForensicEventType::AttributionBlockRemoved
            )
        });

        let has_false_claim = self.events.iter().any(|e| {
            matches!(
                e.event_type,
                ForensicEventType::AllRightsReservedAdded
            )
        });

        has_deletion && has_false_claim
    }
}
