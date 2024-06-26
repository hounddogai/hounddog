use anyhow::Result;

use crate::structs::{ScanConfig, ScanResults};

pub struct GitlabReport;

pub fn export_gitlab_json(config: &ScanConfig, results: &ScanResults) -> Result<GitlabReport> {
    println!("Generating GitLab report ...");
    Ok(GitlabReport)
}
