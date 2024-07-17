use anyhow::Result;

use crate::structs::ScanResults;

pub struct GitlabJson;

pub fn generate_gitlab_output(results: &ScanResults) -> Result<GitlabJson> {
    println!("Generating GitLab JSON file ...");
    Ok(GitlabJson)
}
