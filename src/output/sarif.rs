use anyhow::Result;

use crate::structs::ScanResults;

pub struct Sarif;

pub fn generate_sarif_output(results: &ScanResults) -> Result<Sarif> {
    println!("Generating SARIF output ...");
    Ok(Sarif)
}
