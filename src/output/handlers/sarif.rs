use anyhow::Result;

use crate::structs::{ScanConfig, ScanResults};

pub struct SarifReport;

pub fn export_sarif(scan_config: &ScanConfig, scan_results: &ScanResults) -> Result<SarifReport> {
    println!("Generating SARIF report ...");
    Ok(SarifReport)
}
