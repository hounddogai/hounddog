use anyhow::Result;
use serde::Serialize;

use crate::enums::{Sensitivity, Severity, Source};
use crate::structs::ScanResults;

#[derive(Serialize)]
struct DataElement {
    id: String,
    name: String,
    sensitivity: Sensitivity,
    tags: Vec<String>,
    is_ai_generated: bool,
}

#[derive(Serialize)]
struct DataElementOccurrence {
    data_element: String,
    count: usize,
    locations: Vec<DataElementOccurrenceLocation>,
}

#[derive(Serialize)]
struct DataElementOccurrenceLocation {
    hash: String,
    code_segment: String,
    file: String,
    line_number: usize,
    category: String,
}

#[derive(Serialize)]
struct VulnerabilityRule {
    id: String,
    name: String,
    description: String,
    remediation: String,
    cwe: Vec<String>,
    owasp: Vec<String>,
}

#[derive(Serialize)]
struct Vulnerability {
    hash: String,
    code_segment: String,
    file: String,
    line_number: usize,
    start_column: usize,
    end_column: usize,
    severity: Severity,
    rule: String,
    data_elements: Vec<String>,
}

#[derive(Serialize)]
pub struct CacilianJson {
    repository: String,
    repository_url: String,
    branch: String,
    commit: String,
    data_elements: Vec<DataElement>,
    data_element_occurrences: Vec<DataElementOccurrence>,
    vulnerability_rules: Vec<VulnerabilityRule>,
    vulnerabilities: Vec<Vulnerability>,
}

pub fn generate_cacilian_output(results: &ScanResults) -> Result<CacilianJson> {
    let now = chrono::offset::Local::now();
    let file_path = match &results.output_filename {
        Some(path) => &results.repository.path.join(path),
        None => &results
            .repository
            .path
            .join(now.format("hounddog-%Y-%m-%d-%H-%M-%S.cacilian.json").to_string()),
    };
    let cacilian_json = CacilianJson {
        repository: results.repository.name.clone(),
        repository_url: results.repository.base_url.clone(),
        branch: results.repository.branch.clone(),
        commit: results.repository.commit.clone(),
        data_elements: results
            .data_elements
            .values()
            .map(|data_element| DataElement {
                id: data_element.id.clone(),
                name: data_element.name.clone(),
                sensitivity: data_element.sensitivity.clone(),
                tags: data_element.tags.clone(),
                is_ai_generated: data_element.source == Source::AI,
            })
            .collect(),

        data_element_occurrences: results
            .get_data_element_id_to_occurrences()
            .iter()
            .map(|(id, occurrences)| DataElementOccurrence {
                data_element: (*id).clone(),
                count: occurrences.len(),
                locations: occurrences
                    .iter()
                    .map(|occurrence| DataElementOccurrenceLocation {
                        hash: occurrence.hash.clone(),
                        code_segment: occurrence.code_segment.clone(),
                        file: occurrence.relative_file_path.clone(),
                        line_number: occurrence.line_start,
                        category: "Processing".to_string(),
                    })
                    .collect(),
            })
            .collect(),
        vulnerability_rules: results
            .data_sinks
            .values()
            .flat_map(|map| map.values())
            .map(|data_sink| VulnerabilityRule {
                id: data_sink.id.clone(),
                name: data_sink.name.clone(),
                description: data_sink.description.clone(),
                remediation: data_sink.remediation.clone(),
                cwe: data_sink.cwe.clone(),
                owasp: data_sink.owasp.clone(),
            })
            .collect(),
        vulnerabilities: results
            .vulnerabilities
            .iter()
            .map(|vul| Vulnerability {
                hash: vul.hash.clone(),
                code_segment: vul.code_segment.clone(),
                file: vul.relative_file_path.clone(),
                line_number: vul.line_start,
                start_column: vul.column_start,
                end_column: vul.column_end,
                severity: vul.severity.clone(),
                rule: vul.data_sink_id.clone(),
                data_elements: vul.data_element_names.clone(),
            })
            .collect(),
    };
    serde_json::to_writer_pretty(std::fs::File::create(file_path)?, &cacilian_json)?;
    println!("file://{}", file_path.display());
    Ok(cacilian_json)
}
