use anyhow::Result;
use std::io::Write;

use indexmap::IndexMap;

use crate::enums::Severity;
use crate::output::common::{
    get_dataflow_visualizations, get_sensitive_datamap_summary_table_rows,
    get_vulnerability_summary,
};
use crate::structs::{ScanConfig, ScanResults, VulnerabilitySummary};
use crate::{markdown_label, markdown_note, markdown_text};


pub fn export_markdown_report(config: &ScanConfig, results: &ScanResults) -> Result<()> {
    println!("\nExporting Markdown report:");
    let current_time = chrono::offset::Local::now();
    let file_path = match &config.output_filename {
        Some(path) => &config.scan_dir_path.join(path),
        None => &config
            .scan_dir_path
            .join(current_time.format("hounddog-%Y-%m-%d-%H-%M-%S.md").to_string()),
    };
    let mut md = std::fs::File::create(file_path)?;

    // Overview Section
    writeln!(md, "# [HoundDog.ai](https://hounddog.ai) Report\n")?;
    writeln!(md, "The following report shows results from HoundDog.ai code scanner.\n")?;
    writeln!(md, "Generated on {}.\n", current_time.format("%Y-%m-%d %I:%M:%S %p"))?;

    writeln!(md, "\n# Potential Data Leaks\n")?;
    if results.vulnerabilities.is_empty() {
        writeln!(md, "No potential vulnerabilities detected.")?;
    } else {
        let VulnerabilitySummary { critical, medium, low, total } =
            get_vulnerability_summary(&results.vulnerabilities);
        writeln!(
            md,
            "|{}|{}|{}|Total|",
            markdown_label!(severity: Severity::Critical),
            markdown_label!(severity: Severity::Medium),
            markdown_label!(severity: Severity::Low),
        )?;
        writeln!(md, "|:-:|:-:|:-:|:-:|")?;
        writeln!(md, "|{}|{}|{}|{}|", critical, medium, low, total)?;

        // Print the vulnerabilities for each data sink, ordered by severity
        for v in &results.vulnerabilities {
            let sink =
                config.data_sinks.get(&v.language).unwrap().get(&v.data_sink_id).unwrap();
            writeln!(
                md,
                "## {}<br>{}\n",
                markdown_label!(severity: v.severity),
                markdown_text!(severity: v.severity, "{}: {}", sink.description, v.data_element_names.join(", ")),
            )?;
            writeln!(
                md,
                "{}\n```{}\n{}\n```",
                format!(
                    "[{}:{}:{}]({})",
                    v.relative_file_path, v.line_start, v.column_start, v.url_link
                ),
                v.language,
                v.code_segment
            )?;
            write!(md, "{}\n\n", sink.remediation)?;
            writeln!(
                md,
                "{}<br>{}\n",
                markdown_note!(
                    "Security categories: `{}` `{}`",
                    v.cwe.join("` `"),
                    v.owasp.join("` `")
                ),
                markdown_note!(
                    "To ignore this issue, use flag `--skip-vulnerability={}`",
                    v.hash
                )
            )?;
        }
    }

    // Sensitivity datamap and dataflow visualizations.
    if results.data_element_occurrences.is_empty() {
        writeln!(md, "# Sensitive Datamap\n")?;
        writeln!(md, "No sensitive data elements detected.")?;
        writeln!(md, "# Dataflow Visualizations\n")?;
        writeln!(md, "No sensitive data elements detected.")?;
    } else {
        writeln!(md, "# Sensitive Datamap\n")?;
        writeln!(md, "|Sensitivity|Data Element Name|Data Element ID|Count|Tags|Source|")?;
        writeln!(md, "|:-|:-|:-|:-|:-|:-|")?;

        get_sensitive_datamap_summary_table_rows(
            &config.data_elements,
            &results.data_element_occurrences,
        )
        .iter()
        .for_each(|row| {
            writeln!(md, "|{}|", row.join("|")).unwrap();
        });
        writeln!(md)?;

        let mut elem_id_to_occurrences = IndexMap::new();
        for occurrence in &results.data_element_occurrences {
            elem_id_to_occurrences
                .entry(&occurrence.data_element_id)
                .or_insert_with(Vec::new)
                .push(occurrence);
        }

        // Sort by sensitivity and then by name
        elem_id_to_occurrences.sort_by(|a, _, b, _| {
            let e1 = config.get_data_element(*a);
            let e2 = config.get_data_element(*b);
            e1.sensitivity.cmp(&e2.sensitivity).then_with(|| e1.name.cmp(&e2.name))
        });

        for (elem_id, occurrences) in elem_id_to_occurrences.iter() {
            let elem = config.get_data_element(elem_id);
            let header = markdown_text!(sensitivity: elem.sensitivity, "{}", elem.name);
            writeln!(md, "## {}\n", header)?;
            for occurrence in occurrences {
                let link = format!(
                    "[{}:{}:{}]({})",
                    occurrence.relative_file_path,
                    occurrence.line_start,
                    occurrence.column_start,
                    occurrence.url_link
                );
                writeln!(md, "{}\n", link)?;
                writeln!(md, "```{}", occurrence.language)?;
                writeln!(md, "{}", occurrence.code_segment)?;
                writeln!(md, "```")?;
            }
            let ignore_instruction = markdown_note!(
                "To ignore this data element, use flag `--skip-data-element={}`\n",
                elem_id
            );
            writeln!(md, "{}", ignore_instruction)?;
        }

        let elem_id_to_mermaid_diagrams = get_dataflow_visualizations(
            &config.data_elements,
            &config.data_sinks,
            &results.data_element_occurrences,
            &results.vulnerabilities,
        );
        writeln!(md, "# Dataflow Visualizations\n")?;
        for (elem_id, mermaid_diagram) in elem_id_to_mermaid_diagrams.iter() {
            let elem = config.get_data_element(elem_id);
            let header = markdown_text!(sensitivity: elem.sensitivity, "{}", elem.name);
            writeln!(md, "## {}\n", header)?;
            writeln!(md, "```mermaid")?;
            writeln!(md, "{}", mermaid_diagram)?;
            writeln!(md, "```")?;
        }
    }
    println!("file://{}", file_path.display());
    Ok(())
}
