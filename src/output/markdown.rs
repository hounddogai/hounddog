use std::io::Write;

use anyhow::Result;
use indexmap::IndexMap;

use crate::{markdown_label, markdown_note, markdown_url};
use crate::enums::Severity;
use crate::structs::ScanResults;

pub fn generate_markdown_output(results: &ScanResults) -> Result<()> {
    println!("Saving Markdown output:");
    let now = chrono::offset::Local::now();
    let markdown_file_path = match &results.output_filename {
        Some(path) => &results.repository.path.join(path),
        None => &results
            .repository
            .path
            .join(now.format("hounddog-%Y-%m-%d-%H-%M-%S.md").to_string()),
    };
    let mut markdown = std::fs::File::create(markdown_file_path)?;

    writeln!(markdown, "# [HoundDog.ai](https://hounddog.ai) Report\n")?;
    writeln!(
        markdown,
        "The following Markdown report shows the results from HoundDog.ai code scanner.\n"
    )?;
    writeln!(markdown, "Generated on {}.\n", now.format("%Y-%m-%d %I:%M:%S %p"))?;

    writeln!(markdown, "\n# Vulnerabilities\n")?;
    if results.data_sinks.is_empty() {
        writeln!(markdown, "No data sinks found in scanner rules.")?;
    } else if results.vulnerabilities.is_empty() {
        writeln!(markdown, "No vulnerabilities detected.")?;
    } else {
        let counts = results.get_vulnerability_counts();
        writeln!(
            markdown,
            "|{}|{}|{}|Total Count|",
            markdown_label!(severity: Severity::Critical),
            markdown_label!(severity: Severity::Medium),
            markdown_label!(severity: Severity::Low),
        )?;
        writeln!(markdown, "|:-:|:-:|:-:|:-:|")?;
        writeln!(
            markdown,
            "|{}|{}|{}|{}|",
            counts.critical, counts.medium, counts.low, counts.total
        )?;
        for v in &results.vulnerabilities {
            let sink = match results.get_data_sink(&v.language, &v.data_sink_id) {
                Some(s) => s,
                None => continue,
            };
            // Severity label and title
            writeln!(
                markdown,
                "\n## {}<br>{}: {}\n",
                markdown_label!(severity: v.severity),
                sink.description,
                v.data_element_names.join(", "),
            )?;

            // File path or URL
            match results.repository.git_provider {
                Some(_) => writeln!(
                    markdown,
                    "[{}:{}:{}]({})\n",
                    v.relative_file_path, v.line_start, v.column_start, v.url_link
                )?,
                None => writeln!(
                    markdown,
                    "{}\n",
                    markdown_url!(format!("{}:{}", v.absolute_file_path, v.line_start))
                )?,
            }

            // Code segment and remediation
            writeln!(markdown, "```{}", v.language)?;
            writeln!(markdown, "{}", v.code_segment)?;
            writeln!(markdown, "```")?;
            writeln!(markdown, "{}", sink.remediation)?;

            // More details
            writeln!(markdown, "<details>")?;
            writeln!(markdown, "<summary>Click for more details</summary>\n")?;
            writeln!(
                markdown,
                "\nSecurity categories (CWE/OWASP): `{}` `{}`\n",
                v.cwe.join("` `"),
                v.owasp.join("` `"),
            )?;
            writeln!(
                markdown,
                "This vulnerability was rated as {0} as it involves a data element with {0} sensitivity.\\",
                markdown_label!(severity: v.severity),
            )?;
            writeln!(markdown, "Data elements involved:\n")?;
            writeln!(markdown, "|Sensitivity|Data Element Name|Data Element ID|Tags|")?;
            writeln!(markdown, "|:-|:-|:-|:-|")?;

            let mut data_elements = results.search_data_elements(&v.data_element_ids);
            data_elements.sort_by(|a, b| a.sensitivity.cmp(&b.sensitivity));

            for elem in data_elements {
                let label = markdown_label!(sensitivity: elem.sensitivity);
                writeln!(
                    markdown,
                    "|{}|{}|{}|{}|",
                    label,
                    elem.name,
                    elem.id,
                    elem.tags.join(",")
                )?;
            }
            writeln!(
                markdown,
                "\nTo ignore this vulnerability, use `--skip-vulnerability={}`",
                v.hash
            )?;
            writeln!(markdown, "\n</details>\n")?;
        }
    }

    // Sensitivity datamap and dataflow visualizations.
    if results.occurrences.is_empty() {
        writeln!(markdown, "# Sensitive Datamap\n")?;
        writeln!(markdown, "No sensitive data elements detected.")?;
        writeln!(markdown, "# Dataflow Visualizations\n")?;
        writeln!(markdown, "No sensitive data elements detected.")?;
    } else {
        writeln!(markdown, "# Sensitive Datamap\n")?;
        writeln!(markdown, "|Sensitivity|Data Element Name|Data Element ID|Count|Tags|Source|")?;
        writeln!(markdown, "|:-|:-|:-|:-|:-|:-|")?;

        results.get_sensitive_datamap_table_rows().iter().for_each(|row| {
            writeln!(markdown, "|{}|", row.join("|")).unwrap();
        });
        writeln!(markdown)?;

        let mut elem_id_to_occurrences = IndexMap::new();
        for occurrence in &results.occurrences {
            elem_id_to_occurrences
                .entry(&occurrence.data_element_id)
                .or_insert_with(Vec::new)
                .push(occurrence);
        }

        // Sort by sensitivity and then by name
        elem_id_to_occurrences.sort_by(|a, _, b, _| {
            let e1 = results.get_data_element(*a);
            let e2 = results.get_data_element(*b);
            e1.sensitivity.cmp(&e2.sensitivity).then_with(|| e1.name.cmp(&e2.name))
        });

        for (elem_id, occurrences) in elem_id_to_occurrences.iter() {
            let elem = results.get_data_element(elem_id);
            writeln!(markdown, "## {}\n", elem.name)?;
            for o in occurrences {
                match results.repository.git_provider {
                    Some(_) => writeln!(
                        markdown,
                        "[{}:{}:{}]({})\n",
                        o.relative_file_path, o.line_start, o.column_start, o.url_link
                    )?,
                    None => writeln!(
                        markdown,
                        "{}\n",
                        markdown_url!(format!("{}:{}", o.absolute_file_path, o.line_start))
                    )?,
                }
                writeln!(markdown, "```{}", o.language)?;
                writeln!(markdown, "{}", o.code_segment)?;
                writeln!(markdown, "```")?;
            }
            let ignore_instruction = markdown_note!(
                "To ignore this data element, use flag `--skip-data-element={}`\n",
                elem_id
            );
            writeln!(markdown, "{}", ignore_instruction)?;
        }
        writeln!(markdown, "# Dataflow Visualizations\n")?;
        for (elem_id, mermaid) in results.get_dataflow_visualizations().iter() {
            let elem = results.get_data_element(elem_id);
            writeln!(markdown, "## {}\n", elem.name)?;
            writeln!(markdown, "```mermaid")?;
            writeln!(markdown, "{}", mermaid)?;
            writeln!(markdown, "```")?;
        }
    }
    println!("file://{}", markdown_file_path.display());
    Ok(())
}
