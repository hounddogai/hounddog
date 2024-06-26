use anyhow::Result;
use std::collections::HashMap;

use colored::Colorize;

use crate::output::common::get_sensitive_datamap_summary_table_rows;
use crate::structs::{DataElement, DataElementOccurrence, ScanConfig, ScanResults, Vulnerability};
use crate::{
    console_label, console_note, console_text, console_url_link, print_header, print_table,
};

pub fn print_scan_results_to_console(config: &ScanConfig, results: &ScanResults) -> Result<()> {
    print_sensitive_datamap_to_console(&config.data_elements, &results.data_element_occurrences);
    print_vulnerabilities_to_console(&results.vulnerabilities);
    Ok(())
}

fn print_sensitive_datamap_to_console(
    data_elements: &HashMap<String, DataElement>,
    data_element_occurrences: &Vec<DataElementOccurrence>,
) {
    print_header!("Sensitive Datamap");
    if data_element_occurrences.is_empty() {
        println!("No sensitive data elements detected.");
    } else {
        print_table(
            vec!["Sensitivity", "Data Element Name", "Data Element ID", "Count", "Tags", "Source"],
            get_sensitive_datamap_summary_table_rows(data_elements, data_element_occurrences),
        );
        println!(
            "{}",
            console_note!("To ignore a data element, use flag --skip-data-element=<ID>")
        );
    }
}

fn print_vulnerabilities_to_console(vulnerabilities: &Vec<Vulnerability>) {
    print_header!("Potential Data Leaks");
    if vulnerabilities.is_empty() {
        println!("No potential data leaks detected.");
        return;
    }
    for v in vulnerabilities.iter() {
        println!("{}", console_label!(severity: v.severity));
        println!(
            "{}",
            console_text!(
                severity: v.severity,
                "{}: {}",
                v.description,
                v.data_element_names.join(", "),
            )
        );
        println!("{}", console_url_link!(v.relative_file_path, v.line_start, v.column_start));
        print_code_block_to_console(&v.code_segment, v.line_start, v.line_end);
        println!("{}", console_note!("CWE/OWASP: {}", v.security_categories()));
        println!("{}", console_note!("To ignore, use flag --skip-vulnerability={}", v.hash));
        println!();
    }
}

fn print_code_block_to_console(code: &str, line_start: usize, line_end: usize) {
    let max_line_num_width = line_end.to_string().len();

    for (line_num, line) in code.lines().enumerate() {
        println!(
            "  {:<width$} {} {}",
            (line_start + line_num).to_string().truecolor(92, 145, 255).dimmed(),
            "│".truecolor(92, 145, 255).dimmed(),
            line,
            width = max_line_num_width
        );
    }
}
