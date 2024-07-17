use anyhow::Result;
use colored::Colorize;

use crate::structs::ScanResults;
use crate::{console_label, console_note, console_text, console_url, print_header, print_table};

pub fn print_console_output(results: &ScanResults) -> Result<()> {
    print_header!("Vulnerabilities");
    if results.data_sinks.is_empty() {
        println!("No data sinks found in scanner rules.");
    } else if results.vulnerabilities.is_empty() {
        println!("No vulnerabilities detected.");
    } else {
        let counts = results.get_vulnerability_counts();
        print_table(
            vec!["Critical", "Medium", "Low", "Total"],
            vec![vec![
                counts.critical.to_string(),
                counts.medium.to_string(),
                counts.low.to_string(),
                counts.total.to_string(),
            ]],
        );

        for v in results.vulnerabilities.iter() {
            println!(
                "\n{}\n{}",
                console_label!(severity: v.severity),
                console_text!(
                    severity: v.severity,
                    "{}: {}",
                    v.description,
                    v.data_element_names.join(", "),
                )
            );
            println!("{}", console_url!(v.url_link));
            print_code_block(&v.code_segment, v.line_start, v.line_end);
            print_remediation(results.get_remediation(&v.language, &v.data_sink_id));
            println!("{}", console_note!("CWE/OWASP: {}", v.security_categories()));
            println!("{}", console_note!("To ignore, use flag --skip-vulnerability={}", v.hash));
        }
    }
    println!();

    print_header!("Sensitive Datamap");
    if results.data_elements.is_empty() {
        println!("No data elements found in scanner rules.");
    } else if results.occurrences.is_empty() {
        println!("No sensitive data elements detected.");
    } else {
        print_table(
            vec!["Sensitivity", "Data Element Name", "Data Element ID", "Count", "Tags", "Source"],
            results.get_sensitive_datamap_table_rows(),
        );
        println!(
            "{}",
            console_note!(
                "To ignore a data element, use flag --skip-data-element=<DATA-ELEMENT-ID>"
            )
        );
    }
    println!();
    Ok(())
}

fn print_code_block(code: &str, line_start: usize, line_end: usize) {
    let max_line_num_width = line_end.to_string().len();

    for (line_num, line) in code.lines().enumerate() {
        println!(
            "{:<width$} {} {}",
            (line_start + line_num).to_string().truecolor(92, 145, 255),
            "│".truecolor(92, 145, 255),
            line,
            width = max_line_num_width
        );
    }
    println!();
}

fn print_remediation(remediation: Option<&String>) {
    match remediation {
        Some(remediation) => {
            for line in remediation.lines() {
                println!("{}", line.trim_end_matches('\\'));
            }
            println!();
        }
        None => {}
    }
}
