use std::env;

use ::tree_sitter::{Language, Parser};
use anyhow::Result;
use tree_sitter_python::language as language_python;
use tree_sitter_typescript::language_typescript;

use database::ScanDatabase;
use languages::base::BaseScanner;
use languages::{PythonScanner, TypescriptScanner};

use crate::structs::{ScanConfig, ScanResults};
use crate::utils::file::get_files_in_dir;

pub mod common;
pub mod database;
pub mod languages;

pub fn run_scan(config: &ScanConfig) -> Result<ScanResults> {
    let database = ScanDatabase::new(env::temp_dir().join("hounddog.db").as_path());
    let mut py_parser = initialize_parser(language_python());
    let mut ts_parser = initialize_parser(language_typescript());

    for file in get_files_in_dir(&config.scan_dir_path) {
        let _ = match file.extension().unwrap_or_default().to_str().unwrap() {
            "py" => PythonScanner::scan_file(&database, config, &mut py_parser, &file),
            "js" | "jsx" | "ts" | "tsx" => {
                TypescriptScanner::scan_file(&database, config, &mut ts_parser, &file)
            }
            _ => Ok(()),
        };
    }
    Ok(ScanResults::new(database.get_data_element_occurrences()?, database.get_vulnerabilities()?))
}

fn initialize_parser(language: Language) -> Parser {
    let mut parser = Parser::new();
    parser.set_language(&language).unwrap();
    parser
}
