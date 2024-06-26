use std::collections::HashMap;
use std::fs::{read_dir, read_to_string, File};
use std::path::Path;

use anyhow::Result;
use colored::Colorize;

use crate::enums::Language;
use crate::print_err;
use crate::structs::{DataElement, DataSink, Sanitizer};

pub fn get_local_data_elements(dir: &Path) -> Result<HashMap<String, DataElement>> {
    let data_elements_dir = dir.join("data-elements");

    let mut data_elements = HashMap::new();
    for entry in read_dir(data_elements_dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let file = File::open(&path)?;
            let data_element: DataElement = serde_json::from_reader(file)?;
            data_elements.insert(data_element.id.clone(), data_element);
        }
    }
    Ok(data_elements)
}

pub fn get_local_data_sinks(dir: &Path) -> Result<HashMap<Language, HashMap<String, DataSink>>> {
    let data_sinks_dir = dir.join("data-sinks");
    let remediations_dir = dir.join("remediations");
    
    let mut data_sinks: HashMap<Language, HashMap<String, DataSink>> = HashMap::new();
    for entry in read_dir(data_sinks_dir)? {
        let path = entry?.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            match serde_json::from_str::<DataSink>(&read_to_string(&path)?) {
                Ok(mut data_sink) => {
                    let remediation_path = remediations_dir.join(format!("{}.md", data_sink.id));
                    if remediation_path.exists() {
                        data_sink.remediation = read_to_string(remediation_path)?;
                    }
                    data_sinks
                        .entry(data_sink.language)
                        .or_default()
                        .insert(data_sink.id.clone(), data_sink);
                }
                Err(e) => print_err!("Error parsing {}: {}", path.display(), e),
            }
        }
    }
    Ok(data_sinks)
}

pub fn get_local_sanitizers(dir: &Path) -> Result<Vec<Sanitizer>> {
    let file = File::open(dir.join("sanitizers/sanitizers.json"))?;
    let sanitizers: Vec<Sanitizer> = serde_json::from_reader(file)?;
    Ok(sanitizers)
}
