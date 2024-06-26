use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use strum::IntoEnumIterator;

use crate::enums::{Language, Sensitivity, Severity};
use crate::structs::{
    DataElement, DataElementOccurrence, DataSink, DirectoryInfo, Vulnerability,
    VulnerabilitySummary,
};

pub fn get_dir_stats_table_rows(dir_info: &DirectoryInfo) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Language::iter()
        .filter_map(|language| {
            dir_info.per_lang_file_stats.get(&language).and_then(|stats| {
                if stats.file_count > 0 {
                    Some(vec![
                        language.to_string(),
                        stats.file_count.to_string(),
                        stats.line_count.to_string(),
                    ])
                } else {
                    None
                }
            })
        })
        .collect();

    if rows.len() > 1 {
        rows.push(vec![
            "Total".to_string(),
            dir_info.total_file_stats.file_count.to_string(),
            dir_info.total_file_stats.line_count.to_string(),
        ]);
    }
    rows
}

pub fn get_sensitive_datamap_summary_table_rows(
    data_elements: &HashMap<String, DataElement>,
    data_element_occurrences: &Vec<DataElementOccurrence>,
) -> Vec<Vec<String>> {
    let mut elem_to_count: Vec<(&DataElement, usize)> = data_element_occurrences
        .iter()
        .map(|occurrence| &occurrence.data_element_id)
        .fold(HashMap::new(), |mut map, id| {
            *map.entry(id).or_insert(0) += 1;
            map
        })
        .into_iter()
        .map(|(id, count)| (data_elements.get(id).unwrap(), count))
        .collect();

    elem_to_count.sort_by_key(|(elem, _)| (&elem.sensitivity, &elem.name));
    elem_to_count
        .iter()
        .map(|(data_element, count)| {
            vec![
                data_element.sensitivity.to_string(),
                data_element.name.to_string(),
                data_element.id.to_string(),
                count.to_string(),
                data_element.tags.join(", "),
                data_element.source.to_string(),
            ]
        })
        .collect()
}

pub fn get_vulnerability_summary(vulnerabilities: &Vec<Vulnerability>) -> VulnerabilitySummary {
    VulnerabilitySummary {
        critical: vulnerabilities.iter().filter(|v| v.severity == Severity::Critical).count(),
        medium: vulnerabilities.iter().filter(|v| v.severity == Severity::Medium).count(),
        low: vulnerabilities.iter().filter(|v| v.severity == Severity::Low).count(),
        total: vulnerabilities.len(),
    }
}

/// Returns a map of data elements to their Mermaid.js dataflow diagrams.
pub fn get_dataflow_visualizations(
    data_elements: &HashMap<String, DataElement>,
    data_sinks: &HashMap<Language, HashMap<String, DataSink>>,
    data_element_occurrences: &Vec<DataElementOccurrence>,
    vulnerabilities: &Vec<Vulnerability>,
) -> IndexMap<String, String> {
    let elem_id_to_files =
        data_element_occurrences.iter().fold(HashMap::new(), |mut map, occurrence| {
            map.entry(&occurrence.data_element_id)
                .or_insert_with(HashSet::new)
                .insert(&occurrence.relative_file_path);
            map
        });
    let elem_id_and_file_to_vulnerabilities: HashMap<(&String, &String), Vec<&Vulnerability>> =
        vulnerabilities.iter().fold(HashMap::new(), |mut map, v| {
            v.data_element_ids.iter().for_each(|elem_id| {
                map.entry((elem_id, &v.relative_file_path)).or_insert_with(Vec::new).push(v);
            });
            map
        });

    let mut elem_id_to_mermaid_diagram = IndexMap::new();
    for (elem_id, elem_files) in elem_id_to_files {
        let elem = data_elements.get(elem_id).unwrap();
        let mut elem_data_sinks = HashSet::new();
        let mut elem_diagram = "flowchart LR\n".to_string();
        let color = match elem.sensitivity {
            Sensitivity::Critical => "fill:#FF0000,color:#FFFFFF",
            Sensitivity::Medium => "fill:#FF6400,color:#FFFFFF",
            Sensitivity::Low => "fill:#F1C232,color:#000000",
        };
        elem_diagram.push_str(&format!("{}({})\n", elem_id, elem.name));
        elem_diagram.push_str(&format!("style {} {}\n", elem_id, color));

        for file in elem_files {
            let file_stem = file.split('/').last().unwrap();
            let file_id = &format!("{}#{}", elem_id, file.replace("/", "-"));

            elem_diagram.push_str(&format!("{}({})\n", file_id, file_stem));
            elem_diagram.push_str(&format!("style {} fill:#808080,color:#FFFFFF\n", file_id));
            elem_diagram.push_str(&format!("{} --> {}\n", elem_id, file_id));

            elem_id_and_file_to_vulnerabilities
                .get(&(elem_id, file))
                .unwrap_or(&vec![])
                .iter()
                .for_each(|v| {
                    let data_sink =
                        data_sinks.get(&v.language).unwrap().get(&v.data_sink_id).unwrap();
                    elem_data_sinks.insert((&data_sink.id, &data_sink.name));
                    elem_diagram.push_str(&format!(
                        "{} --> |<a href='{}'>L{}</a>| {}\n",
                        file_id, v.url_link, v.line_start, v.data_sink_id
                    ));
                });
        }
        for (data_sink_id, data_sink_name) in elem_data_sinks {
            elem_diagram.push_str(&format!("{}({})\n", data_sink_id, data_sink_name));
            elem_diagram.push_str(&format!("style {} {}\n", data_sink_id, color));
        }
        elem_id_to_mermaid_diagram.insert(elem_id.clone(), elem_diagram);
    }
    elem_id_to_mermaid_diagram.sort_by(|a, _, b, _| {
        let e1 = data_elements.get(a).unwrap();
        let e2 = data_elements.get(b).unwrap();
        e1.sensitivity.cmp(&e2.sensitivity).then_with(|| e1.name.cmp(&e2.name))
    });
    elem_id_to_mermaid_diagram
}
