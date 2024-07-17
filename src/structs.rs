use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tree_sitter::Node;

use crate::enums::{GitProvider, Language, OutputFormat, ScopeType, Sensitivity, Severity, Source};
use crate::scanner::database::ScanDatabase;
use crate::utils::file::get_file_language;
use crate::utils::git::get_url_link;
use crate::utils::hash::calculate_md5_hash;
use crate::utils::serde::{deserialize_regex, deserialize_regex_option, deserialize_regex_vec};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub org_id: String,
    pub org_name: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FileStats {
    pub file_count: usize,
    pub line_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct Repository {
    pub path: PathBuf,
    pub base_url: String,
    pub name: String,
    pub branch: String,
    pub commit: String,
    pub git_provider: Option<GitProvider>,
    pub per_lang_file_stats: HashMap<Language, FileStats>,
    pub total_file_stats: FileStats,
}

impl Repository {
    pub fn get_dir_stats_table_rows(&self) -> Vec<Vec<String>> {
        let mut rows: Vec<Vec<String>> = Language::iter()
            .filter_map(|language| {
                self.per_lang_file_stats.get(&language).and_then(|stats| {
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
                self.total_file_stats.file_count.to_string(),
                self.total_file_stats.line_count.to_string(),
            ]);
        }
        rows
    }
}

fn return_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct DataElement {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(deserialize_with = "deserialize_regex_vec")]
    pub include_patterns: Vec<Regex>,
    #[serde(deserialize_with = "deserialize_regex_vec")]
    pub exclude_patterns: Vec<Regex>,
    #[serde(default = "return_true")]
    pub is_enabled: bool,
    pub sensitivity: Sensitivity,
    pub source: Source,
    pub tags: Vec<String>,
}

impl DataElement {
    pub fn is_match(&self, s: &str) -> bool {
        self.include_patterns.iter().any(|p| p.is_match(s))
            && !self.exclude_patterns.iter().any(|p| p.is_match(s))
    }
}

impl Hash for DataElement {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        (&self.id).hash(state);
    }
}

impl Eq for DataElement {}

impl PartialEq for DataElement {
    fn eq(&self, other: &Self) -> bool {
        &self.id == &other.id
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSinkMatchRule {
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_regex_option")]
    pub regex: Option<Regex>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataSink {
    pub id: String,
    pub description: String,
    pub language: Language,
    pub name: String,
    pub cwe: Vec<String>,
    pub owasp: Vec<String>,
    pub match_rules: Vec<DataSinkMatchRule>,
    #[serde(default)]
    pub remediation: String,
}

impl DataSink {
    pub fn is_match(&self, s: &str) -> bool {
        for matcher in &self.match_rules {
            if let Some(regex) = &matcher.regex {
                if regex.is_match(s) {
                    return true;
                }
            }
        }
        return false;
    }
}

impl Hash for DataSink {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        (&self.id).hash(state);
    }
}

impl PartialEq for DataSink {
    fn eq(&self, other: &Self) -> bool {
        &self.id == &other.id
    }
}

impl Eq for DataSink {}

#[derive(Debug, Deserialize)]
pub struct Sanitizer {
    #[serde(deserialize_with = "deserialize_regex")]
    pub pattern: Regex,
    pub source: Source,
    pub description: String,
    #[serde(rename = "type")]
    pub sanitizer_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataElementOccurrence {
    pub data_element_id: String,
    pub data_element_name: String,
    pub hash: String,
    pub sensitivity: Sensitivity,
    pub language: Language,
    pub code_segment: String,
    pub absolute_file_path: String,
    pub relative_file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub url_link: String,
    pub source: Source,
    pub tags: Vec<String>,
}

impl DataElementOccurrence {
    pub fn from_node(
        ctx: &FileScanContext,
        node: &Node,
        data_element: &DataElement,
    ) -> DataElementOccurrence {
        let start_pos = node.start_position();
        let end_pos = node.end_position();
        let line_start = start_pos.row + 1;
        let line_end = end_pos.row + 1;
        let column_start = start_pos.column + 1;
        let column_end = end_pos.column + 1;

        DataElementOccurrence {
            data_element_id: data_element.id.clone(),
            data_element_name: data_element.name.clone(),
            sensitivity: data_element.sensitivity.clone(),
            hash: calculate_md5_hash(format!(
                "{}|{}|{}|{}|{}",
                ctx.config.repository.name,
                ctx.config.repository.branch,
                data_element.id.clone(),
                ctx.relative_file_path.display().to_string(),
                ctx.get_node_text(node)
            )),
            language: ctx.language.clone(),
            code_segment: ctx.get_code_line(node),
            absolute_file_path: ctx.absolute_file_path.display().to_string(),
            relative_file_path: ctx.relative_file_path.display().to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            url_link: get_url_link(
                &ctx.config.repository.base_url,
                &ctx.config.repository.commit,
                &ctx.display_file_path,
                &ctx.config.repository.git_provider,
                line_start,
                line_end,
                column_start,
            ),
            source: data_element.source.clone(),
            tags: data_element.tags.clone(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Vulnerability {
    pub data_sink_id: String,
    pub data_element_ids: Vec<String>,
    pub data_element_names: Vec<String>,
    pub hash: String,
    pub description: String,
    pub severity: Severity,
    pub language: Language,
    pub code_segment: String,
    pub absolute_file_path: String,
    pub relative_file_path: String,
    pub line_start: usize,
    pub line_end: usize,
    pub column_start: usize,
    pub column_end: usize,
    pub url_link: String,
    pub cwe: Vec<String>,
    pub owasp: Vec<String>,
}

impl Vulnerability {
    pub fn from_node(
        ctx: &FileScanContext,
        node: &Node,
        data_sink: &DataSink,
        data_elements: &Vec<&DataElement>,
    ) -> Vulnerability {
        let start_pos = node.start_position();
        let end_pos = node.end_position();
        let line_start = start_pos.row + 1;
        let line_end = end_pos.row + 1;
        let column_start = start_pos.column + 1;
        let column_end = end_pos.column + 1;

        Vulnerability {
            data_sink_id: data_sink.id.clone(),
            data_element_ids: data_elements.iter().map(|elem| elem.id.clone()).collect(),
            data_element_names: data_elements.iter().map(|elem| elem.name.clone()).collect(),
            hash: calculate_md5_hash(format!(
                "{}|{}|{}|{}|{}",
                ctx.config.repository.name,
                ctx.config.repository.branch,
                data_sink.id.clone(),
                ctx.relative_file_path.display().to_string(),
                ctx.get_node_text(node).trim(),
            )),
            description: data_sink.description.clone(),
            severity: data_elements
                .iter()
                .map(|elem| &elem.sensitivity)
                .min()
                .map(|s| match s {
                    Sensitivity::Critical => Severity::Critical,
                    Sensitivity::Medium => Severity::Medium,
                    Sensitivity::Low => Severity::Low,
                })
                .unwrap(),
            language: ctx.language.clone(),
            code_segment: ctx.get_code_block(node),
            absolute_file_path: ctx.absolute_file_path.display().to_string(),
            relative_file_path: ctx.relative_file_path.display().to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            url_link: get_url_link(
                &ctx.config.repository.base_url,
                &ctx.config.repository.commit,
                &ctx.display_file_path,
                &ctx.config.repository.git_provider,
                line_start,
                line_end,
                column_start,
            ),
            cwe: data_sink.cwe.clone(),
            owasp: data_sink.owasp.clone(),
        }
    }

    pub fn security_categories(&self) -> String {
        format!("{}, {}", self.cwe.join(", "), self.owasp.join(", "))
    }
}

#[derive(Debug, Serialize)]
pub struct DataflowVisualization {
    pub data_element_id: String,
    pub mermaid: String,
}

#[derive(Debug)]
pub struct ScanConfig {
    pub is_debug: bool,
    pub is_paid_features_enabled: bool,
    pub repository: Repository,
    pub data_elements: HashMap<String, DataElement>,
    pub data_sinks: HashMap<Language, HashMap<String, DataSink>>,
    pub sanitizers: Vec<Sanitizer>,
    pub output_filename: Option<String>,
    pub output_format: OutputFormat,
    pub skip_data_elements: HashSet<String>,
    pub skip_data_sinks: HashSet<String>,
    pub skip_occurrences: HashSet<String>,
    pub skip_vulnerabilities: HashSet<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResults<'a> {
    pub repository: &'a Repository,
    #[serde(skip)]
    pub output_filename: &'a Option<String>,
    #[serde(skip)]
    pub output_format: &'a OutputFormat,
    #[serde(skip)]
    pub data_elements: &'a HashMap<String, DataElement>,
    #[serde(skip)]
    pub data_sinks: &'a HashMap<Language, HashMap<String, DataSink>>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub occurrences: Vec<DataElementOccurrence>,
}

impl<'a> ScanResults<'a> {
    pub fn new(
        config: &'a ScanConfig,
        mut vulnerabilities: Vec<Vulnerability>,
        mut occurrences: Vec<DataElementOccurrence>,
    ) -> ScanResults<'a> {
        vulnerabilities.sort_by(|a, b| a.severity.cmp(&b.severity));
        occurrences.sort_by(|a, b| a.sensitivity.cmp(&b.sensitivity));

        ScanResults {
            repository: &config.repository,
            output_filename: &config.output_filename,
            output_format: &config.output_format,
            data_elements: &config.data_elements,
            data_sinks: &config.data_sinks,
            vulnerabilities,
            occurrences,
        }
    }

    pub fn search_data_elements(&self, ids: &Vec<String>) -> Vec<&DataElement> {
        ids.iter().filter_map(|id| self.data_elements.get(id)).collect()
    }

    pub fn get_data_element(&self, id: &str) -> &DataElement {
        self.data_elements.get(id).unwrap()
    }

    pub fn get_data_sink(&self, language: &Language, id: &str) -> Option<&DataSink> {
        self.data_sinks.get(language).and_then(|map| map.get(id))
    }

    pub fn get_remediation(&self, language: &Language, id: &str) -> Option<&String> {
        self.get_data_sink(language, id).map(|sink| &sink.remediation)
    }

    pub fn get_data_element_id_to_occurrences(
        &self,
    ) -> HashMap<&String, Vec<&DataElementOccurrence>> {
        self.occurrences.iter().fold(HashMap::new(), |mut map, occurrence| {
            map.entry(&occurrence.data_element_id).or_insert_with(Vec::new).push(occurrence);
            map
        })
    }

    pub fn get_sensitive_datamap_table_rows(&self) -> Vec<Vec<String>> {
        let mut elem_to_count: Vec<(&DataElement, usize)> = self
            .occurrences
            .iter()
            .map(|occurrence| &occurrence.data_element_id)
            .fold(HashMap::new(), |mut map, id| {
                *map.entry(id).or_insert(0) += 1;
                map
            })
            .into_iter()
            .map(|(id, count)| (self.data_elements.get(id).unwrap(), count))
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

    pub fn get_vulnerability_counts(&self) -> VulnerabilityCounts {
        VulnerabilityCounts {
            critical: self
                .vulnerabilities
                .iter()
                .filter(|v| v.severity == Severity::Critical)
                .count(),
            medium: self.vulnerabilities.iter().filter(|v| v.severity == Severity::Medium).count(),
            low: self.vulnerabilities.iter().filter(|v| v.severity == Severity::Low).count(),
            total: self.vulnerabilities.len(),
        }
    }

    pub fn get_dataflow_visualizations(&self) -> IndexMap<String, String> {
        let elem_id_to_files =
            self.occurrences.iter().fold(HashMap::new(), |mut map, occurrence| {
                map.entry(&occurrence.data_element_id)
                    .or_insert_with(HashSet::new)
                    .insert(&occurrence.relative_file_path);
                map
            });

        let elem_id_and_file_to_vulnerabilities: HashMap<(&String, &String), Vec<&Vulnerability>> =
            self.vulnerabilities.iter().fold(HashMap::new(), |mut map, v| {
                v.data_element_ids.iter().for_each(|elem_id| {
                    map.entry((elem_id, &v.relative_file_path)).or_insert_with(Vec::new).push(v);
                });
                map
            });

        let mut elem_id_to_mermaid = IndexMap::new();

        for (elem_id, elem_files) in elem_id_to_files {
            let elem = self.data_elements.get(elem_id).unwrap();
            let mut elem_data_sinks = HashSet::new();
            let mut mermaid = "flowchart LR\n".to_string();
            let color = match elem.sensitivity {
                Sensitivity::Critical => "fill:#FF0000,color:#FFFFFF",
                Sensitivity::Medium => "fill:#FF6400,color:#FFFFFF",
                Sensitivity::Low => "fill:#F1C232,color:#000000",
            };
            mermaid.push_str(&format!("{}({})\n", elem_id, elem.name));
            mermaid.push_str(&format!("style {} {}\n", elem_id, color));

            for file in elem_files {
                let file_stem = file.split('/').last().unwrap();
                let file_id = &format!("{}#{}", elem_id, file.replace("/", "-"));

                mermaid.push_str(&format!("{}({})\n", file_id, file_stem));
                mermaid.push_str(&format!("style {} fill:#808080,color:#FFFFFF\n", file_id));
                mermaid.push_str(&format!("{} --> {}\n", elem_id, file_id));

                elem_id_and_file_to_vulnerabilities
                    .get(&(elem_id, file))
                    .unwrap_or(&vec![])
                    .iter()
                    .for_each(|v| {
                        match self
                            .data_sinks
                            .get(&v.language)
                            .and_then(|map| map.get(&v.data_sink_id))
                        {
                            Some(data_sink) => {
                                elem_data_sinks.insert((&data_sink.id, &data_sink.name));
                                mermaid.push_str(&format!(
                                    "{} --> |<a href='{}'>L{}</a>| {}\n",
                                    file_id, v.url_link, v.line_start, v.data_sink_id
                                ));
                            }
                            None => {}
                        }
                    });
            }
            for (data_sink_id, data_sink_name) in elem_data_sinks {
                mermaid.push_str(&format!("{}({})\n", data_sink_id, data_sink_name));
                mermaid.push_str(&format!("style {} {}\n", data_sink_id, color));
            }
            elem_id_to_mermaid.insert(elem_id.clone(), mermaid);
        }
        elem_id_to_mermaid.sort_by(|a, _, b, _| {
            let e1 = self.data_elements.get(a).unwrap();
            let e2 = self.data_elements.get(b).unwrap();
            e1.sensitivity.cmp(&e2.sensitivity).then_with(|| e1.name.cmp(&e2.name))
        });
        elem_id_to_mermaid
    }
}

pub struct ScanUpload {
    pub directory_info: Repository,
    pub vulnerabilities: Vec<Vulnerability>,
    pub data_element_occurrences: Vec<DataElementOccurrence>,
}

pub struct CodeScope {
    // Type of the scope (e.g., function, class).
    pub scope_type: ScopeType,
    // Name of the scope (e.g., function name, class name).
    pub scope_name: String,
    // Variable aliases (from imports, assignments etc).
    pub aliases: HashMap<String, String>,
}

impl<'a> CodeScope {
    pub fn new(scope_type: ScopeType, scope_name: String) -> CodeScope {
        CodeScope { scope_type, scope_name, aliases: HashMap::new() }
    }
}

pub struct FileScanContext<'a> {
    pub database: &'a ScanDatabase,
    pub config: &'a ScanConfig,
    pub absolute_file_path: &'a PathBuf,
    pub relative_file_path: &'a Path,
    pub display_file_path: String,
    pub source: &'a [u8],
    pub language: Language,
    scopes: Vec<CodeScope>,
    data_sinks_cache: HashMap<String, &'a DataSink>,

    data_elements_cache: HashMap<String, &'a DataElement>,
    pub data_element_aliases: HashMap<String, Vec<String>>,
}

impl<'a> FileScanContext<'a> {
    pub fn new(
        scan_database: &'a ScanDatabase,
        scan_config: &'a ScanConfig,
        file_path: &'a PathBuf,
        file_source: &'a [u8],
    ) -> FileScanContext<'a> {
        let relative_file_path = file_path.strip_prefix(&scan_config.repository.path).unwrap();

        FileScanContext {
            database: scan_database,
            config: scan_config,
            absolute_file_path: file_path,
            relative_file_path,
            display_file_path: relative_file_path.display().to_string(),
            source: file_source,
            language: get_file_language(&file_path).unwrap(),
            scopes: vec![],
            data_sinks_cache: HashMap::new(),
            data_elements_cache: HashMap::new(),
            data_element_aliases: HashMap::new(),
        }
    }

    pub fn set_data_element_aliases(&mut self, left: String, right: String) {
        let values = vec![right];
        self.data_element_aliases
            .entry(left)
            .or_insert_with(Vec::new)
            .extend(values.iter().map(|v| v.to_string()));
    }
    pub fn enter_global_scope(&mut self) {
        self.scopes.push(CodeScope::new(ScopeType::Global, "global".to_string()));
    }

    pub fn enter_anonymous_scope(&mut self, node: &Node) {
        self.scopes.push(CodeScope::new(ScopeType::Anonymous, self.get_node_text(node)));
    }

    pub fn enter_class_scope(&mut self, node: &Node) {
        self.scopes.push(CodeScope::new(ScopeType::Class, self.get_node_name(node)));
    }

    pub fn enter_function_scope(&mut self, node: &Node) {
        self.scopes.push(CodeScope::new(ScopeType::Function, self.get_node_name(node)));
    }

    pub fn exit_current_scope(&mut self) {
        self.scopes.pop();
    }

    pub fn get_current_scope(&self) -> &CodeScope {
        self.scopes.last().unwrap()
    }

    pub fn find_data_element(&mut self, name: &str) -> Vec<Option<&'a DataElement>> {
        if let Some(data_element) = self.data_elements_cache.get(name) {
            return vec![Some(data_element)];
        }
        if let Some(data_element_names) = self.data_element_aliases.get(name) {
            let mut options = vec![];
            for data_element_name in data_element_names {
                let option = self.data_elements_cache.get(data_element_name);
                options.push(option.copied());
            }
            return options;
        }

        let normalized_name = name.replace(".", "_");
        let data_element = self
            .config
            .data_elements
            .values()
            .find(|data_element| data_element.is_match(&normalized_name));

        match data_element {
            Some(data_element) => {
                self.data_elements_cache.insert(name.to_string(), data_element);
                vec![Some(data_element)]
            }
            None => None,
        }
    }

    pub fn find_data_sink(&mut self, name: &str) -> Option<&'a DataSink> {
        if let Some(data_sink) = self.data_sinks_cache.get(name) {
            return Some(data_sink);
        }

        // If the name is an alias, use the original name.
        let original_name: String = self
            .scopes
            .iter()
            .rev()
            .find_map(|s| s.aliases.get(name).cloned())
            .unwrap_or_else(|| name.to_string());

        let data_sink = self
            .config
            .data_sinks
            .get(&self.language)?
            .values()
            .find(|data_sink| data_sink.is_match(&original_name));

        match data_sink {
            Some(data_sink) => {
                self.data_sinks_cache.insert(name.to_string(), data_sink);
                Some(data_sink)
            }
            None => None,
        }
    }

    pub fn get_node_text(&self, node: &Node) -> String {
        node.utf8_text(self.source).unwrap().to_string()
    }

    pub fn get_node_name(&self, node: &Node) -> String {
        node.child_by_field_name("name")
            .unwrap()
            .utf8_text(self.source)
            .unwrap()
            .to_string()
    }

    pub fn get_code_block(&self, node: &Node) -> String {
        let text = self.get_node_text(node);
        let code_block =
            format!("{:>width$}", text, width = text.len() + node.start_position().column);

        // De-dent code block
        let code_lines = code_block.lines().collect::<Vec<&str>>();

        let min_indent_length = code_lines
            .iter()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.chars().take_while(|c| c.is_whitespace()).count())
            .min()
            .unwrap_or(0);

        code_lines
            .iter()
            .map(|line| &line[min_indent_length..])
            .collect::<Vec<&str>>()
            .join("\n")
    }

    pub fn get_code_line(&self, node: &Node) -> String {
        let mut start = node.start_byte();
        let mut end = node.end_byte();

        // Find the start of the line
        start = self.source[..start]
            .iter()
            .rposition(|&ch| ch == b'\n')
            .map_or(0, |position| position + 1);

        // Find the end of the line
        end = self.source[end..]
            .iter()
            .position(|&ch| ch == b'\n')
            .map_or(self.source.len(), |pos| end + pos);

        // Trim whitespaces, commas, and semicolons from the beginning and end of the line
        String::from_utf8_lossy(&self.source[start..end])
            .trim_matches(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .to_string()
    }

    pub fn put_alias(&mut self, name: String, alias: String) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.aliases.insert(name, alias);
        }
    }

    pub fn put_occurrence(&self, occurrence: DataElementOccurrence) -> Result<()> {
        if !self.config.skip_occurrences.contains(&occurrence.hash) {
            self.database.put_data_element_occurrence(&occurrence).unwrap();
        }
        Ok(())
    }

    pub fn put_vulnerability(&self, vulnerability: Vulnerability) -> Result<()> {
        if !self.config.skip_vulnerabilities.contains(&vulnerability.hash) {
            self.database.put_vulnerability(&vulnerability).unwrap()
        }
        Ok(())
    }
}

pub struct VulnerabilityCounts {
    pub critical: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}
