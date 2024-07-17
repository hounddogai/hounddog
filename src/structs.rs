use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use git2::PushOptions;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::enums::{GitProvider, Language, OutputFormat, ScopeType, Sensitivity, Severity, Source};
use crate::scanner::database::ScanDatabase;
use crate::utils::file::get_file_language;
use crate::utils::git::get_url_link;
use crate::utils::hash::calculate_md5_hash;
use crate::utils::serde::{
    deserialize_regex, deserialize_regex_option, deserialize_regex_vec, serialize_regex,
    serialize_regex_option, serialize_regex_vec,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub org_id: String,
    pub org_name: String,
}

#[derive(Debug, Serialize)]
pub struct FileStats {
    pub file_count: usize,
    pub line_count: usize,
}

impl FileStats {
    pub fn new() -> FileStats {
        FileStats { file_count: 0, line_count: 0 }
    }
}

#[derive(Debug, Serialize)]
pub struct DirectoryInfo {
    pub git_remote_url: String,
    pub git_repo_name: String,
    pub git_branch: String,
    pub git_commit: String,
    pub git_provider: Option<GitProvider>,
    pub per_lang_file_stats: HashMap<Language, FileStats>,
    pub total_file_stats: FileStats,
}

pub fn return_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct DataElement {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(deserialize_with = "deserialize_regex_vec")]
    #[serde(serialize_with = "serialize_regex_vec")]
    pub include_patterns: Vec<Regex>,
    #[serde(deserialize_with = "deserialize_regex_vec")]
    #[serde(serialize_with = "serialize_regex_vec")]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct DataSinkMatchRule {
    pub clue : Option<String>,
    #[serde(deserialize_with = "deserialize_regex_option")]
    #[serde(serialize_with = "serialize_regex_option")]
    #[serde(default)]
    pub regex: Option<Regex>,
}

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct Sanitizer {
    #[serde(deserialize_with = "deserialize_regex")]
    #[serde(serialize_with = "serialize_regex")]
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
    #[serde(rename(deserialize = "file"))]
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
                ctx.config.scan_dir_info.git_repo_name,
                ctx.config.scan_dir_info.git_branch,
                data_element.id.clone(),
                ctx.relative_file_path.display().to_string(),
                ctx.get_node_text(node)
            )),
            language: ctx.language.clone(),
            code_segment: ctx.get_code_line(node),
            relative_file_path: ctx.relative_file_path.display().to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            url_link: get_url_link(
                &ctx.config.scan_dir_info.git_provider,
                &ctx.config.scan_dir_info.git_remote_url,
                &ctx.config.scan_dir_info.git_commit,
                &ctx.display_file_path,
                line_start,
                line_end,
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
                ctx.config.scan_dir_info.git_repo_name,
                ctx.config.scan_dir_info.git_branch,
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
            relative_file_path: ctx.relative_file_path.display().to_string(),
            line_start,
            line_end,
            column_start,
            column_end,
            url_link: get_url_link(
                &ctx.config.scan_dir_info.git_provider,
                &ctx.config.scan_dir_info.git_remote_url,
                &ctx.config.scan_dir_info.git_commit,
                &ctx.display_file_path,
                line_start,
                line_end,
            ),
            cwe: data_sink.cwe.clone(),
            owasp: data_sink.owasp.clone(),
        }
    }

    pub fn security_categories(&self) -> String {
        format!("{}, {}", self.cwe.join(", "), self.owasp.join(", "))
    }
}

#[derive(Debug)]
pub struct ScanConfig<'a> {
    pub scan_dir_path: &'a PathBuf,
    pub scan_dir_info: &'a DirectoryInfo,
    pub data_elements: &'a HashMap<String, DataElement>,
    pub data_sinks: &'a HashMap<Language, HashMap<String, DataSink>>,
    pub sanitizers: &'a Vec<Sanitizer>,
    pub output_filename: &'a Option<String>,
    pub output_format: &'a OutputFormat,
    pub skip_data_elements: HashSet<String>,
    pub skip_data_sinks: HashSet<String>,
    pub skip_occurrence_hashes: HashSet<String>,
    pub skip_vulnerability_hashes: HashSet<String>,
}

impl<'a> ScanConfig<'a> {
    pub fn new(
        scan_dir_path: &'a PathBuf,
        scan_dir_info: &'a DirectoryInfo,
        data_elements: &'a HashMap<String, DataElement>,
        data_sinks: &'a HashMap<Language, HashMap<String, DataSink>>,
        sanitizers: &'a Vec<Sanitizer>,
        output_filename: &'a Option<String>,
        output_format: &'a OutputFormat,
        skip_data_elements: &'a Vec<String>,
        skip_data_sinks: &'a Vec<String>,
        skip_occurrence_hashes: &'a Vec<String>,
        skip_vulnerability_hashes: &'a Vec<String>,
    ) -> ScanConfig<'a> {
        ScanConfig {
            scan_dir_path,
            scan_dir_info,
            data_elements,
            data_sinks,
            sanitizers,
            output_filename,
            output_format,
            skip_data_elements: skip_data_elements
                .iter()
                .map(|data_element_id| data_element_id.to_lowercase())
                .collect(),
            skip_data_sinks: skip_data_sinks
                .iter()
                .map(|data_sink_id| data_sink_id.to_lowercase())
                .collect(),
            skip_occurrence_hashes: skip_occurrence_hashes
                .iter()
                .map(|hash| hash.to_uppercase())
                .collect(),
            skip_vulnerability_hashes: skip_vulnerability_hashes
                .iter()
                .map(|hash| hash.to_uppercase())
                .collect(),
        }
    }

    pub fn get_data_element(&self, id: &str) -> &DataElement {
        self.data_elements.get(id).unwrap()
    }
}

#[derive(Debug, Serialize)]
pub struct ScanResults {
    pub data_element_occurrences: Vec<DataElementOccurrence>,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl ScanResults {
    pub fn new(
        data_element_occurrences: Vec<DataElementOccurrence>,
        mut vulnerabilities: Vec<Vulnerability>,
    ) -> ScanResults {
        vulnerabilities.sort_by(|a, b| a.severity.cmp(&b.severity));
        ScanResults {
            data_element_occurrences,
            vulnerabilities,
        }
    }
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
    pub config: &'a ScanConfig<'a>,
    pub absolute_file_path: &'a PathBuf,
    pub relative_file_path: &'a Path,
    pub display_file_path: String,
    pub source: &'a [u8],
    pub language: Language,
    scopes: Vec<CodeScope>,
    data_sinks_cache: HashMap<String, &'a DataSink>,
    data_elements_cache: HashMap<String, &'a DataElement>,
}

impl<'a> FileScanContext<'a> {
    pub fn new(
        scan_database: &'a ScanDatabase,
        scan_config: &'a ScanConfig,
        file_path: &'a PathBuf,
        file_source: &'a [u8],
    ) -> FileScanContext<'a> {
        let relative_file_path = file_path.strip_prefix(&scan_config.scan_dir_path).unwrap();

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
        }
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

    pub fn find_data_element(&mut self, name: &str) -> Option<&'a DataElement> {
        if let Some(data_element) = self.data_elements_cache.get(name) {
            return Some(data_element);
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
                Some(data_element)
            }
            None => None,
        }
    }

    pub fn find_data_sink(&mut self, name: &str) -> Option<&'a DataSink> {
        if let Some(data_sink) = self.data_sinks_cache.get(name) {
            return Some(data_sink);
        }

        // If the name is an alias, use the original name.
        let orig_name: String = self
            .scopes
            .iter()
            .rev()
            .find_map(|s| s.aliases.get(name).cloned())
            .unwrap_or_else(|| name.to_string());

        let data_sink = self
            .config
            .data_sinks
            .get(&self.language)
            .unwrap()
            .values()
            .find(|data_sink| data_sink.is_match(&orig_name));

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
        if !self.config.skip_occurrence_hashes.contains(&occurrence.hash) {
            self.database.put_data_element_occurrence(&occurrence).unwrap();
        }
        Ok(())
    }

    pub fn put_vulnerability(&self, vulnerability: Vulnerability) -> Result<()> {
        if !self.config.skip_vulnerability_hashes.contains(&vulnerability.hash) {
            self.database.put_vulnerability(&vulnerability).unwrap()
        }
        Ok(())
    }
}

pub struct VulnerabilitySummary {
    pub critical: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}
