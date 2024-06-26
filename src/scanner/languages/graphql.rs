use std::path::Path;

use graphql_parser::parse_schema;

use crate::scanner::database::ScanDatabase;
use crate::structs::ScanConfig;

pub struct GraphQLAnalyzer;

impl GraphQLAnalyzer {
    fn scan(
        &mut self,
        database: &ScanDatabase,
        scan_config: &ScanConfig,
        file_path: &Path,
    ) -> anyhow::Result<()> {
        let relative_path = file_path.strip_prefix(&scan_config.scan_dir_path)?;
        let source = std::fs::read_to_string(file_path)?;
        let ast = parse_schema::<&str>(&source)?;
        Ok(())
    }
}
