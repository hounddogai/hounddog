use std::path::Path;

use graphql_parser::parse_schema;

use crate::scanner::database::ScanDatabase;
use crate::structs::ScanConfig;

pub struct GraphQLScanner;

impl GraphQLScanner {
    fn scan(
        &mut self,
        database: &ScanDatabase,
        config: &ScanConfig,
        file_path: &Path,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}
