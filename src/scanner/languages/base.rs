use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::Result;
use regex::Regex;
use tree_sitter::{Node, Parser};

use crate::enums::{Language, VisitChildren};
use crate::err;
use crate::scanner::database::ScanDatabase;
use crate::structs::FileScanContext;
use crate::structs::ScanConfig;
use crate::utils::file::get_file_language;

pub trait BaseScanner {
    /// Visit a node in the abstract syntax tree (AST).
    ///
    /// This method is called when a node in the AST is first encountered.
    ///
    /// # Arguments
    ///
    /// * `context` - Provides file-scoped contextual data and helper functions.
    /// * `node` - The current node in the abstract syntax tree.
    ///
    /// # Returns
    ///
    /// `true` if the scanner should continue scanning the node's children, `false` otherwise.
    fn visit_node(ctx: &mut FileScanContext, node: &Node) -> Result<VisitChildren>;

    /// Leave a node in the abstract syntax tree (AST).
    ///
    /// This method is called when the scanner has finished scanning a node and all its children.
    ///
    /// # Arguments
    ///
    /// * `context` - Provides file-scoped contextual data and helper functions.
    /// * `node` - The current node in the abstract syntax tree.
    fn leave_node(ctx: &mut FileScanContext, node: &Node);

    fn scan_file(
        database: &ScanDatabase,
        config: &ScanConfig,
        parser: &mut Parser,
        file_path: &PathBuf,
    ) -> Result<()> {
        let source = std::fs::read(file_path)?;
        let ast = parser
            .parse(&source, None)
            .ok_or(err!("Failed to parse {}", file_path.display()))?;

        let mut context = FileScanContext::new(database, config, file_path, &source);
        let mut cursor = ast.walk();
        let mut visited_all_children = false;

        loop {
            let node = cursor.node();
            if !visited_all_children {
                let visit_children = Self::visit_node(&mut context, &node)?;
                if visit_children == VisitChildren::No || !cursor.goto_first_child() {
                    visited_all_children = true;
                }
            } else if cursor.goto_next_sibling() {
                visited_all_children = false;
                Self::leave_node(&mut context, &node);
            } else {
                Self::leave_node(&mut context, &node);
                if !cursor.goto_parent() {
                    return Ok(());
                }
            }
        }
    }
}
