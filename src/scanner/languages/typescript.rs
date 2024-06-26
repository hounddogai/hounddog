use anyhow::Result;
use tree_sitter::Node;
use crate::enums::VisitChildren;
use crate::scanner::languages::base::BaseScanner;
use crate::structs::FileScanContext;

pub struct TypescriptScanner;

impl BaseScanner for TypescriptScanner {
    fn visit_node(state: &mut FileScanContext, node: &Node) -> Result<VisitChildren> {
        Ok(VisitChildren::No)
    }

    fn leave_node(state: &mut FileScanContext, node: &Node) {}
}
