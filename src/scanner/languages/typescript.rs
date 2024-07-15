use anyhow::Result;
use tree_sitter::Node;
use crate::enums::VisitChildren;
use crate::scanner::languages::base::BaseScanner;
use crate::structs::{DataElementOccurrence, FileScanContext};

pub struct TypescriptScanner;

impl BaseScanner for TypescriptScanner {
    fn visit_node(state: &mut FileScanContext, node: &Node) -> Result<VisitChildren> {
        match (node.kind()) {
            "identifier" => {}
            "property_identifier"  => {
                let text = state.get_node_text(node);
                if let Some(data_element) = state.find_data_element(&text) {
                    let _ = state.put_occurrence(DataElementOccurrence::from_node(
                        state,
                        node,
                        &data_element,
                    ));
                    return Ok(VisitChildren::No); // Do not look at parts of the same attribute again.
                }
            }
            "method_definition" => {}
            "function_declaration" => {}
            "type_identifier" => {}
            _ => {}
        }
        Ok(VisitChildren::Yes)
    }

    fn leave_node(state: &mut FileScanContext, node: &Node) {}
}
