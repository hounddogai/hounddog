use std::collections::VecDeque;

use anyhow::Result;
use tree_sitter::Node;

use crate::enums::VisitChildren;
use crate::scanner::languages::base::BaseScanner;
use crate::structs::{DataElementOccurrence, FileScanContext, Vulnerability};

pub struct TypescriptScanner;

impl BaseScanner for TypescriptScanner {
    fn visit_node(state: &mut FileScanContext, node: &Node) -> Result<VisitChildren> {
        match (node.kind()) {
            "identifier" | "property_identifier" => {
                let text = state.get_node_text(node);
                for data_elem in state.find_data_element(&text) {
                    if let Some(data_element) = data_elem {
                        let _ = state.put_occurrence(DataElementOccurrence::from_node(
                            state,
                            node,
                            &data_element,
                        ));
                        return Ok(VisitChildren::No); // Do not look at parts of the same attribute again.
                    }
                }
            }
            "method_definition" => {}
            "function_declaration" => {}
            "type_identifier" => {}
            "member_expression" => {}
            "assignment_expression" => {
                let left_node = node.child_by_field_name("left").unwrap();
                let left_node_text = state.get_node_text(&left_node);

                if let Some(right_node) = node.child_by_field_name("right") {
                    let children = find_all_child_member_expressions(right_node);
                    for child in children{
                        state.set_data_element_aliases(left_node_text.clone(),
                                                       state.get_node_text(&child));
                    }
                }
            }
            "call_expression" => {
                let func_node = get_child_by_field(node, "function");

                let func_name = state.get_node_text(&func_node);

                if let Some(data_sink) = state.find_data_sink(&func_name) {
                    let mut data_elements = vec![];
                    for arg in
                        find_all_child_member_expressions(get_child_by_field(node, "arguments"))
                    {
                        match arg.kind() {
                            "identifier" | "property_identifier" => {

                                let arg_text = state.get_node_text(&arg);
                                for data_element in state.find_data_element(&arg_text) {
                                    if let Some(elem) = data_element {
                                        data_elements.push(elem);
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                    if !data_elements.is_empty() {
                        let _ = state.put_vulnerability(Vulnerability::from_node(
                            state,
                            node,
                            data_sink,
                            &data_elements,
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(VisitChildren::Yes)
    }

    fn leave_node(state: &mut FileScanContext, node: &Node) {}
}

fn find_all_child_member_expressions(node: Node) -> Vec<Node> {
    let mut all_children = vec![node]; // Start with the current node

    if node.kind() == "member_expression" {
        all_children.push(node.child_by_field_name("property").unwrap());
    } else {
        // Recursively traverse all children of the current node
        for child in node.children(&mut node.walk()) {
            all_children.extend(find_all_child_member_expressions(child));
        }
    }

    all_children
}

pub fn get_child_by_field<'a>(node: &'a Node, field: &str) -> Node<'a> {
    node.child_by_field_name(field).unwrap()
}

pub fn get_children<'a>(node: &'a Node) -> VecDeque<Node<'a>> {
    let mut cursor = node.walk();
    VecDeque::from_iter(node.children(&mut cursor))
}

pub fn get_children_by_field<'a>(node: &'a Node, field: &str) -> VecDeque<Node<'a>> {
    let mut cursor = node.walk();
    VecDeque::from_iter(node.children_by_field_name(field, &mut cursor))
}
