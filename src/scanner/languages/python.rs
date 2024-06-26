use anyhow::Result;
use tree_sitter::Node;

use crate::enums::VisitChildren;
use crate::scanner::languages::BaseScanner;
use crate::scanner::common::{
    get_child_by_field, get_children, get_children_by_field,
};
use crate::structs::{DataElementOccurrence, Vulnerability};
use crate::structs::FileScanContext;

pub struct PythonScanner;


impl BaseScanner for PythonScanner {
    fn visit_node(ctx: &mut FileScanContext, node: &Node) -> Result<VisitChildren> {
        match node.kind() {
            "module" => {
                ctx.enter_global_scope();
            }
            // e.g. `class ExampleClass:`
            "class_definition" => {
                ctx.enter_class_scope(node);
            }
            // e.g. `def example_function():`
            "function_definition" => {
                ctx.enter_function_scope(node);
            }
            // e.g. `lambda x: x + 1`
            "lambda" => {
                ctx.enter_anonymous_scope(node);
            }
            // e.g. `[x for x in range(10)]`
            "list_comprehension" => {
                ctx.enter_anonymous_scope(node);
            }
            // e.g. `(x for x in range(10))`
            "generator_expression" => {
                ctx.enter_anonymous_scope(node);
            }
            // e.g. `import urllib.request as request`
            "import_statement" => {
                for child in get_children(node) {
                    // e.g. `import urllib.request as request`
                    if child.kind() == "aliased_import" {
                        // e.g. urllib.request
                        let module_name = ctx.get_node_text(&get_child_by_field(&child, "name"));
                        // e.g. request
                        let alias = ctx.get_node_text(&get_child_by_field(&child, "alias"));
                        // e.g. alias "urllib.request" to "request"
                        ctx.put_alias(alias, module_name);
                    }
                }
            }
            // e.g. `from sentry_sdk import capture_exception`
            "import_from_statement" => {
                let module_name_node = get_child_by_field(&node, "module_name");
                let module_name = ctx.get_node_text(&module_name_node);

                for child in get_children_by_field(&node, "name") {
                    match child.kind() {
                        // e.g. from sentry_sdk import capture_exception
                        "dotted_name" => {
                            // e.g. capture_exception
                            let imported_obj_name = ctx.get_node_text(&child);
                            // e.g. sentry_sdk.capture_exception
                            let imported_obj_full_name =
                                format!("{}.{}", module_name, imported_obj_name);
                            // e.g. alias "capture_exception" to "sentry_sdk.capture_exception"
                            ctx.put_alias(imported_obj_name, imported_obj_full_name);
                        }
                        // e.g. from sentry_sdk import capture_exception as capture
                        "aliased_import" => {
                            // e.g. capture_exception
                            let imported_obj_orig_name =
                                ctx.get_node_text(&get_child_by_field(&child, "name"));
                            // e.g. capture
                            let imported_obj_alias =
                                ctx.get_node_text(&get_child_by_field(&child, "alias"));
                            // e.g. sentry_sdk.capture_exception
                            let imported_obj_full_name =
                                format!("{}.{}", module_name, imported_obj_orig_name);
                            // e.g. alias "sentry_sdk.capture_exception" to "capture"
                            ctx.put_alias(imported_obj_alias, imported_obj_full_name);
                        }
                        _ => {}
                    }
                }
            }
            "attribute" | "identifier" if node.end_byte() - node.start_byte() > 1 => {
                let text = ctx.get_node_text(node);
                if let Some(data_element) = ctx.find_data_element(&text) {
                    let _ = ctx.put_occurrence(DataElementOccurrence::from_node(
                        ctx,
                        node,
                        &data_element,
                    ));
                    return Ok(VisitChildren::No); // Do not look at parts of the same attribute again.
                }
            }
            "call" => {
                let func_node = get_child_by_field(node, "function");
                let func_name = ctx.get_node_text(&func_node);

                if let Some(data_sink) = ctx.find_data_sink(&func_name) {
                    let mut data_elements = vec![];
                    for arg in get_children(&get_child_by_field(node, "arguments")) {
                        match arg.kind() {
                            "identifier" => {
                                let arg_text = ctx.get_node_text(&arg);
                                if let Some(elem) = ctx.find_data_element(&arg_text) {
                                    data_elements.push(elem);
                                }
                            }
                            _ => (),
                        }
                    }
                    if !data_elements.is_empty() {
                        let _ = ctx.put_vulnerability(Vulnerability::from_node(
                            ctx,
                            node,
                            data_sink,
                            &data_elements,
                        ));
                    }
                }
                // TODO early stop?
            }
            "assignment" => {
                let left_node = node.child_by_field_name("left").unwrap();
                let left_node_text = ctx.get_node_text(&left_node);

                if let Some(right_node) = node.child_by_field_name("right") {
                    let right_node_text = ctx.get_node_text(&right_node);
                }
            }
            _ => (),
        }
        Ok(VisitChildren::Yes)
    }

    fn leave_node(ctx: &mut FileScanContext, node: &Node) {
        match node.kind() {
            "class_definition"
            | "function_definition"
            | "list_comprehension"
            | "lambda"
            | "generator_expression" => {
                ctx.exit_current_scope();
            }
            _ => (),
        }
    }
}
