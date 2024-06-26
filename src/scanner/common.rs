use std::collections::VecDeque;

use tree_sitter::Node;

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
