"""Tree-sitter AST extractor — walks parse tree to extract symbols and call edges."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, cast

from tree_sitter_language_pack import get_parser

from codemunch_pro.parser.languages import LanguageSpec, get_language_for_file, get_spec
from codemunch_pro.parser.symbols import CallEdge, Symbol
from codemunch_pro.security import is_binary_file, is_too_large

logger = logging.getLogger(__name__)


def extract_symbols(file_path: str | Path) -> list[Symbol]:
    """Extract all symbols from a source file.

    Args:
        file_path: Path to the source file.

    Returns:
        List of Symbol objects found in the file.
        Returns empty list if file can't be parsed.
    """
    file_path = Path(file_path)

    if not file_path.is_file():
        return []
    if is_binary_file(file_path):
        return []
    if is_too_large(file_path):
        logger.warning('Skipping oversized file: %s', file_path)
        return []

    language = get_language_for_file(file_path)
    if not language:
        return []

    spec = get_spec(language)
    if not spec:
        return []

    try:
        source = file_path.read_bytes()
    except (OSError, PermissionError) as e:
        logger.warning('Cannot read %s: %s', file_path, e)
        return []

    try:
        parser = get_parser(cast(Any, spec.tree_sitter_name))
        tree = parser.parse(source)
    except Exception as e:
        logger.warning('Parse error for %s: %s', file_path, e)
        return []

    symbols: list[Symbol] = []
    _walk_node(tree.root_node, spec, str(file_path), source, symbols, parent_name='')
    return symbols


def _walk_node(
    node,
    spec: LanguageSpec,
    file_path: str,
    source: bytes,
    symbols: list[Symbol],
    parent_name: str,
) -> None:
    """Recursively walk AST nodes to extract symbols."""
    node_type = node.type

    # Check all symbol-producing node types
    all_types = (
        spec.function_types
        + spec.class_types
        + spec.type_types
        + spec.interface_types
    )

    if node_type in all_types:
        sym = _extract_symbol(node, spec, file_path, source, parent_name)
        if sym:
            symbols.append(sym)
            # Recurse into children with updated parent
            child_parent = sym.qualified_name
            for child in node.children:
                _walk_node(child, spec, file_path, source, symbols, child_parent)
            return

    # Recurse into children
    for child in node.children:
        _walk_node(child, spec, file_path, source, symbols, parent_name)


def _extract_symbol(
    node,
    spec: LanguageSpec,
    file_path: str,
    source: bytes,
    parent_name: str,
) -> Symbol | None:
    """Extract a Symbol from an AST node."""
    name = _get_name(node, spec)
    if not name:
        return None

    # Determine kind
    kind = _classify_kind(node.type, spec)

    # Build qualified name
    qualified_name = f'{parent_name}.{name}' if parent_name else name

    # Extract signature
    signature = _get_signature(node, spec, source)

    # Extract docstring
    docstring = _get_docstring(node, spec, source)

    # Extract decorators
    decorators = _get_decorators(node, spec, source)

    # Extract call edges
    calls = _extract_calls(node, spec, source, qualified_name)

    return Symbol(
        name=name,
        qualified_name=qualified_name,
        kind=kind,
        language=spec.name,
        file_path=file_path,
        line=node.start_point[0] + 1,  # 1-indexed
        end_line=node.end_point[0] + 1,
        byte_offset=node.start_byte,
        byte_length=node.end_byte - node.start_byte,
        signature=signature,
        docstring=docstring,
        decorators=decorators,
        parent_name=parent_name,
        calls=calls,
    )


def _get_name(node, spec: LanguageSpec) -> str:
    """Extract the name from an AST node."""
    # Try the name field directly
    name_node = node.child_by_field_name(spec.name_field)
    if name_node:
        # For C/C++ declarators, dig into function_declarator
        if name_node.type in ('function_declarator', 'pointer_declarator'):
            inner = name_node.child_by_field_name('declarator')
            if inner:
                # Could be another level of nesting
                if inner.type == 'qualified_identifier':
                    return inner.text.decode('utf-8', errors='replace')
                return inner.text.decode('utf-8', errors='replace')
            return name_node.text.decode('utf-8', errors='replace')
        return name_node.text.decode('utf-8', errors='replace')

    # Fallback: look for identifier child
    for child in node.children:
        if child.type == 'identifier':
            return child.text.decode('utf-8', errors='replace')
        if child.type == 'type_identifier':
            return child.text.decode('utf-8', errors='replace')

    return ''


def _classify_kind(node_type: str, spec: LanguageSpec) -> str:
    """Classify a node type into a symbol kind."""
    if node_type in spec.function_types:
        if 'method' in node_type:
            return 'method'
        return 'function'
    if node_type in spec.class_types:
        if 'enum' in node_type:
            return 'enum'
        if 'struct' in node_type:
            return 'struct'
        if 'module' in node_type:
            return 'module'
        return 'class'
    if node_type in spec.type_types:
        return 'type'
    if node_type in spec.interface_types:
        return 'interface'
    return 'unknown'


def _get_signature(node, spec: LanguageSpec, source: bytes) -> str:
    """Extract the function/method signature."""
    parts = []

    # Get the name
    name = _get_name(node, spec)
    if name:
        parts.append(name)

    # Get parameters
    params_node = node.child_by_field_name(spec.parameters_field)
    if params_node:
        parts.append(params_node.text.decode('utf-8', errors='replace'))

    # Get return type
    if spec.return_type_field:
        ret_node = node.child_by_field_name(spec.return_type_field)
        if ret_node:
            ret_text = ret_node.text.decode('utf-8', errors='replace')
            parts.append(f'-> {ret_text}')

    return ' '.join(parts) if parts else ''


def _get_docstring(node, spec: LanguageSpec, source: bytes) -> str:
    """Extract the docstring from a function/class definition."""
    if spec.name == 'python':
        return _get_python_docstring(node, source)

    # For other languages, look for preceding comment
    return _get_preceding_comment(node, spec, source)


def _get_python_docstring(node, source: bytes) -> str:
    """Extract Python docstring (first string in body block)."""
    body = node.child_by_field_name('body')
    if not body or not body.children:
        return ''

    first_stmt = body.children[0]

    # Newer tree-sitter-python: bare string node in block
    if first_stmt.type == 'string':
        string_node = first_stmt
    # Older tree-sitter-python: expression_statement wrapping string
    elif first_stmt.type == 'expression_statement' and first_stmt.children:
        if first_stmt.children[0].type == 'string':
            string_node = first_stmt.children[0]
        else:
            return ''
    else:
        return ''

    text = string_node.text.decode('utf-8', errors='replace')
    # Strip triple quotes
    for q in ('"""', "'''"):
        if text.startswith(q) and text.endswith(q):
            text = text[3:-3]
            break
    return text.strip()


def _get_preceding_comment(node, spec: LanguageSpec, source: bytes) -> str:
    """Extract comments immediately preceding a node (JSDoc, etc.)."""
    prev = node.prev_sibling
    if not prev:
        return ''

    if prev.type in ('comment', 'line_comment', 'block_comment'):
        text = prev.text.decode('utf-8', errors='replace')
        # Strip comment markers
        text = text.strip()
        for prefix in ('//', '/*', '*/', '*', '#', '///', '/**'):
            text = text.strip(prefix)
        return text.strip()

    return ''


def _get_decorators(node, spec: LanguageSpec, source: bytes) -> list[str]:
    """Extract decorator names from a node."""
    if not spec.decorator_type:
        return []

    decorators = []
    # Check previous siblings and direct children
    prev = node.prev_sibling
    while prev and prev.type == spec.decorator_type:
        text = prev.text.decode('utf-8', errors='replace')
        decorators.append(text)
        prev = prev.prev_sibling

    # Also check children (some grammars nest decorators)
    for child in node.children:
        if child.type == spec.decorator_type:
            text = child.text.decode('utf-8', errors='replace')
            decorators.append(text)

    return decorators


def _extract_calls(
    node, spec: LanguageSpec, source: bytes, caller_qname: str,
) -> list[CallEdge]:
    """Extract function call expressions from inside a node body."""
    calls: list[CallEdge] = []

    body = node.child_by_field_name(spec.body_field)
    target = body if body else node

    _walk_for_calls(target, spec, caller_qname, calls)
    return calls


def _walk_for_calls(
    node, spec: LanguageSpec, caller_qname: str, calls: list[CallEdge],
) -> None:
    """Walk AST to find call expressions."""
    if node.type in spec.call_types:
        callee = _get_callee_name(node, spec)
        if callee:
            calls.append(CallEdge(
                callee_name=callee,
                line=node.start_point[0] + 1,
                caller_qualified_name=caller_qname,
            ))

    for child in node.children:
        # Don't descend into nested function/class definitions
        if child.type in spec.function_types or child.type in spec.class_types:
            continue
        _walk_for_calls(child, spec, caller_qname, calls)


def _get_callee_name(node, spec: LanguageSpec) -> str:
    """Extract the callee name from a call expression node."""
    # Try 'function' field (Python, JS, TS, Rust)
    func_node = node.child_by_field_name('function')
    if func_node:
        return func_node.text.decode('utf-8', errors='replace')

    # Try 'name' field (Java method_invocation)
    name_node = node.child_by_field_name('name')
    if name_node:
        # For method calls, also get the object
        obj_node = node.child_by_field_name('object')
        if obj_node:
            return f'{obj_node.text.decode("utf-8", errors="replace")}.{name_node.text.decode("utf-8", errors="replace")}'
        return name_node.text.decode('utf-8', errors='replace')

    # Try 'method' field (Ruby)
    method_node = node.child_by_field_name('method')
    if method_node:
        return method_node.text.decode('utf-8', errors='replace')

    # Fallback: first child
    if node.children:
        return node.children[0].text.decode('utf-8', errors='replace')

    return ''
