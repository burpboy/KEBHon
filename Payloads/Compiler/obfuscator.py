#!/usr/bin/env python3
"""
obfuscator.py - AST-Level Python Script Obfuscator & String Encryptor
"""

import ast
import argparse
import base64
import random
import string
import sys
from pathlib import Path


class NameMangler(ast.NodeTransformer):
    """Mangles variable, function, class, and argument names while preserving built-ins and dunder methods."""
    
    def __init__(self):
        super().__init__()
        self.mapping = {}
        self.reserved = {
            '__init__', '__main__', '__str__', '__repr__', '__call__', '__iter__',
            '__next__', '__enter__', '__exit__', 'self', 'cls', 'True', 'False',
            'None', 'print', 'len', 'range', 'int', 'str', 'float', 'list', 'dict',
            'set', 'tuple', 'open', 'bytes', 'base64', 'super', 'type', 'isinstance'
        }

    def _generate_name(self, original: str) -> str:
        if original in self.reserved or (original.startswith('__') and original.endswith('__')):
            return original
        if original not in self.mapping:
            chars = string.ascii_letters + string.digits
            rand_str = ''.join(random.choices(chars, k=8))
            self.mapping[original] = f"_0x{rand_str}"
        return self.mapping[original]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        node.name = self._generate_name(node.name)
        self.generic_visit(node)
        return node

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        node.name = self._generate_name(node.name)
        self.generic_visit(node)
        return node

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.name = self._generate_name(node.name)
        self.generic_visit(node)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = self._generate_name(node.id)
        return node

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = self._generate_name(node.arg)
        return node


class StringEncryptor(ast.NodeTransformer):
    """Encrypts string literals using Base64 and injects runtime decryption calls."""

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str) and len(node.value) > 0:
            encoded_val = base64.b64encode(node.value.encode('utf-8')).decode('utf-8')
            
            # Constructs AST for: __import__('base64').b64decode('ENCODED_STRING').decode('utf-8')
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Name(id='__import__', ctx=ast.Load()),
                        args=[ast.Constant(value='base64')],
                        keywords=[]
                    ),
                    attr='b64decode',
                    ctx=ast.Load()
                ),
                args=[ast.Call(
                    func=ast.Attribute(
                        value=ast.Constant(value=encoded_val),
                        attr='encode',
                        ctx=ast.Load()
                    ),
                    args=[ast.Constant(value='utf-8')],
                    keywords=[]
                )],
                keywords=[]
            )
        return node


def obfuscate_code(source_code: str, encrypt_strings: bool = True, mangle_names: bool = True) -> str:
    """Parses source code into an AST, applies transformations, and unparses back to Python code."""
    tree = ast.parse(source_code)
    
    if encrypt_strings:
        tree = StringEncryptor().visit(tree)
        
    if mangle_names:
        tree = NameMangler().visit(tree)
        
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def main():
    parser = argparse.ArgumentParser(description="AST-Level Python Script Obfuscator & String Encryptor")
    parser.add_argument("input", type=Path, help="Path to input Python script")
    parser.add_argument("-o", "--output", type=Path, required=True, help="Path to output obfuscated script")
    parser.add_argument("--no-strings", action="store_true", help="Disable string encryption")
    parser.add_argument("--no-mangle", action="store_true", help="Disable name mangling")

    args = parser.parse_args()

    if not args.input.is_file():
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        source_code = args.input.read_text(encoding="utf-8")
        obfuscated_code = obfuscate_code(
            source_code,
            encrypt_strings=not args.no_strings,
            mangle_names=not args.no_mangle
        )
        args.output.write_text(obfuscated_code, encoding="utf-8")
        print(f"Successfully obfuscated '{args.input}' -> '{args.output}'")
    except Exception as e:
        print(f"Error during obfuscation process: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
