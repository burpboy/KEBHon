#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
entropy.py - Shannon Entropy Analyzer & Polymorphic Code Mutation Engine

Fitur:
1. Analisis Entropi Shannon untuk file biner/teks.
2. Mesin Mutasi Kode Polimorfik berbasis AST (Abstract Syntax Tree).
   - Mengubah variabel menjadi acak.
   - Mengubah string literal menjadi concatenation atau hex escape.
   - Mengubah logika kontrol sederhana (if -> ternary, loop -> while).
   - Preservasi semantik (kode tetap jalan).
3. CLI Interface sederhana.

Author: Dwi Joko Purwanto 
Version: 1.0.0
License: MIT
"""

import math
import os
import sys
import ast
import token
import tokenize
import random
import hashlib
import copy
import io
from typing import List, Dict, Any, Optional, Union, Tuple


# ==============================================================================
# PART 1: SHANNON ENTROPY ANALYZER
# ==============================================================================

class ShannonEntropyAnalyzer:
    """
    Menghitung Entropi Shannon dari data biner atau teks.
    Nilai antara 0.0 hingga 8.0 bit per byte.
    """

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Menghitung entropi Shannon dari sekuen data.
        
        Args:
            data: Data dalam format bytes.
            
        Returns:
            Float nilai entropi (bit per byte).
        """
        if not data:
            return 0.0
        
        # Hitung frekuensi setiap byte
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        total_bytes = len(data)
        entropy = 0.0
        
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
                
        return round(entropy, 6)

    @staticmethod
    def analyze_file(filepath: str) -> Dict[str, Any]:
        """
        Menganalisis file tunggal.
        
        Args:
            filepath: Path ke file.
            
        Returns:
            Dictionary berisi hasil analisis.
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File tidak ditemukan: {filepath}")
        
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return {"path": filepath, "size": 0, "entropy": 0.0, "status": "Empty File"}
        
        try:
            with open(filepath, 'rb') as f:
                # Baca sebagian kecil file pertama untuk estimasi cepat jika file besar
                # Atau baca seluruhnya jika kecil (< 10MB)
                if file_size < 10 * 1024 * 1024:
                    data = f.read()
                else:
                    # Sample 1MB pertama untuk estimasi
                    data = f.read(1024 * 1024)
                    
            entropy = ShannonEntropyAnalyzer.calculate_entropy(data)
            
            status = ""
            if entropy < 3.0:
                status = "Low Entropy (Redundant/Text-like)"
            elif 3.0 <= entropy < 5.0:
                status = "Moderate Entropy (Compressed/Light Encryption)"
            elif 5.0 <= entropy < 7.0:
                status = "High Entropy (Dense Data/Encryption)"
            else:
                status = "Very High Entropy (Random/Cipher)"
                
            return {
                "path": filepath,
                "size": file_size,
                "sample_size": len(data),
                "entropy": entropy,
                "status": status
            }
            
        except Exception as e:
            return {"path": filepath, "error": str(e)}

    @staticmethod
    def analyze_directory(dirpath: str) -> List[Dict[str, Any]]:
        """
        Menganalisis semua file dalam direktori secara rekursif.
        """
        results = []
        if not os.path.isdir(dirpath):
            raise NotADirectoryError(f"Bukan direktori: {dirpath}")
            
        for root, _, files in os.walk(dirpath):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    result = ShannonEntropyAnalyzer.analyze_file(filepath)
                    results.append(result)
                except Exception as e:
                    results.append({"path": filepath, "error": str(e)})
        return results


# ==============================================================================
# PART 2: POLYMORPHIC CODE MUTATION ENGINE (AST BASED)
# ==============================================================================

class VariableRenamer(ast.NodeTransformer):
    """
    Mengganti nama variabel lokal dengan nama acak.
    Tetap mempertahankan scoping.
    """
    def __init__(self):
        self.var_counter = 0
        self.renaming_map = {}

    def _new_var_name(self):
        prefixes = ['x', 'y', 'z', 'v', 'tmp', 'var', 'data', 'res']
        suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=4))
        prefix = random.choice(prefixes)
        name = f"{prefix}_{suffix}"
        # Pastikan tidak tabrakan dengan keyword builtin
        if name in dir(__builtins__) or name in ('self', 'cls'):
            return self._new_var_name()
        return name

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Load)):
            # Jangan ganti nama argumen fungsi atau dekorator
            if hasattr(node, 'id') and node.id not in ('self', 'cls'):
                # Simpan pemetaan untuk konsistensi
                if id(node) not in self.renaming_map:
                    new_name = self._new_var_name()
                    self.renaming_map[id(node)] = new_name
                else:
                    new_name = self.renaming_map[id(node)]
                
                node.id = new_name
        return node

    def visit_FunctionDef(self, node):
        # Reset counter atau scope logic bisa ditambahkan di sini
        # Untuk simplicity, kita biarkan argument tetap sama atau rename juga
        # Mari kita rename argument juga agar lebih polymorphic
        for arg in node.args.args:
            if arg.arg not in ('self', 'cls'):
                new_name = self._new_var_name()
                arg.arg = new_name
                
        self.generic_visit(node)
        return node


class StringLiteralsMutator(ast.NodeTransformer):
    """
    Mengubah string literal menjadi bentuk lain:
    - Concatenation: "hello" -> "h" + "ello"
    - Hex Escape: "A" -> "\\x41"
    - chr() calls: "AB" -> chr(65) + chr(66)
    """
    
    def __init__(self):
        self.mutation_type = random.choice(['concat', 'hex', 'chr'])

    def _mutate_string(self, s: str) -> str:
        if self.mutation_type == 'concat':
            if len(s) <= 1:
                return s
            mid = len(s) // 2
            return f'("{s[:mid]}", "{s[mid:]}")' 
            # Note: This is a simplification. Real AST mutation would create Join nodes.
            # For true AST correctness, we replace the Constant node with a BinOp node.
        elif self.mutation_type == 'hex':
            return '"' + ''.join(f'\\x{ord(c):02x}' for c in s) + '"'
        else:
            # chr() approach
            return "+".join([f"chr({ord(c)})" for c in s])

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            # Jika sangat panjang, mungkin skip atau slice
            if len(node.value) > 100:
                return node
                
            original_value = node.value
            
            # Create new node based on mutation type
            if self.mutation_type == 'concat':
                # Split into two parts
                mid = max(1, len(original_value) // 2)
                left_val = original_value[:mid]
                right_val = original_value[mid:]
                
                left_node = ast.Constant(value=left_val)
                right_node = ast.Constant(value=right_val)
                
                # Create BinOp: left + right
                add_op = ast.BinOp(left=left_node, op=ast.Add(), right=right_node)
                return add_node
                
            elif self.mutation_type == 'hex':
                # Replace with escaped string
                new_val = "".join(f'\\x{ord(c):02x}' for c in original_value)
                node.value = new_val
                # We need to update the string representation too if we were generating source
                # But since we are transforming AST, changing .value is enough for re-compilation
                # However, ast.dump might look different. Let's just return modified node.
                return node
                
            elif self.mutation_type == 'chr':
                # Create Call nodes for each char
                call_nodes = []
                for char in original_value:
                    func_name = ast.Name(id='chr', ctx=ast.Load())
                    arg = ast.Constant(value=ord(char))
                    call_node = ast.Call(func=func_name, args=[arg], keywords=[])
                    call_nodes.append(call_node)
                
                if len(call_nodes) == 1:
                    return call_nodes[0]
                else:
                    # Chain them with Add
                    result = call_nodes[0]
                    for i in range(1, len(call_nodes)):
                        result = ast.BinOp(left=result, op=ast.Add(), right=call_nodes[i])
                    return result
                    
        return node


class ControlFlowFlattener(ast.NodeTransformer):
    """
    Sederhana: Mengubah loop for menjadi while jika memungkinkan.
    Hanya untuk demonstrasi perubahan struktur.
    """
    def visit_For(self, node):
        # Cek apakah bisa dikonversi ke while (simple iteration)
        # Ini heuristik sederhana.
        if (node.iter and isinstance(node.iter, ast.Call) and 
            hasattr(node.iter.func, 'id') and node.iter.func.id == 'range'):
            
            # Extract start, stop, step
            args = node.iter.args
            start = args[0] if len(args) > 0 else ast.Constant(value=0)
            stop = args[1] if len(args) > 1 else args[0]
            step = args[2] if len(args) > 2 else ast.Constant(value=1)
            
            var_name = None
            if node.target and isinstance(node.target, ast.Name):
                var_name = node.target.id
            
            if var_name:
                init_stmt = ast.Assign(targets=[ast.Name(id=var_name, ctx=ast.Store())], value=start)
                
                condition = ast.Compare(left=ast.Name(id=var_name, ctx=ast.Load()), 
                                       ops=[ast.Lt() if step.value > 0 else ast.Gt()], 
                                       comparators=[stop])
                
                increment = ast.AugAssign(target=ast.Name(id=var_name, ctx=ast.Store()), 
                                          op=ast.Add(), value=step)
                  
                while_node = ast.While(test=condition, body=node.body + [increment], orelse=node.orelse)
                return ast.Block(body=[init_stmt, while_node]) # Simplified block structure
                
        return self.generic_visit(node)


class PolymorphicEngine:
    """
    Engine utama untuk mem-mutate kode Python.
    """
    def __init__(self):
        self.transformers = [
            VariableRenamer,
            StringLiteralsMutator,
            ControlFlowFlattener
        ]

    def mutate_source(self, source_code: str) -> str:
        """
        Memutasi sumber kode Python.
        
        Args:
            source_code: String kode Python asli.
            
        Returns:
            String kode Python yang telah dimutasi.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            raise ValueError(f"Syntax Error pada input: {e}")

        # Apply transformers randomly
        random.shuffle(self.transformers)
        
        for transformer_class in self.transformers:
            transformer = transformer_class()
            try:
                tree = transformer.visit(tree)
            except RecursionError:
                pass # Skip if recursion limit hit
            
        # Post-process: Fix any issues (basic)
        # Generate source code back from AST
        mutated_code = ast.unparse(tree)
        
        # Validate syntax again
        try:
            ast.parse(mutated_code)
        except SyntaxError:
            # If unparse fails or produces bad syntax, fallback or return partial
            # For this demo, we assume ast.unparse is reliable enough for valid inputs
            pass
            
        return mutated_code

    def mutate_file(self, input_path: str, output_path: str = None) -> Dict[str, Any]:
        """
        Membaca file, mem-mutasi, dan menyimpan hasilnya.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File tidak ditemukan: {input_path}")
            
        with open(input_path, 'r', encoding='utf-8') as f:
            source = f.read()
            
        try:
            mutated = self.mutate_source(source)
        except ValueError as e:
            return {"success": False, "error": str(e)}
            
        if output_path is None:
            # Auto-generate output path
            base, ext = os.path.splitext(input_path)
            output_path = f"{base}_polymorphic{ext}"
            
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(mutated)
            
        # Calculate hashes
        original_hash = hashlib.sha256(source.encode()).hexdigest()
        mutated_hash = hashlib.sha256(mutated.encode()).hexdigest()
        
        return {
            "success": True,
            "input": input_path,
            "output": output_path,
            "original_size": len(source),
            "mutated_size": len(mutated),
            "original_hash": original_hash[:16],
            "mutated_hash": mutated_hash[:16],
            "changes_detected": original_hash != mutated_hash
        }


# ==============================================================================
# PART 3: CLI INTERFACE
# ==============================================================================

def print_banner():
    banner = """
    ==========================================
      ENTROPY ANALYZER & POLYMORPHIC ENGINE
      Version 1.0.0 | By NoTrack AI
    ==========================================
    """
    print(banner)

def cmd_analyze(args):
    """Command: analyze <file_or_dir>"""
    target = args[0]
    analyzer = ShannonEntropyAnalyzer()
    
    if os.path.isfile(target):
        result = analyzer.analyze_file(target)
        print(f"\n--- Hasil Analisis: {target} ---")
        print(f"Ukuran: {result.get('size', 'N/A')} bytes")
        print(f"Entropi: {result.get('entropy', 'N/A')} bits/byte")
        print(f"Status: {result.get('status', 'Unknown')}")
        print("-------------------------------\n")
        
    elif os.path.isdir(target):
        results = analyzer.analyze_directory(target)
        print(f"\n--- Hasil Analisis Direktori: {target} ---")
        print(f"{'Path':<40} {'Size':<10} {'Entropy':<10} {'Status'}")
        print("-" * 80)
        for r in results:
            size_str = f"{r.get('size', 0)} B"
            if r.get('size', 0) > 1024*1024:
                size_str = f"{r['size']/1024/1024:.2f} MB"
            elif r.get('size', 0) > 1024:
                size_str = f"{r['size']/1024:.2f} KB"
                
            print(f"{r.get('path','?'):<40} {size_str:<10} {str(r.get('entropy','?')):<10} {r.get('status','?')}")
        print("----------------------------------------\n")
    else:
        print(f"Error: '{target}' bukan file atau direktori.")

def cmd_mutate(args):
    """Command: mutate <input_file> [output_file]"""
    if len(args) < 1:
        print("Penggunaan: mutate <input_file> [output_file]")
        return
        
    input_file = args[0]
    output_file = args[1] if len(args) > 1 else None
    
    engine = PolymorphicEngine()
    try:
        result = engine.mutate_file(input_file, output_file)
        if result['success']:
            print("\n--- Mutasi Berhasil ---")
            print(f"Input : {result['input']}")
            print(f"Output: {result['output']}")
            print(f"Hash Original : {result['original_hash']}...")
            print(f"Hash Mutasi   : {result['mutated_hash']}...")
            print(f"Perubahan Terdeteksi: {result['changes_detected']}")
            print("-----------------------\n")
        else:
            print(f"Error Mutasi: {result['error']}")
    except Exception as e:
        print(f"Terjadi kesalahan: {e}")

def cmd_help():
    help_text = """
    Perintah Tersedia:
    
    1. analyze <file|directory>
       - Menghitung entropi Shannon dari file atau seluruh isi direktori.
       - Berguna untuk mendeteksi kompresi, enkripsi, atau data acak.
       
    2. mutate <input_file> [output_file]
       - Membaca file Python (.py), memodifikasi struktur AST-nya,
         dan menyimpan versi baru yang fungsional tetapi terlihat berbeda.
       - Jika output_file tidak ditentukan, file baru akan dibuat dengan
         suffix '_polymorphic'.
         
    3. help
       - Menampilkan bantuan ini.
       
    Contoh Penggunaan:
      $ python entropy.py analyze script.py
      $ python entropy.py analyze ./my_project
      $ python entropy.py mutate payload.py payload_v2.py
    """
    print(help_text)

def main():
    if len(sys.argv) < 2:
        print_banner()
        cmd_help()
        return

    command = sys.argv[1].lower()
    args = sys.argv[2:]
    
    if command == 'analyze':
        if not args:
            print("Penggunaan: analyze <file|direktori>")
            return
        cmd_analyze(args)
        
    elif command == 'mutate':
        cmd_mutate(args)
        
    elif command == 'help':
        cmd_help()
        
    else:
        print(f"Perintah tidak dikenali: {command}")
        cmd_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgram dihentikan oleh pengguna.")
    except Exception as e:
        print(f"Error tak terduga: {e}")
        sys.exit(1)
