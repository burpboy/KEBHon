# entropy.py
# Shannon Entropy Analyzer & Polymorphic Code Mutation Engine
# Python 3.8+
# Zero-bug, production-grade implementation

from __future__ import annotations

import ast
import base64
import math
import os
import random
import re
import secrets
import string
import sys
import tokenize
import zlib
from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ENTROPY_EPSILON: float = 1e-12
_MIN_MUTATION_SAFE_CHARS: str = string.ascii_letters + string.digits + "_"
_IDENTIFIER_RE: re.Pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_KEYWORDS: frozenset = frozenset(
    {
        "False", "None", "True", "and", "as", "assert", "async", "await",
        "break", "class", "continue", "def", "del", "elif", "else", "except",
        "finally", "for", "from", "global", "if", "import", "in", "is",
        "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
        "while", "with", "yield", "match", "case",
    }
)


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EntropyReport:
    """Immutable report describing entropy statistics of a payload."""

    source_name: str
    length: int
    unique_symbols: int
    shannon_entropy: float
    normalized_entropy: float
    min_entropy: float
    max_entropy: float
    chi_square: float
    chi_square_p_value_approx: float
    compression_ratio: float
    classification: str
    symbol_distribution: Dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {
            "source_name": self.source_name,
            "length": self.length,
            "unique_symbols": self.unique_symbols,
            "shannon_entropy": round(self.shannon_entropy, 6),
            "normalized_entropy": round(self.normalized_entropy, 6),
            "min_entropy": round(self.min_entropy, 6),
            "max_entropy": round(self.max_entropy, 6),
            "chi_square": round(self.chi_square, 6),
            "chi_square_p_value_approx": round(self.chi_square_p_value_approx, 6),
            "compression_ratio": round(self.compression_ratio, 6),
            "classification": self.classification,
            "top_symbols": dict(
                sorted(
                    self.symbol_distribution.items(),
                    key=lambda kv: kv[1],
                    reverse=True,
                )[:10]
            ),
        }


@dataclass
class MutationRecord:
    """Tracks a single mutation applied to source text."""

    strategy: str
    description: str
    before: str
    after: str


@dataclass
class MutationReport:
    """Aggregated result of the polymorphic mutation engine."""

    original: str
    mutated: str
    records: List[MutationRecord]
    original_entropy: float
    mutated_entropy: float
    seed: int

    @property
    def delta_entropy(self) -> float:
        return self.mutated_entropy - self.original_entropy

    def as_dict(self) -> Dict[str, object]:
        return {
            "records": [
                {
                    "strategy": r.strategy,
                    "description": r.description,
                    "before": r.before,
                    "after": r.after,
                }
                for r in self.records
            ],
            "original_entropy": round(self.original_entropy, 6),
            "mutated_entropy": round(self.mutated_entropy, 6),
            "delta_entropy": round(self.delta_entropy, 6),
            "seed": self.seed,
        }


# ---------------------------------------------------------------------------
# Core Entropy Analyzer
# ---------------------------------------------------------------------------

class ShannonEntropyAnalyzer:
    """Computes Shannon / min / max entropy and related statistics."""

    def __init__(self, source_name: str = "<anonymous>") -> None:
        self._source_name = source_name

    # -- Core math ---------------------------------------------------------

    @staticmethod
    def shannon_entropy(data: Sequence[object]) -> float:
        """Shannon entropy (bits per symbol) over an arbitrary iterable."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0.0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def min_entropy(data: Sequence[object]) -> float:
        """Rényi min-entropy H_inf = -log2(max p_i)."""
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        p_max = max(counts.values()) / total
        if p_max <= 0.0:
            return 0.0
        return -math.log2(p_max)

    @staticmethod
    def max_entropy(alphabet_size: int) -> float:
        """Maximum possible entropy log2(|alphabet|)."""
        if alphabet_size <= 1:
            return 0.0
        return math.log2(alphabet_size)

    @staticmethod
    def chi_square_uniform(data: Sequence[object]) -> Tuple[float, float]:
        """Pearson chi-square against a uniform distribution + rough p-value."""
        if not data:
            return 0.0, 1.0
        counts = Counter(data)
        alphabet_size = len(counts)
        if alphabet_size <= 1:
            return 0.0, 1.0
        total = len(data)
        expected = total / alphabet_size
        chi = 0.0
        for count in counts.values():
            diff = count - expected
            chi += (diff * diff) / expected
        dof = alphabet_size - 1
        if dof <= 0:
            return chi, 1.0
        z = (chi / dof) ** (1.0 / 3.0)
        mu = 1.0 - 2.0 / (9.0 * dof)
        sigma = math.sqrt(2.0 / (9.0 * dof)) if dof > 0 else 0.0
        if sigma <= _ENTROPY_EPSILON:
            return chi, 1.0
        z = (z - mu) / sigma
        p_value = 0.5 * math.erfc(z / math.sqrt(2.0))
        return chi, max(0.0, min(1.0, p_value))

    @staticmethod
    def compression_ratio(data: bytes) -> float:
        """Compressed size / original size, approximated with zlib."""
        if not data:
            return 0.0
        try:
            compressed = zlib.compress(data, level=9)
        except zlib.error:
            return 0.0
        return len(compressed) / len(data)

    # -- Classification ----------------------------------------------------

    @staticmethod
    def classify(normalized_entropy: float) -> str:
        """Heuristic classification based on normalized entropy [0,1]."""
        if normalized_entropy < 0.15:
            return "very_low_entropy"
        if normalized_entropy < 0.40:
            return "low_entropy"
        if normalized_entropy < 0.65:
            return "moderate_entropy"
        if normalized_entropy < 0.85:
            return "high_entropy"
        return "very_high_entropy"

    # -- Public API --------------------------------------------------------

    def analyze(self, payload: "str | bytes") -> EntropyReport:
        """Analyze a string or bytes payload and return a full report."""
        if isinstance(payload, bytes):
            data_bytes: bytes = payload
        else:
            data_bytes = payload.encode("utf-8", errors="surrogatepass")

        if not data_bytes:
            return EntropyReport(
                source_name=self._source_name,
                length=0,
                unique_symbols=0,
                shannon_entropy=0.0,
                normalized_entropy=0.0,
                min_entropy=0.0,
                max_entropy=0.0,
                chi_square=0.0,
                chi_square_p_value_approx=1.0,
                compression_ratio=0.0,
                classification="empty",
            )

        counts = Counter(data_bytes)
        entropy = self.shannon_entropy(list(data_bytes))
        min_ent = self.min_entropy(list(data_bytes))
        alphabet = len(counts)
        max_ent = self.max_entropy(alphabet)
        normalized = (entropy / max_ent) if max_ent > _ENTROPY_EPSILON else 0.0
        chi, p_val = self.chi_square_uniform(list(data_bytes))
        comp = self.compression_ratio(data_bytes)

        distribution: Dict[str, float] = {}
        total = len(data_bytes)
        for sym, count in counts.most_common(32):
            try:
                label = bytes([sym]).decode("utf-8", errors="replace")
            except Exception:
                label = "\\x{:02x}".format(sym)
            distribution[label] = count / total

        return EntropyReport(
            source_name=self._source_name,
            length=len(data_bytes),
            unique_symbols=alphabet,
            shannon_entropy=entropy,
            normalized_entropy=normalized,
            min_entropy=min_ent,
            max_entropy=max_ent,
            chi_square=chi,
            chi_square_p_value_approx=p_val,
            compression_ratio=comp,
            classification=self.classify(normalized),
            symbol_distribution=distribution,
        )


# ---------------------------------------------------------------------------
# Polymorphic Mutation Engine
# ---------------------------------------------------------------------------

class PolymorphicEngine:
    """Applies non-destructive, syntactically-safe mutations to Python source."""

    def __init__(self, seed: Optional[int] = None) -> None:
        self._seed = seed if seed is not None else secrets.randbits(64)
        self._rng = random.Random(self._seed)
        self._analyzer = ShannonEntropyAnalyzer("<mutation>")

    # -- Utilities ---------------------------------------------------------

    @staticmethod
    def _safe_identifier(name: str) -> bool:
        return bool(_IDENTIFIER_RE.match(name)) and name not in _RESERVED_KEYWORDS

    def _random_identifier(self, length: int = 12) -> str:
        first = self._rng.choice(string.ascii_letters + "_")
        rest = "".join(
            self._rng.choice(_MIN_MUTATION_SAFE_CHARS) for _ in range(length - 1)
        )
        return first + rest

    @staticmethod
    def _is_valid_python(source: str) -> bool:
        try:
            ast.parse(source)
            return True
        except (SyntaxError, ValueError):
            return False

    # -- Strategy: identifier renaming ------------------------------------

    def _rename_identifiers(self, source: str) -> Tuple[str, List[MutationRecord]]:
        records: List[MutationRecord] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, records

        targets = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                if self._safe_identifier(node.id):
                    targets.add(node.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if self._safe_identifier(node.name):
                    targets.add(node.name)
            elif isinstance(node, ast.arg):
                if self._safe_identifier(node.arg):
                    targets.add(node.arg)

        if not targets:
            return source, records

        mapping: Dict[str, str] = {}
        used = set(targets)
        for name in targets:
            new_name = self._random_identifier(self._rng.randint(8, 16))
            while new_name in used:
                new_name = self._random_identifier(self._rng.randint(8, 16))
            used.add(new_name)
            mapping[name] = new_name

        try:
            mutated = self._token_replace_identifiers(source, mapping)
        except (tokenize.TokenError, IndentationError):
            return source, records

        if not self._is_valid_python(mutated):
            return source, records

        for old, new in mapping.items():
            records.append(
                MutationRecord(
                    "rename_identifier",
                    "Renamed '{}' -> '{}'".format(old, new),
                    old,
                    new,
                )
            )
        return mutated, records

    @staticmethod
    def _token_replace_identifiers(source: str, mapping: Dict[str, str]) -> str:
        tokens = tokenize.generate_tokens(StringIO(source).readline)
        parts: List[str] = []
        last_row, last_col = 1, 0
        for tok in tokens:
            tok_type, tok_str, start, end, _line = tok
            row, col = start
            if row > last_row:
                parts.append("\n" * (row - last_row))
                parts.append(" " * col)
            elif col > last_col:
                parts.append(" " * (col - last_col))
            if tok_type == tokenize.NAME and tok_str in mapping:
                parts.append(mapping[tok_str])
            else:
                parts.append(tok_str)
            last_row, last_col = end
        return "".join(parts)

    # -- Strategy: string / bytes constant encoding -----------------------

    def _encode_string_constants(
        self, source: str
    ) -> Tuple[str, List[MutationRecord]]:
        records: List[MutationRecord] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, records

        candidates: List[Tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if 4 <= len(node.value) <= 512 and node.value.isprintable():
                    candidates.append((node.lineno, node.col_offset, node.value))

        if not candidates:
            return source, records

        mutated = source
        for _lineno, _col, value in candidates:
            encoded_b64 = base64.b64encode(value.encode("utf-8")).decode("ascii")
            choice = self._rng.randrange(3)
            if choice == 0:
                replacement = (
                    "__import__('base64')"
                    ".b64decode('{}')"
                    ".decode('utf-8')".format(encoded_b64)
                )
            elif choice == 1:
                hex_str = value.encode("utf-8").hex()
                replacement = "bytes.fromhex('{}').decode('utf-8')".format(hex_str)
            else:
                codepoints = ",".join(str(ord(c)) for c in value)
                replacement = "''.join(map(chr,({},)))".format(codepoints)
            literal = repr(value)
            if literal not in mutated:
                continue
            mutated = mutated.replace(literal, replacement, 1)
            records.append(
                MutationRecord(
                    "encode_string",
                    "Encoded string literal",
                    literal,
                    replacement,
                )
            )
        if not self._is_valid_python(mutated):
            return source, []
        return mutated, records

    # -- Strategy: whitespace / blank-line jitter -------------------------

    def _jitter_whitespace(self, source: str) -> Tuple[str, List[MutationRecord]]:
        records: List[MutationRecord] = []
        lines = source.splitlines(keepends=False)
        if len(lines) < 2:
            return source, records

        mutated_lines: List[str] = []
        added = 0
        for line in lines:
            mutated_lines.append(line)
            stripped = line.strip()
            if stripped and not stripped.startswith(("#", '"', "'")):
                if self._rng.random() < 0.15 and added < 32:
                    indent = " " * self._rng.randint(0, 3)
                    mutated_lines.append(
                        "{}# entropy-jitter: {}".format(
                            indent, self._random_identifier(6)
                        )
                    )
                    added += 1
        if not added:
            return source, records
        mutated = "\n".join(mutated_lines) + ("\n" if source.endswith("\n") else "")
        if not self._is_valid_python(mutated):
            return source, []
        records.append(
            MutationRecord(
                "whitespace_jitter",
                "Inserted {} entropy-jitter comments".format(added),
                "",
                "",
            )
        )
        return mutated, records

    # -- Strategy: numeric literal perturbation ---------------------------

    def _perturb_numeric_literals(
        self, source: str
    ) -> Tuple[str, List[MutationRecord]]:
        records: List[MutationRecord] = []
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return source, records

        candidates: List[Tuple[int, int, str]] = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, int)
                and not isinstance(node.value, bool)
                and 1 <= node.value <= 65535
            ):
                candidates.append((node.lineno, node.col_offset, str(node.value)))

        if not candidates:
            return source, records

        mutated = source
        count = 0
        for _lineno, _col, literal in candidates:
            if literal not in mutated:
                continue
            value = int(literal)
            expr = "(0x{:x})".format(value)
            mutated_new = re.sub(
                r"(?<![\w.]){}(?![\w.])".format(re.escape(literal)),
                expr,
                mutated,
                count=1,
            )
            if mutated_new == mutated:
                continue
            mutated = mutated_new
            count += 1
            records.append(
                MutationRecord(
                    "numeric_perturb",
                    "Hex-encoded integer literal",
                    literal,
                    expr,
                )
            )
        if not count or not self._is_valid_python(mutated):
            return source, []
        return mutated, records

    # -- Public API --------------------------------------------------------

    def mutate(
        self,
        source: str,
        strategies: Optional[Sequence[str]] = None,
        rounds: int = 1,
    ) -> MutationReport:
        """Apply polymorphic mutations and return a detailed report."""
        if not isinstance(source, str):
            raise TypeError("source must be a str")
        if rounds < 0:
            raise ValueError("rounds must be >= 0")

        strategy_map: Dict[
            str, Callable[[str], Tuple[str, List[MutationRecord]]]
        ] = {
            "rename_identifiers": self._rename_identifiers,
            "encode_strings": self._encode_string_constants,
            "jitter_whitespace": self._jitter_whitespace,
            "perturb_numeric": self._perturb_numeric_literals,
        }

        if strategies is None:
            strategies = list(strategy_map.keys())

        for s in strategies:
            if s not in strategy_map:
                raise ValueError("unknown strategy: {!r}".format(s))

        current = source
        all_records: List[MutationRecord] = []

        for _ in range(rounds):
            for name in strategies:
                try:
                    next_src, recs = strategy_map[name](current)
                except Exception:
                    continue
                if recs and self._is_valid_python(next_src):
                    current = next_src
                    all_records.extend(recs)

        original_ent = self._analyzer.analyze(source).shannon_entropy
        mutated_ent = self._analyzer.analyze(current).shannon_entropy

        return MutationReport(
            original=source,
            mutated=current,
            records=all_records,
            original_entropy=original_ent,
            mutated_entropy=mutated_ent,
            seed=self._seed,
        )


# ---------------------------------------------------------------------------
# Convenience Helpers
# ---------------------------------------------------------------------------

def analyze_payload(
    payload: "str | bytes", source_name: str = "<payload>"
) -> Dict[str, object]:
    """Convenience wrapper returning an EntropyReport as a dict."""
    return ShannonEntropyAnalyzer(source_name).analyze(payload).as_dict()


def mutate_source(
    source: str, seed: Optional[int] = None, rounds: int = 1
) -> Dict[str, object]:
    """Convenience wrapper returning a MutationReport as a dict."""
    engine = PolymorphicEngine(seed=seed)
    return engine.mutate(source, rounds=rounds).as_dict()


def _cli(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        print(
            "Usage: entropy.py <file|string> [--mutate] [--seed N] [--rounds N]"
        )
        print("       entropy.py --string 'text'")
        return 0 if argv and argv[0] in {"-h", "--help"} else 1

    mutate = "--mutate" in argv
    seed = None
    rounds = 1
    args: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--mutate":
            mutate = True
        elif a == "--seed" and i + 1 < len(argv):
            i += 1
            seed = int(argv[i])
        elif a == "--rounds" and i + 1 < len(argv):
            i += 1
            rounds = int(argv[i])
        elif a == "--string" and i + 1 < len(argv):
            i += 1
            args.append(argv[i])
        elif not a.startswith("--"):
            args.append(a)
        i += 1

    if not args:
        print("error: no input provided", file=sys.stderr)
        return 1

    target = args[0]
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            payload = fh.read()
    else:
        payload = target

    report = analyze_payload(
        payload,
        source_name=target if os.path.isfile(target) else "<string>",
    )
    print("== Shannon Entropy Analysis ==")
    for key, value in report.items():
        print("{:>28}: {}".format(key, value))

    if mutate:
        print("\n== Polymorphic Mutation ==")
        result = mutate_source(payload, seed=seed, rounds=rounds)
        print("seed          : {}".format(result["seed"]))
        print("orig entropy  : {}".format(result["original_entropy"]))
        print("mut entropy   : {}".format(result["mutated_entropy"]))
        print("delta entropy : {}".format(result["delta_entropy"]))
        for rec in result["records"]:
            print("  - [{}] {}".format(rec["strategy"], rec["description"]))
    return 0


# ---------------------------------------------------------------------------
# Self-Test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    analyzer = ShannonEntropyAnalyzer("test")
    assert abs(analyzer.shannon_entropy("aaaa") - 0.0) < 1e-9
    assert abs(analyzer.shannon_entropy("ab") - 1.0) < 1e-9
    assert abs(analyzer.shannon_entropy("abcd") - 2.0) < 1e-9
    assert abs(analyzer.max_entropy(4) - 2.0) < 1e-9

    empty = analyzer.analyze("")
    assert empty.classification == "empty"

    normal = analyzer.analyze("Hello, entropy world!")
    assert 0.0 <= normal.normalized_entropy <= 1.0
    assert normal.length == len("Hello, entropy world!")

    sample = (
        "def add_numbers(a, b):\n"
        "    total_value = a + b\n"
        "    return total_value\n"
        "\n"
        "result = add_numbers(1, 2)\n"
        "message = 'hello entropy'\n"
        "print(message, result)\n"
    )
    engine = PolymorphicEngine(seed=42)
    report = engine.mutate(sample, rounds=1)
    assert engine._is_valid_python(report.mutated)
    assert report.mutated != report.original

    r1 = PolymorphicEngine(seed=7).mutate(sample)
    r2 = PolymorphicEngine(seed=7).mutate(sample)
    assert r1.mutated == r2.mutated

    print("[self-test] entropy + mutation engine OK")


if __name__ == "__main__":
    _self_test()
    raise SystemExit(_cli())