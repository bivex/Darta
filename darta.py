#!/usr/bin/env python3
"""
Darta v1.0 — Dart/Flutter Architecture Analyzer
A static analysis tool for Dart/Flutter projects.
Usage: python darta.py [--path <dir>] [--format json|html|md] [--output file|stdout] [--component-depth N]
"""

import os
import re
import sys
import json
import argparse
import math
from fnmatch import fnmatchcase
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Dict, Optional, Tuple, Set
from pathlib import Path
from collections import defaultdict

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only when PyYAML is unavailable
    yaml = None

# ─────────────────────────────────────────────
# SECTION 1: Data Classes
# ─────────────────────────────────────────────

@dataclass
class FieldInfo:
    name: str
    type_name: str
    is_public: bool
    line: int


@dataclass
class MethodInfo:
    name: str
    params: List[str]
    start_line: int
    end_line: int
    cc: int = 1
    loc: int = 0
    is_public: bool = True

    @property
    def param_count(self) -> int:
        return len([p for p in self.params if p.strip()])


@dataclass
class ClassInfo:
    name: str
    file_path: str
    extends: Optional[str]
    implements: List[str]
    mixins: List[str]
    start_line: int
    end_line: int
    methods: List[MethodInfo] = field(default_factory=list)
    fields: List[FieldInfo] = field(default_factory=list)

    @property
    def loc(self) -> int:
        return max(0, self.end_line - self.start_line)

    @property
    def nom(self) -> int:
        return len(self.methods)

    @property
    def nopm(self) -> int:
        return sum(1 for m in self.methods if m.is_public)

    @property
    def nof(self) -> int:
        return len(self.fields)

    @property
    def nopf(self) -> int:
        return sum(1 for f in self.fields if f.is_public)

    @property
    def wmc(self) -> int:
        return sum(m.cc for m in self.methods)

    @property
    def avg_cc(self) -> float:
        if not self.methods:
            return 0.0
        return sum(m.cc for m in self.methods) / len(self.methods)


@dataclass
class FileInfo:
    path: str
    rel_path: str
    project_rel_path: str
    component: str
    raw_lines: List[str] = field(default_factory=list)
    clean_lines: List[str] = field(default_factory=list)
    analysis_lines: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    classes: List[ClassInfo] = field(default_factory=list)
    fanin: int = 0
    fanout: int = 0

    @property
    def loc(self) -> int:
        return sum(1 for ln in self.clean_lines if ln.strip())

    @property
    def total_methods(self) -> int:
        return sum(c.nom for c in self.classes)

    @property
    def avg_cc(self) -> float:
        all_methods = [m for c in self.classes for m in c.methods]
        if not all_methods:
            return 0.0
        return sum(m.cc for m in all_methods) / len(all_methods)


@dataclass
class ComponentInfo:
    name: str
    files: List[str] = field(default_factory=list)
    loc: int = 0
    incoming_components: Set[str] = field(default_factory=set, repr=False)
    outgoing_components: Set[str] = field(default_factory=set, repr=False)

    @property
    def fanin(self) -> int:
        return len(self.incoming_components)

    @property
    def fanout(self) -> int:
        return len(self.outgoing_components)

    @property
    def stability(self) -> float:
        total = self.fanin + self.fanout
        if total == 0:
            return 0.0
        return self.fanout / total

    @property
    def file_count(self) -> int:
        return len(self.files)


@dataclass
class Smell:
    smell: str
    severity: str
    reasons: List[str]
    suggestion: str
    file: str = ""
    class_name: str = ""
    method_name: str = ""
    component: str = ""
    line: int = 0


@dataclass
class ComponentPattern:
    name: str
    include: List[str]
    exclude: List[str] = field(default_factory=list)


@dataclass
class DependencyRule:
    source: str
    allow: List[str] = field(default_factory=list)


@dataclass
class ForbiddenPackageRule:
    components: List[str]
    packages: List[str]
    reason: str = ""


@dataclass
class FileImportRule:
    name: str
    from_patterns: List[str]
    to_patterns: List[str]
    severity: str = "warning"
    description: str = ""


@dataclass
class Waiver:
    rule: str
    from_patterns: List[str]
    to_patterns: List[str]
    reason: str = ""
    priority: str = "medium"


@dataclass
class DartaConfig:
    path: str = ""
    project_name: str = ""
    component_mode: str = "auto"
    component_depth: Optional[int] = None
    ignore_paths: List[str] = field(default_factory=list)
    components: List[ComponentPattern] = field(default_factory=list)
    layers: Dict[str, List[str]] = field(default_factory=dict)
    component_layers: Dict[str, str] = field(default_factory=dict)
    dependency_rules: List[DependencyRule] = field(default_factory=list)
    forbidden_packages: List[ForbiddenPackageRule] = field(default_factory=list)
    file_rules: List[FileImportRule] = field(default_factory=list)
    cycles: Dict[str, str] = field(default_factory=dict)
    budgets: Dict[str, Dict[str, int]] = field(default_factory=dict)
    waivers: List[Waiver] = field(default_factory=list)
    smell_settings: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    reporting: Dict[str, Any] = field(default_factory=dict)

    def is_ignored(self, project_rel_path: str) -> bool:
        return any(match_path_pattern(project_rel_path, pattern) for pattern in self.ignore_paths)

    def resolve_component(self, project_rel_path: str, fallback_component: str) -> str:
        if not self.components:
            return fallback_component

        for rule in self.components:
            if not any(match_path_pattern(project_rel_path, pattern) for pattern in rule.include):
                continue
            if any(match_path_pattern(project_rel_path, pattern) for pattern in rule.exclude):
                continue
            return rule.name

        return fallback_component

    def layer_for_component(self, component: str) -> Optional[str]:
        return self.component_layers.get(component)

    def allowed_targets_for_component(self, component: str) -> Optional[List[str]]:
        for rule in self.dependency_rules:
            if match_name_pattern(component, rule.source):
                return rule.allow
        return None

    def find_waiver(self, rule_name: str, from_path: str, to_path: str) -> Optional[Waiver]:
        for waiver in self.waivers:
            if waiver.rule not in (rule_name, "*"):
                continue
            if not any(match_path_pattern(from_path, pattern) for pattern in waiver.from_patterns):
                continue
            if not any(match_path_pattern(to_path, pattern) for pattern in waiver.to_patterns):
                continue
            return waiver
        return None


def normalize_path(path: str) -> str:
    normalized = path.replace(os.sep, '/')
    while normalized.startswith('./'):
        normalized = normalized[2:]
    return normalized


def _split_segments(path: str) -> List[str]:
    normalized = normalize_path(path).strip('/')
    if not normalized or normalized == '.':
        return []
    return normalized.split('/')


def match_path_pattern(path: str, pattern: str) -> bool:
    path_segments = _split_segments(path)
    pattern_segments = _split_segments(pattern)

    def _match(path_index: int, pattern_index: int) -> bool:
        if pattern_index == len(pattern_segments):
            return path_index == len(path_segments)
        token = pattern_segments[pattern_index]
        if token == '**':
            if pattern_index == len(pattern_segments) - 1:
                return True
            for next_index in range(path_index, len(path_segments) + 1):
                if _match(next_index, pattern_index + 1):
                    return True
            return False
        if path_index >= len(path_segments):
            return False
        if not fnmatchcase(path_segments[path_index], token):
            return False
        return _match(path_index + 1, pattern_index + 1)

    return _match(0, 0)


def match_name_pattern(name: str, pattern: str) -> bool:
    if pattern == '*':
        return True
    return match_path_pattern(name, pattern)


def config_severity(level: str, default: str = "MEDIUM") -> str:
    mapping = {
        'error': 'HIGH',
        'critical': 'HIGH',
        'warning': 'MEDIUM',
        'warn': 'MEDIUM',
        'info': 'LOW',
        'low': 'LOW',
        'medium': 'MEDIUM',
        'high': 'HIGH',
    }
    return mapping.get(str(level or '').strip().lower(), default)


def load_darta_config(project_path: str, config_path: Optional[str] = None) -> Optional[DartaConfig]:
    candidate_paths = []
    if config_path:
        candidate_paths.append(os.path.abspath(config_path))
    else:
        candidate_paths.extend([
            os.path.join(project_path, 'darta.yaml'),
            os.path.join(project_path, 'darta.yml'),
        ])

    resolved_path = next((path for path in candidate_paths if os.path.isfile(path)), None)
    if not resolved_path:
        if config_path:
            print(f"ERROR: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        return None

    if yaml is None:
        print(
            "ERROR: darta.yaml support requires PyYAML. Install it with `pip install pyyaml`.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        with open(resolved_path, 'r', encoding='utf-8') as f:
            raw = yaml.safe_load(f) or {}
    except Exception as exc:
        print(f"ERROR: Failed to read {resolved_path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(raw, dict):
        print(f"ERROR: {resolved_path} must contain a YAML object at the root.", file=sys.stderr)
        sys.exit(1)

    analysis = raw.get('analysis') or {}
    components = raw.get('components') or {}
    layers = raw.get('layers') or {}
    architecture = raw.get('architecture') or {}

    component_rules = []
    for name, spec in components.items():
        spec = spec or {}
        component_rules.append(ComponentPattern(
            name=str(name),
            include=[normalize_path(p) for p in (spec.get('include') or [])],
            exclude=[normalize_path(p) for p in (spec.get('exclude') or [])],
        ))

    component_layers = {}
    parsed_layers: Dict[str, List[str]] = {}
    for layer_name, component_names in layers.items():
        names = [str(name) for name in (component_names or [])]
        parsed_layers[str(layer_name)] = names
        for component_name in names:
            component_layers[component_name] = str(layer_name)

    dependency_rules = []
    for rule in architecture.get('dependency_rules') or []:
        dependency_rules.append(DependencyRule(
            source=str(rule.get('from', '')),
            allow=[str(name) for name in (rule.get('allow') or [])],
        ))

    forbidden_packages = []
    for rule in architecture.get('forbidden_packages') or []:
        forbidden_packages.append(ForbiddenPackageRule(
            components=[str(name) for name in (rule.get('from') or [])],
            packages=[str(name) for name in (rule.get('packages') or [])],
            reason=str(rule.get('reason', '')).strip(),
        ))

    file_rules = []
    for rule in architecture.get('file_rules') or []:
        forbid_imports = rule.get('forbid_imports') or {}
        file_rules.append(FileImportRule(
            name=str(rule.get('name', 'unnamed_rule')),
            from_patterns=[normalize_path(p) for p in (forbid_imports.get('from') or [])],
            to_patterns=[normalize_path(p) for p in (forbid_imports.get('to') or [])],
            severity=str(rule.get('severity', 'warning')),
            description=str(rule.get('description', '')).strip(),
        ))

    waivers = []
    for waiver in architecture.get('waivers') or []:
        from_value = waiver.get('from')
        to_value = waiver.get('to')
        from_patterns = from_value if isinstance(from_value, list) else [from_value]
        to_patterns = to_value if isinstance(to_value, list) else [to_value]
        waivers.append(Waiver(
            rule=str(waiver.get('rule', '*')),
            from_patterns=[normalize_path(p) for p in from_patterns if p],
            to_patterns=[normalize_path(p) for p in to_patterns if p],
            reason=str(waiver.get('reason', '')).strip(),
            priority=str(waiver.get('priority', 'medium')),
        ))

    component_depth = analysis.get('component_depth')
    if component_depth is not None:
        try:
            component_depth = int(component_depth)
        except (TypeError, ValueError):
            component_depth = None

    budgets = {}
    for budget_name, budget_map in (architecture.get('budgets') or {}).items():
        parsed_budget = {}
        for key, value in (budget_map or {}).items():
            try:
                parsed_budget[str(key)] = int(value)
            except (TypeError, ValueError):
                continue
        budgets[str(budget_name)] = parsed_budget

    return DartaConfig(
        path=resolved_path,
        project_name=str((raw.get('project') or {}).get('name', '')).strip(),
        component_mode=str(analysis.get('component_mode', 'auto')),
        component_depth=component_depth,
        ignore_paths=[normalize_path(p) for p in (analysis.get('ignore_paths') or [])],
        components=component_rules,
        layers=parsed_layers,
        component_layers=component_layers,
        dependency_rules=dependency_rules,
        forbidden_packages=forbidden_packages,
        file_rules=file_rules,
        cycles={str(k): str(v) for k, v in (architecture.get('cycles') or {}).items()},
        budgets=budgets,
        waivers=waivers,
        smell_settings=raw.get('smells') or {},
        reporting=raw.get('reporting') or {},
    )


# ─────────────────────────────────────────────
# SECTION 2: Dart Parser
# ─────────────────────────────────────────────

class DartParser:
    """Regex-based Dart file parser. No full AST — pattern matching only."""

    AGGREGATE_COMPONENT_DIRS = {'feature', 'features', 'module', 'modules'}

    # Patterns
    IMPORT_RE = re.compile(r"""^\s*import\s+['"]([^'"]+)['"]\s*(?:as\s+\w+)?\s*;""")
    EXPORT_RE = re.compile(r"""^\s*export\s+['"]([^'"]+)['"]\s*;""")
    PART_RE = re.compile(r"""^\s*part\s+(?!of\b)['"]([^'"]+)['"]\s*;""")
    CLASS_RE = re.compile(
        r"""^\s*(?:abstract\s+)?class\s+(\w+)"""
        r"""(?:\s+extends\s+(\w+))?"""
        r"""(?:\s+with\s+([\w\s,]+?))?"""
        r"""(?:\s+implements\s+([\w\s,]+?))?\s*\{"""
    )
    METHOD_RE = re.compile(
        r"""^\s*(?:(?:static|async|override|@\w+)\s+)*"""
        r"""(?:(?:void|bool|int|double|String|List|Map|Set|Future|Stream|Widget|dynamic|\w+(?:<[^>]+>)?)\s+)?"""
        r"""(\w+)\s*\(([^)]*)\)\s*(?:async\s*)?(?:\{|=>)"""
    )
    FIELD_RE = re.compile(
        r"""^\s*(?:final\s+|static\s+|late\s+|const\s+)*"""
        r"""(?:(?:bool|int|double|String|List|Map|Set|Future|Stream|Widget|dynamic|\w+(?:<[^>]+>)?)\s+)"""
        r"""(_?\w+)\s*[=;]"""
    )
    CC_TOKENS = re.compile(
        r"""\b(if|else|for|while|case|catch|&&|\|\|)\b|(\?\s*\w)"""
    )

    KEYWORDS = {
        'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break',
        'return', 'continue', 'class', 'extends', 'implements', 'with',
        'import', 'export', 'part', 'library', 'typedef', 'enum', 'mixin',
        'abstract', 'final', 'const', 'static', 'late', 'required', 'super',
        'this', 'new', 'null', 'true', 'false', 'void', 'var', 'dynamic',
        'async', 'await', 'yield', 'try', 'catch', 'finally', 'throw',
        'rethrow', 'assert', 'is', 'as', 'in', 'get', 'set', 'operator',
    }

    def __init__(self, component_depth: Optional[int] = None,
                 project_root: Optional[str] = None,
                 config: Optional[DartaConfig] = None):
        self.component_depth = component_depth
        self.project_root = os.path.abspath(project_root) if project_root else None
        self.config = config

    def remove_comments(self, source: str) -> Tuple[str, List[str]]:
        """Strip comments while preserving string literals for parsing."""
        return self._sanitize_source(source, strip_strings=False)

    def remove_comments_and_strings(self, source: str) -> Tuple[str, List[str]]:
        """Strip comments and string literals for smell detection."""
        return self._sanitize_source(source, strip_strings=True)

    def _sanitize_source(self, source: str, strip_strings: bool) -> Tuple[str, List[str]]:
        """Sanitize source while preserving newlines and respecting Dart string/comment syntax."""
        result = []
        i = 0
        n = len(source)
        in_line_comment = False
        in_block_comment = False
        string_quote = ''
        triple_quote = False
        raw_string = False

        while i < n:
            c = source[i]

            if in_line_comment:
                if c == '\n':
                    in_line_comment = False
                    result.append('\n')
                i += 1
                continue

            if in_block_comment:
                if i + 1 < n and source[i:i + 2] == '*/':
                    in_block_comment = False
                    i += 2
                    continue
                if c == '\n':
                    result.append('\n')
                i += 1
                continue

            if string_quote:
                closing = string_quote * 3 if triple_quote else string_quote
                if source.startswith(closing, i):
                    if not strip_strings:
                        result.append(closing)
                    string_quote = ''
                    triple_quote = False
                    raw_string = False
                    i += len(closing)
                    continue
                if c == '\n':
                    result.append('\n')
                    i += 1
                    continue
                if not triple_quote and not raw_string and c == '\\' and i + 1 < n:
                    if not strip_strings:
                        result.append(source[i:i + 2])
                    i += 2
                    continue
                if not strip_strings:
                    result.append(c)
                i += 1
                continue

            if i + 1 < n and source[i:i + 2] == '//':
                in_line_comment = True
                i += 2
                continue

            if i + 1 < n and source[i:i + 2] == '/*':
                in_block_comment = True
                i += 2
                continue

            if c in ("'", '"'):
                prev = source[i - 1] if i > 0 else ''
                prev2 = source[i - 2] if i > 1 else ''
                raw_string = prev in ('r', 'R') and not (prev2.isalnum() or prev2 == '_')
                triple_quote = source.startswith(c * 3, i)
                string_quote = c
                if not strip_strings:
                    result.append(c * 3 if triple_quote else c)
                i += 3 if triple_quote else 1
                continue

            result.append(c)
            i += 1

        sanitized = ''.join(result)
        return sanitized, sanitized.split('\n')

    def parse_file(self, path: str, lib_root: str) -> Optional[FileInfo]:
        """Parse a single .dart file and return FileInfo."""
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                source = f.read()
        except Exception as e:
            print(f"  [WARN] Cannot read {path}: {e}", file=sys.stderr)
            return None

        project_root = self.project_root or os.path.dirname(lib_root)
        rel = normalize_path(os.path.relpath(path, lib_root))
        project_rel = normalize_path(os.path.relpath(path, project_root))
        component = self._get_component(rel, project_rel)

        fi = FileInfo(path=path, rel_path=rel, project_rel_path=project_rel, component=component)
        fi.raw_lines = source.split('\n')

        _, fi.clean_lines = self.remove_comments(source)
        _, fi.analysis_lines = self.remove_comments_and_strings(source)

        # Parse imports
        seen_directives = set()
        for ln in fi.clean_lines:
            for pattern in (self.IMPORT_RE, self.EXPORT_RE, self.PART_RE):
                m = pattern.match(ln)
                if m:
                    directive = m.group(1)
                    if directive not in seen_directives:
                        fi.imports.append(directive)
                        seen_directives.add(directive)
                    break

        # Parse classes and methods
        fi.classes = self._parse_classes(fi.clean_lines, path)

        return fi

    def _get_component(self, rel_path: str, project_rel_path: str) -> str:
        """Get component name from relative path under lib/."""
        default_component = self._infer_component(rel_path)
        if self.config:
            return self.config.resolve_component(project_rel_path, default_component)
        return default_component

    def _infer_component(self, rel_path: str) -> str:
        """Infer component name from relative path under lib/."""
        parts = Path(rel_path).parts
        # rel_path is relative to lib_root (the lib/ dir itself)
        if len(parts) == 1:
            return "root"
        directories = parts[:-1]

        if self.component_depth is not None:
            depth = max(1, min(self.component_depth, len(directories)))
            return '/'.join(directories[:depth])

        if directories[0] in self.AGGREGATE_COMPONENT_DIRS and len(directories) >= 2:
            return '/'.join(directories[:2])

        return directories[0]

    def _parse_classes(self, lines: List[str], path: str) -> List[ClassInfo]:
        """Extract class definitions with their methods and fields."""
        classes = []
        i = 0
        while i < len(lines):
            ln = lines[i]
            m = self.CLASS_RE.match(ln)
            if m:
                class_name = m.group(1)
                extends = m.group(2)
                mixins_str = m.group(3) or ''
                impls_str = m.group(4) or ''
                mixins = [x.strip() for x in mixins_str.split(',') if x.strip()]
                implements = [x.strip() for x in impls_str.split(',') if x.strip()]

                # Find class body boundaries using brace counting
                start_line = i
                end_line = self._find_block_end(lines, i)

                ci = ClassInfo(
                    name=class_name,
                    file_path=path,
                    extends=extends,
                    implements=implements,
                    mixins=mixins,
                    start_line=start_line,
                    end_line=end_line,
                )

                body = lines[start_line:end_line + 1]
                ci.methods = self._parse_methods(body, start_line)
                ci.fields = self._parse_fields(body, start_line)
                classes.append(ci)
                i = end_line + 1
            else:
                i += 1
        return classes

    def _find_block_end(self, lines: List[str], start: int) -> int:
        """Find the closing brace for a block starting at `start`."""
        depth = 0
        for i in range(start, len(lines)):
            depth += lines[i].count('{') - lines[i].count('}')
            if depth <= 0 and i > start:
                return i
        return len(lines) - 1

    def _parse_methods(self, body: List[str], offset: int) -> List[MethodInfo]:
        """Extract method definitions from a class body."""
        methods = []
        i = 0
        # Skip the class declaration line
        i = 1
        while i < len(body):
            ln = body[i]
            m = self.METHOD_RE.match(ln)
            if m:
                method_name = m.group(1)
                params_str = m.group(2) or ''

                # Skip constructors (same name as class — we don't know class name here)
                # Skip keywords that look like methods
                if method_name in self.KEYWORDS:
                    i += 1
                    continue
                # Skip common non-method patterns
                if method_name in ('if', 'for', 'while', 'switch', 'catch'):
                    i += 1
                    continue

                params = self._parse_params(params_str)
                is_public = not method_name.startswith('_')
                start_line = offset + i

                # Find method end
                if '{' in ln:
                    end_line = offset + self._find_block_end(body, i)
                else:
                    # Arrow function or abstract — single line
                    end_line = start_line

                mi = MethodInfo(
                    name=method_name,
                    params=params,
                    start_line=start_line,
                    end_line=end_line,
                    is_public=is_public,
                )
                mi.loc = max(1, end_line - start_line)
                mi.cc = self._compute_cc(body[i:end_line - offset + 1])
                methods.append(mi)
                i = (end_line - offset) + 1
            else:
                i += 1
        return methods

    def _parse_params(self, params_str: str) -> List[str]:
        """Parse parameter list, handling nested generics."""
        if not params_str.strip():
            return []
        # Flatten nested < > to avoid splitting on commas inside generics
        depth = 0
        result = []
        current = []
        for c in params_str:
            if c in '<({':
                depth += 1
                current.append(c)
            elif c in '>)}':
                depth -= 1
                current.append(c)
            elif c == ',' and depth == 0:
                p = ''.join(current).strip()
                if p:
                    result.append(p)
                current = []
            else:
                current.append(c)
        p = ''.join(current).strip()
        if p:
            result.append(p)
        return result

    def _parse_fields(self, body: List[str], offset: int) -> List[FieldInfo]:
        """Extract field declarations from a class body."""
        fields = []
        for i, ln in enumerate(body[1:], 1):
            # Skip lines that look like method signatures
            if re.search(r'\(', ln) and re.search(r'\)\s*[{;=>]', ln):
                continue
            m = self.FIELD_RE.match(ln)
            if m:
                name = m.group(1)
                if name in self.KEYWORDS:
                    continue
                fields.append(FieldInfo(
                    name=name,
                    type_name='',
                    is_public=not name.startswith('_'),
                    line=offset + i,
                ))
        return fields

    def _compute_cc(self, lines: List[str]) -> int:
        """Cyclomatic complexity: 1 + count of branching tokens."""
        cc = 1
        for ln in lines:
            cc += len(self.CC_TOKENS.findall(ln))
        return cc


# ─────────────────────────────────────────────
# SECTION 3: Metrics Computer
# ─────────────────────────────────────────────

class MetricsComputer:
    """Computes cross-file metrics: FANIN, FANOUT, DIT, component coupling."""

    def __init__(self, files: List[FileInfo], lib_root: str):
        self.files = files
        self.lib_root = lib_root
        self.file_map: Dict[str, FileInfo] = {f.path: f for f in files}
        # Map from relative path (normalized) to FileInfo
        self.rel_map: Dict[str, FileInfo] = {f.rel_path: f for f in files}
        self.components: Dict[str, ComponentInfo] = {}
        self.file_dependencies: Dict[str, List[FileInfo]] = {}

    def compute_all(self):
        """Run all metric computations in order."""
        print("  Computing FANOUT / FANIN...", file=sys.stderr)
        self._compute_fan_metrics()
        print("  Computing DIT...", file=sys.stderr)
        self._compute_dit()
        print("  Computing components...", file=sys.stderr)
        self._compute_components()

    def _resolve_import(self, importing_file: FileInfo, import_path: str) -> Optional[FileInfo]:
        """Resolve a Dart import string to a FileInfo if it's a local file."""
        # Only resolve local file references or package imports pointing back to lib/
        if import_path.startswith('dart:') or import_path.startswith('package:flutter'):
            return None
        # package: imports — strip package prefix
        if import_path.startswith('package:'):
            # package:myapp/foo/bar.dart → foo/bar.dart
            parts = import_path.split('/', 1)
            if len(parts) > 1:
                local_path = parts[1]
                # Try to find in lib
                candidate = os.path.join(self.lib_root, local_path)
                if candidate in self.file_map:
                    return self.file_map[candidate]
                # Try rel_map
                if local_path in self.rel_map:
                    return self.rel_map[local_path]
            return None
        # Relative URI import/export/part. Dart allows both './foo.dart' and 'foo/bar.dart'.
        if ':' not in import_path:
            base = os.path.dirname(importing_file.path)
            resolved = os.path.normpath(os.path.join(base, import_path))
            if resolved in self.file_map:
                return self.file_map[resolved]
        return None

    def _compute_fan_metrics(self):
        """Compute FANOUT (internal imports) and FANIN (imported by others)."""
        for fi in self.files:
            fi.fanin = 0
            fi.fanout = 0

        for fi in self.files:
            targets = self._resolve_local_dependencies(fi)
            self.file_dependencies[fi.path] = targets
            fi.fanout = len(targets)
            for target in targets:
                target.fanin += 1

    def _resolve_local_dependencies(self, fi: FileInfo) -> List[FileInfo]:
        """Resolve unique internal dependencies for a file."""
        targets = []
        seen_paths = set()
        for imp in fi.imports:
            target = self._resolve_import(fi, imp)
            if not target or target.path == fi.path or target.path in seen_paths:
                continue
            seen_paths.add(target.path)
            targets.append(target)
        return targets

    def _compute_dit(self):
        """Depth of Inheritance Tree per class."""
        # Build class name → ClassInfo map (use first occurrence for duplicates)
        class_map: Dict[str, ClassInfo] = {}
        for fi in self.files:
            for ci in fi.classes:
                if ci.name not in class_map:
                    class_map[ci.name] = ci

        def depth(class_name: str, visited: Set[str] = None) -> int:
            if visited is None:
                visited = set()
            if class_name in visited or len(visited) > 10:
                return 0
            visited.add(class_name)
            ci = class_map.get(class_name)
            if ci is None or not ci.extends:
                return 0
            return 1 + depth(ci.extends, visited)

        # Store DIT on ClassInfo as a plain attribute
        for fi in self.files:
            for ci in fi.classes:
                ci.dit = depth(ci.name)  # type: ignore[attr-defined]

    def _compute_components(self):
        """Aggregate file-level metrics into components (first-level directories)."""
        comp_map: Dict[str, ComponentInfo] = defaultdict(lambda: ComponentInfo(name=''))
        for fi in self.files:
            comp = fi.component
            if comp not in comp_map:
                comp_map[comp] = ComponentInfo(name=comp)
            ci = comp_map[comp]
            ci.files.append(fi.path)
            ci.loc += fi.loc

        # Component coupling: count cross-component imports
        for fi in self.files:
            for target in self.file_dependencies.get(fi.path, []):
                if target.component != fi.component:
                    comp_map[fi.component].outgoing_components.add(target.component)
                    comp_map[target.component].incoming_components.add(fi.component)

        self.components = comp_map


# ─────────────────────────────────────────────
# SECTION 4: Smell Detector
# ─────────────────────────────────────────────

class SmellDetector:
    """Detects implementation, design, and architecture smells."""

    MAGIC_NUM_RE = re.compile(r'(?<![.\w])(\d+\.?\d*)(?![\w.])')
    CHAIN_RE = re.compile(r'(?:\.\w+\([^)]*\)){4,}')
    SWITCH_RE = re.compile(r'\bswitch\b')
    DEFAULT_RE = re.compile(r'\bdefault\s*:')
    IDENTIFIER_RE = re.compile(r'\b([a-zA-Z_]\w*)\b')

    WIDGET_BASES = {'StatelessWidget', 'StatefulWidget', 'State', 'Widget'}

    def __init__(self, files: List[FileInfo], components: Dict[str, ComponentInfo],
                 file_dependencies: Optional[Dict[str, List[FileInfo]]] = None,
                 config: Optional[DartaConfig] = None):
        self.files = files
        self.components = components
        self.file_dependencies = file_dependencies or {}
        self.config = config or DartaConfig()
        self.file_map: Dict[str, FileInfo] = {f.path: f for f in files}
        self.project_rel_map: Dict[str, FileInfo] = {f.project_rel_path: f for f in files}
        self.implementation_smells: List[Smell] = []
        self.design_smells: List[Smell] = []
        self.architecture_smells: List[Smell] = []
        self.applied_waivers: List[Dict[str, str]] = []

        impl_settings = self._config_section(self.config.smell_settings, 'implementation')
        long_method_cfg = self._config_section(impl_settings, 'long_method')
        long_parameter_cfg = self._config_section(impl_settings, 'long_parameter_list')
        long_statement_cfg = self._config_section(impl_settings, 'long_statement')
        long_identifier_cfg = self._config_section(impl_settings, 'long_identifier')
        magic_number_cfg = self._config_section(impl_settings, 'magic_number')

        self.long_method_threshold = self._as_int(long_method_cfg.get('threshold'), 30)
        self.widget_build_threshold = self._as_int(
            long_method_cfg.get('widget_build_threshold'),
            self.long_method_threshold,
        )
        self.long_parameter_threshold = self._as_int(long_parameter_cfg.get('threshold'), 4)
        self.long_statement_threshold = self._as_int(long_statement_cfg.get('threshold'), 120)
        self.long_identifier_threshold = self._as_int(long_identifier_cfg.get('threshold'), 30)
        self.long_identifier_ignore = {
            str(name) for name in (long_identifier_cfg.get('ignore_exact') or [])
        }

        self.magic_number_ignore_in_strings = bool(
            magic_number_cfg.get('ignore_in_strings', True)
        )
        self.magic_number_ignore_const_final = bool(
            magic_number_cfg.get('ignore_const_final', True)
        )
        self.magic_number_ignore_duration = bool(
            magic_number_cfg.get('ignore_duration_constructors', False)
        )
        self.magic_number_ignore_common_values = set()
        for value in magic_number_cfg.get('ignore_common_ui_values') or []:
            try:
                self.magic_number_ignore_common_values.add(float(value))
            except (TypeError, ValueError):
                continue

    def detect_all(self):
        print("  Detecting implementation smells...", file=sys.stderr)
        self._detect_implementation_smells()
        print("  Detecting design smells...", file=sys.stderr)
        self._detect_design_smells()
        print("  Detecting architecture smells...", file=sys.stderr)
        self._detect_architecture_smells()

    # ── Implementation Smells ──────────────────

    def _detect_implementation_smells(self):
        for fi in self.files:
            self._check_long_statements(fi)
            self._check_long_identifiers(fi)
            self._check_magic_numbers(fi)
            self._check_empty_catch(fi)
            self._check_missing_default(fi)
            self._check_long_message_chains(fi)
            for ci in fi.classes:
                for mi in ci.methods:
                    self._check_long_method(mi, ci, fi)
                    self._check_complex_method(mi, ci, fi)
                    self._check_long_parameter_list(mi, ci, fi)

    def _check_long_method(self, mi: MethodInfo, ci: ClassInfo, fi: FileInfo):
        threshold = self.long_method_threshold
        if mi.name == 'build' and self._is_widget_class(ci):
            threshold = self.widget_build_threshold

        if mi.loc > threshold:
            self.implementation_smells.append(Smell(
                smell="Long Method",
                severity="HIGH" if mi.loc > threshold * 1.75 else "MEDIUM",
                reasons=[f"{mi.name} has {mi.loc} lines (threshold: {threshold})"],
                suggestion="Extract parts of this method into smaller, named helper methods.",
                file=fi.rel_path,
                class_name=ci.name,
                method_name=mi.name,
                line=mi.start_line,
            ))

    def _check_complex_method(self, mi: MethodInfo, ci: ClassInfo, fi: FileInfo):
        if mi.cc > 10:
            self.implementation_smells.append(Smell(
                smell="Complex Method",
                severity="HIGH" if mi.cc > 20 else "MEDIUM",
                reasons=[f"{mi.name} has CC={mi.cc} (threshold: 10)"],
                suggestion="Simplify branching logic or extract into multiple methods.",
                file=fi.rel_path,
                class_name=ci.name,
                method_name=mi.name,
                line=mi.start_line,
            ))

    def _check_long_parameter_list(self, mi: MethodInfo, ci: ClassInfo, fi: FileInfo):
        if mi.param_count > self.long_parameter_threshold:
            self.implementation_smells.append(Smell(
                smell="Long Parameter List",
                severity="MEDIUM",
                reasons=[f"{mi.name} has {mi.param_count} parameters (threshold: {self.long_parameter_threshold})"],
                suggestion="Group parameters into a config object or use named parameters.",
                file=fi.rel_path,
                class_name=ci.name,
                method_name=mi.name,
                line=mi.start_line,
            ))

    def _check_long_statements(self, fi: FileInfo):
        for i, ln in enumerate(fi.raw_lines, 1):
            if len(ln) > self.long_statement_threshold:
                self.implementation_smells.append(Smell(
                    smell="Long Statement",
                    severity="LOW",
                    reasons=[f"Line {i} has {len(ln)} characters (threshold: {self.long_statement_threshold})"],
                    suggestion="Break long lines for readability.",
                    file=fi.rel_path,
                    line=i,
                ))

    def _check_long_identifiers(self, fi: FileInfo):
        seen = set()
        for ln in fi.raw_lines:
            for m in self.IDENTIFIER_RE.finditer(ln):
                ident = m.group(1)
                if ident in DartParser.KEYWORDS or ident in self.long_identifier_ignore:
                    continue
                if len(ident) <= self.long_identifier_threshold:
                    continue
                if ident not in seen:
                    seen.add(ident)
                    self.implementation_smells.append(Smell(
                        smell="Long Identifier",
                        severity="LOW",
                        reasons=[f"'{ident}' has {len(ident)} characters (threshold: {self.long_identifier_threshold})"],
                        suggestion="Use a shorter, equally descriptive name.",
                        file=fi.rel_path,
                    ))

    def _check_magic_numbers(self, fi: FileInfo):
        lines = fi.analysis_lines if self.magic_number_ignore_in_strings else fi.clean_lines
        for i, ln in enumerate(lines, 1):
            if self.magic_number_ignore_const_final and re.search(r'\b(const|final)\b', ln):
                continue
            if self.magic_number_ignore_duration and 'Duration(' in ln:
                continue
            for m in self.MAGIC_NUM_RE.finditer(ln):
                val = m.group(1)
                try:
                    num = float(val)
                    if abs(num) <= 2:
                        continue
                    if self._number_is_ignored(num):
                        continue
                except ValueError:
                    continue
                self.implementation_smells.append(Smell(
                    smell="Magic Number",
                    severity="LOW",
                    reasons=[f"Line {i}: literal {val} — extract to a named constant."],
                    suggestion="Define this value as a named constant.",
                    file=fi.rel_path,
                    line=i,
                ))
                break  # one per line

    def _check_empty_catch(self, fi: FileInfo):
        source = '\n'.join(fi.clean_lines)
        for m in re.finditer(r'\bcatch\s*\([^)]*\)\s*\{([^}]*)\}', source):
            body = m.group(1).strip()
            if not body or body.startswith('//'):
                # Find approximate line number
                line = source[:m.start()].count('\n') + 1
                self.implementation_smells.append(Smell(
                    smell="Empty Catch Clause",
                    severity="HIGH",
                    reasons=["Catch block is empty or contains only a comment."],
                    suggestion="Handle the exception or at least log it.",
                    file=fi.rel_path,
                    line=line,
                ))

    def _check_missing_default(self, fi: FileInfo):
        source = '\n'.join(fi.clean_lines)
        for m in self.SWITCH_RE.finditer(source):
            # Find the switch block end
            start = m.start()
            brace = source.find('{', start)
            if brace == -1:
                continue
            depth = 0
            end = brace
            for j in range(brace, len(source)):
                if source[j] == '{':
                    depth += 1
                elif source[j] == '}':
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
            block = source[brace:end]
            if not self.DEFAULT_RE.search(block):
                line = source[:start].count('\n') + 1
                self.implementation_smells.append(Smell(
                    smell="Missing Default",
                    severity="MEDIUM",
                    reasons=["switch statement has no default clause."],
                    suggestion="Add a default case to handle unexpected values.",
                    file=fi.rel_path,
                    line=line,
                ))

    def _check_long_message_chains(self, fi: FileInfo):
        for i, ln in enumerate(fi.raw_lines, 1):
            if self.CHAIN_RE.search(ln):
                self.implementation_smells.append(Smell(
                    smell="Long Message Chain",
                    severity="LOW",
                    reasons=[f"Line {i}: more than 3 chained method calls."],
                    suggestion="Extract intermediate results into local variables.",
                    file=fi.rel_path,
                    line=i,
                ))

    # ── Design Smells ─────────────────────────

    def _detect_design_smells(self):
        for fi in self.files:
            for ci in fi.classes:
                self._check_god_class(ci, fi)
                self._check_insufficient_modularization(ci, fi)
                self._check_deficient_encapsulation(ci, fi)
                self._check_hub_like(ci, fi)
                self._check_multifaceted(ci, fi)

    def _check_god_class(self, ci: ClassInfo, fi: FileInfo):
        is_god = (ci.loc > 300 and ci.nom > 15) or ci.wmc > 50
        if is_god:
            reasons = []
            if ci.loc > 300 and ci.nom > 15:
                reasons.append(f"LOC={ci.loc} > 300 and methods={ci.nom} > 15")
            if ci.wmc > 50:
                reasons.append(f"WMC={ci.wmc} > 50")
            self.design_smells.append(Smell(
                smell="God Class",
                severity="HIGH",
                reasons=reasons,
                suggestion="Split this class into smaller, single-responsibility classes.",
                file=fi.rel_path,
                class_name=ci.name,
            ))

    def _check_insufficient_modularization(self, ci: ClassInfo, fi: FileInfo):
        if ci.loc > 500:
            self.design_smells.append(Smell(
                smell="Insufficient Modularization",
                severity="MEDIUM",
                reasons=[f"LOC={ci.loc} > 500"],
                suggestion="Break this class into multiple smaller classes or modules.",
                file=fi.rel_path,
                class_name=ci.name,
            ))

    def _check_deficient_encapsulation(self, ci: ClassInfo, fi: FileInfo):
        if ci.nopf > 5:
            self.design_smells.append(Smell(
                smell="Deficient Encapsulation",
                severity="MEDIUM",
                reasons=[f"{ci.nopf} public fields > 5"],
                suggestion="Make fields private and expose via getters/setters.",
                file=fi.rel_path,
                class_name=ci.name,
            ))

    def _check_hub_like(self, ci: ClassInfo, fi: FileInfo):
        if fi.fanin > 8 and fi.fanout > 8:
            self.design_smells.append(Smell(
                smell="Hub-like Modularization",
                severity="HIGH",
                reasons=[f"FANIN={fi.fanin} > 8 and FANOUT={fi.fanout} > 8"],
                suggestion="Reduce coupling by introducing an interface or splitting concerns.",
                file=fi.rel_path,
                class_name=ci.name,
            ))

    def _check_multifaceted(self, ci: ClassInfo, fi: FileInfo):
        is_widget = self._is_widget_class(ci)
        if ci.wmc > 30 and fi.fanout > 5 and not is_widget:
            self.design_smells.append(Smell(
                smell="Multifaceted Abstraction",
                severity="MEDIUM",
                reasons=[f"WMC={ci.wmc} > 30, FANOUT={fi.fanout} > 5, not a Widget"],
                suggestion="Separate concerns — this class likely does too many things.",
                file=fi.rel_path,
                class_name=ci.name,
            ))

    # ── Architecture Smells ───────────────────

    def _detect_architecture_smells(self):
        for comp_name, ci in self.components.items():
            self._check_god_component(ci)
            self._check_dense_structure(ci)
        self._check_unstable_dependency()
        self._check_feature_concentration()
        self._check_dependency_rule_violations()
        self._check_forbidden_package_dependencies()
        self._check_file_rule_violations()
        self._check_cycle_violations()
        self._check_budget_violations()

    def _check_god_component(self, ci: ComponentInfo):
        if ci.loc > 2000 or ci.file_count > 15:
            reasons = []
            if ci.loc > 2000:
                reasons.append(f"LOC={ci.loc} > 2000")
            if ci.file_count > 15:
                reasons.append(f"Files={ci.file_count} > 15")
            self.architecture_smells.append(Smell(
                smell="God Component",
                severity="HIGH",
                reasons=reasons,
                suggestion="Split this directory into smaller, focused sub-components.",
                component=ci.name,
            ))

    def _check_dense_structure(self, ci: ComponentInfo):
        if ci.fanout > 8:
            self.architecture_smells.append(Smell(
                smell="Dense Structure",
                severity="MEDIUM",
                reasons=[f"External component dependencies={ci.fanout} > 8"],
                suggestion="Reduce dependencies or introduce abstractions.",
                component=ci.name,
            ))

    def _check_unstable_dependency(self):
        for source in self.components.values():
            if source.stability >= 0.4:
                continue

            unstable_targets = []
            for target_name in sorted(source.outgoing_components):
                target = self.components.get(target_name)
                if target and target.stability > 0.7:
                    unstable_targets.append(f"{target.name} ({target.stability:.2f})")

            if unstable_targets:
                self.architecture_smells.append(Smell(
                    smell="Unstable Dependency",
                    severity="HIGH",
                    reasons=[
                        f"'{source.name}' is relatively stable (stability={source.stability:.2f})",
                        f"Direct dependencies on unstable components: {', '.join(unstable_targets)}",
                    ],
                    suggestion="Stable components should not depend on unstable ones. "
                               "Invert the dependency direction or introduce an abstraction layer.",
                    component=source.name,
                ))

    def _check_feature_concentration(self):
        """Detect components that mix too many architectural concerns."""
        concern_terms = {
            'UI': {'widget', 'screen', 'page', 'view', 'button', 'dialog', 'modal'},
            'Data': {'repository', 'dao', 'database', 'cache', 'storage', 'model', 'entity', 'dto'},
            'Logic': {'service', 'usecase', 'interactor', 'manager', 'controller', 'coordinator'},
            'State': {'bloc', 'cubit', 'provider', 'notifier', 'state', 'store'},
            'Infrastructure': {'api', 'client', 'remote', 'network', 'http', 'dio', 'socket', 'platform', 'channel'},
        }

        for comp_name, ci in self.components.items():
            if ci.file_count < 4:
                continue

            concern_hits = defaultdict(list)
            for path in ci.files:
                tokens = ' '.join(part.lower() for part in Path(path).parts[-3:])
                for concern, terms in concern_terms.items():
                    if any(term in tokens for term in terms):
                        concern_hits[concern].append(os.path.basename(path))

            if len(concern_hits) > 3:
                summary = ', '.join(
                    f"{concern} ({len(files)})"
                    for concern, files in sorted(concern_hits.items())
                )
                self.architecture_smells.append(Smell(
                    smell="Feature Concentration",
                    severity="MEDIUM",
                    reasons=[f"Concerns detected: {summary}"],
                    suggestion="Organize files into focused UI, state, logic, data, and infrastructure directories.",
                    component=comp_name,
                ))

    def _check_dependency_rule_violations(self):
        if not self.config.dependency_rules:
            return

        for source in self.files:
            allowed_targets = self.config.allowed_targets_for_component(source.component)
            if allowed_targets is None:
                continue

            for target in self.file_dependencies.get(source.path, []):
                if target.component == source.component:
                    continue
                if any(match_name_pattern(target.component, pattern) for pattern in allowed_targets):
                    continue

                waiver = self._find_matching_waiver(
                    ['dependency_rules'],
                    source.project_rel_path,
                    target.project_rel_path,
                )
                if waiver:
                    self._record_waiver(waiver, source.project_rel_path, target.project_rel_path)
                    continue

                allowed_desc = ', '.join(allowed_targets) if allowed_targets else '(no cross-component dependencies)'
                self.architecture_smells.append(Smell(
                    smell="Dependency Rule Violation",
                    severity="HIGH",
                    reasons=[
                        f"Component '{source.component}' may depend only on: {allowed_desc}",
                        f"{source.project_rel_path} imports {target.project_rel_path} ({target.component})",
                    ],
                    suggestion="Move the dependency behind an allowed contract, or document an intentional waiver in darta.yaml.",
                    component=source.component,
                    file=source.project_rel_path,
                ))

    def _check_forbidden_package_dependencies(self):
        if not self.config.forbidden_packages:
            return

        for fi in self.files:
            package_imports = [imp for imp in fi.imports if imp.startswith('package:')]
            if not package_imports:
                continue

            for rule in self.config.forbidden_packages:
                if not any(match_name_pattern(fi.component, component) for component in rule.components):
                    continue

                for package_import in package_imports:
                    if package_import not in rule.packages:
                        continue

                    waiver = self._find_matching_waiver(
                        ['forbidden_packages'],
                        fi.project_rel_path,
                        package_import,
                    )
                    if waiver:
                        self._record_waiver(waiver, fi.project_rel_path, package_import)
                        continue

                    self.architecture_smells.append(Smell(
                        smell="Forbidden Package Dependency",
                        severity="HIGH",
                        reasons=[
                            f"Component '{fi.component}' must not import {package_import}",
                            rule.reason or "This package is reserved for another architectural boundary.",
                        ],
                        suggestion="Move this SDK usage to the configured owning layer, or depend on an abstraction instead.",
                        component=fi.component,
                        file=fi.project_rel_path,
                    ))

    def _check_file_rule_violations(self):
        if not self.config.file_rules:
            return

        for rule in self.config.file_rules:
            for source in self.files:
                if not any(match_path_pattern(source.project_rel_path, pattern) for pattern in rule.from_patterns):
                    continue

                for target in self.file_dependencies.get(source.path, []):
                    if not any(match_path_pattern(target.project_rel_path, pattern) for pattern in rule.to_patterns):
                        continue

                    waiver = self._find_matching_waiver(
                        [rule.name, 'file_rules'],
                        source.project_rel_path,
                        target.project_rel_path,
                    )
                    if waiver:
                        self._record_waiver(waiver, source.project_rel_path, target.project_rel_path)
                        continue

                    description = rule.description or "A configured file-level import rule was violated."
                    self.architecture_smells.append(Smell(
                        smell="File Rule Violation",
                        severity=config_severity(rule.severity),
                        reasons=[
                            f"Rule '{rule.name}' forbids this import.",
                            description,
                            f"{source.project_rel_path} imports {target.project_rel_path}",
                        ],
                        suggestion="Remove the direct import, or reshape the dependency through an allowed boundary.",
                        component=source.component,
                        file=source.project_rel_path,
                    ))

    def _check_cycle_violations(self):
        if not self.config.cycles:
            return

        file_severity = self.config.cycles.get('files')
        if file_severity:
            graph = {
                fi.project_rel_path: {
                    target.project_rel_path
                    for target in self.file_dependencies.get(fi.path, [])
                }
                for fi in self.files
            }
            self._append_cycle_smells(
                graph,
                smell_name="File Cycle",
                severity=config_severity(file_severity),
                suggestion="Break the file-level cycle by extracting an interface or shared helper.",
            )

        component_severity = self.config.cycles.get('components')
        if component_severity:
            graph = {
                name: set(info.outgoing_components)
                for name, info in self.components.items()
            }
            self._append_cycle_smells(
                graph,
                smell_name="Component Cycle",
                severity=config_severity(component_severity),
                suggestion="Refactor cross-component references so dependencies flow in one direction.",
            )

        layer_severity = self.config.cycles.get('layers')
        if layer_severity and self.config.component_layers:
            graph: Dict[str, Set[str]] = defaultdict(set)
            for source_name, source in self.components.items():
                source_layer = self.config.layer_for_component(source_name)
                if not source_layer:
                    continue
                graph.setdefault(source_layer, set())
                for target_name in source.outgoing_components:
                    target_layer = self.config.layer_for_component(target_name)
                    if target_layer and target_layer != source_layer:
                        graph[source_layer].add(target_layer)
                        graph.setdefault(target_layer, set())

            self._append_cycle_smells(
                graph,
                smell_name="Layer Cycle",
                severity=config_severity(layer_severity),
                suggestion="Restore one-way layer flow by moving dependencies inward or introducing ports.",
            )

    def _check_budget_violations(self):
        if not self.config.budgets:
            return

        fanout_budget = self.config.budgets.get('max_component_fanout') or {}
        for component_name, component in self.components.items():
            limit = self._resolve_named_budget(fanout_budget, component_name)
            if limit is None or component.fanout <= limit:
                continue
            self.architecture_smells.append(Smell(
                smell="Component Fanout Budget Exceeded",
                severity="HIGH" if component.fanout > limit * 1.5 else "MEDIUM",
                reasons=[f"{component_name} fan-out is {component.fanout} (budget: {limit})"],
                suggestion="Reduce outward dependencies or split the component into smaller slices.",
                component=component_name,
            ))

        size_budget = self.config.budgets.get('max_files_per_component') or {}
        for component_name, component in self.components.items():
            limit = self._resolve_named_budget(size_budget, component_name)
            if limit is None or component.file_count <= limit:
                continue
            self.architecture_smells.append(Smell(
                smell="Component Size Budget Exceeded",
                severity="HIGH" if component.file_count > limit * 1.5 else "MEDIUM",
                reasons=[f"{component_name} contains {component.file_count} files (budget: {limit})"],
                suggestion="Split the component by feature or responsibility before it turns into a monolith.",
                component=component_name,
            ))

        file_budget = self.config.budgets.get('max_loc_per_file') or {}
        for fi in self.files:
            limit = self._resolve_path_budget(file_budget, fi.project_rel_path)
            if limit is None or fi.loc <= limit:
                continue
            self.architecture_smells.append(Smell(
                smell="File Size Budget Exceeded",
                severity="HIGH" if fi.loc > limit * 1.5 else "MEDIUM",
                reasons=[f"{fi.project_rel_path} has {fi.loc} LOC (budget: {limit})"],
                suggestion="Break this file into smaller collaborators or widgets so the module stays navigable.",
                component=fi.component,
                file=fi.project_rel_path,
            ))

    def _append_cycle_smells(self, graph: Dict[str, Set[str]], smell_name: str,
                             severity: str, suggestion: str):
        for cycle_nodes in self._find_cycles(graph):
            label = ', '.join(cycle_nodes)
            self.architecture_smells.append(Smell(
                smell=smell_name,
                severity=severity,
                reasons=[f"Cycle detected among: {label}"],
                suggestion=suggestion,
                component=cycle_nodes[0],
                file=cycle_nodes[0],
            ))

    def _find_cycles(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        index = 0
        stack: List[str] = []
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        on_stack: Set[str] = set()
        components: List[List[str]] = []

        def strongconnect(node: str):
            nonlocal index
            indices[node] = index
            lowlinks[node] = index
            index += 1
            stack.append(node)
            on_stack.add(node)

            for neighbor in graph.get(node, set()):
                if neighbor not in indices:
                    strongconnect(neighbor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
                elif neighbor in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[neighbor])

            if lowlinks[node] == indices[node]:
                scc = []
                while stack:
                    item = stack.pop()
                    on_stack.remove(item)
                    scc.append(item)
                    if item == node:
                        break
                components.append(sorted(scc))

        for node in graph:
            if node not in indices:
                strongconnect(node)

        cycles = []
        for group in components:
            if len(group) > 1:
                cycles.append(group)
                continue
            node = group[0]
            if node in graph.get(node, set()):
                cycles.append(group)
        return cycles

    def _find_matching_waiver(self, rule_names: List[str], from_path: str,
                              to_path: str) -> Optional[Waiver]:
        for rule_name in rule_names:
            waiver = self.config.find_waiver(rule_name, from_path, to_path)
            if waiver:
                return waiver
        return None

    def _record_waiver(self, waiver: Waiver, from_path: str, to_path: str):
        self.applied_waivers.append({
            'rule': waiver.rule,
            'from': from_path,
            'to': to_path,
            'reason': waiver.reason,
            'priority': waiver.priority,
        })

    def _resolve_named_budget(self, budget_map: Dict[str, int], name: str) -> Optional[int]:
        if name in budget_map:
            return budget_map[name]
        best_match = None
        best_len = -1
        for pattern, value in budget_map.items():
            if pattern == 'default':
                continue
            if match_name_pattern(name, pattern) and len(pattern) > best_len:
                best_match = value
                best_len = len(pattern)
        if best_match is not None:
            return best_match
        return budget_map.get('default')

    def _resolve_path_budget(self, budget_map: Dict[str, int], path: str) -> Optional[int]:
        if path in budget_map:
            return budget_map[path]
        best_match = None
        best_len = -1
        for pattern, value in budget_map.items():
            if pattern == 'default':
                continue
            if match_path_pattern(path, pattern) and len(pattern) > best_len:
                best_match = value
                best_len = len(pattern)
        if best_match is not None:
            return best_match
        return budget_map.get('default')

    def _config_section(self, root: Dict[str, Any], key: str) -> Dict[str, Any]:
        value = root.get(key) if isinstance(root, dict) else {}
        return value if isinstance(value, dict) else {}

    def _as_int(self, value: Any, default: int) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _is_widget_class(self, ci: ClassInfo) -> bool:
        return ci.extends in self.WIDGET_BASES or any(b in self.WIDGET_BASES for b in ci.mixins)

    def _number_is_ignored(self, num: float) -> bool:
        return any(math.isclose(num, candidate, rel_tol=0.0, abs_tol=1e-9)
                   for candidate in self.magic_number_ignore_common_values)


# ─────────────────────────────────────────────
# SECTION 5: Health Score
# ─────────────────────────────────────────────

def compute_health(smells_arch: List[Smell], smells_design: List[Smell],
                   smells_impl: List[Smell]) -> Tuple[float, float]:
    """Return (health_score, technical_debt_score)."""
    # Count by smell type
    counts = defaultdict(int)
    for s in smells_arch:
        counts[s.smell] += 1
    for s in smells_design:
        counts[s.smell] += 1
    for s in smells_impl:
        counts[s.smell] += 1

    debt = (
        counts["God Class"] * 50 +
        counts["God Component"] * 100 +
        counts["Unstable Dependency"] * 80 +
        counts["Dense Structure"] * 40 +
        counts["Feature Concentration"] * 35 +
        counts["Dependency Rule Violation"] * 90 +
        counts["Forbidden Package Dependency"] * 85 +
        counts["File Rule Violation"] * 70 +
        counts["File Cycle"] * 90 +
        counts["Component Cycle"] * 120 +
        counts["Layer Cycle"] * 140 +
        counts["Component Fanout Budget Exceeded"] * 30 +
        counts["Component Size Budget Exceeded"] * 25 +
        counts["File Size Budget Exceeded"] * 10 +
        counts["Hub-like Modularization"] * 60 +
        counts["Insufficient Modularization"] * 30 +
        counts["Deficient Encapsulation"] * 20 +
        counts["Long Method"] * 5 +
        counts["Complex Method"] * 10 +
        counts["Magic Number"] * 2
    )
    health = max(0.0, 100.0 - debt / 10.0)
    return round(health, 1), round(debt, 1)


# ─────────────────────────────────────────────
# SECTION 6: Actionable Recommendations
# ─────────────────────────────────────────────

def build_recommendations(smells_arch, smells_design, smells_impl) -> List[Dict]:
    """Derive prioritized recommendations from detected smells."""
    recs = []
    counts = defaultdict(int)
    for s in smells_arch + smells_design + smells_impl:
        counts[s.smell] += 1

    priority_map = {
        "God Component": ("CRITICAL", "Architecture", "A component is acting as a monolith.",
                          "Split into sub-components by feature or layer."),
        "Unstable Dependency": ("CRITICAL", "Architecture",
                                "Stable components depend on unstable ones.",
                                "Introduce interfaces or inversion of control."),
        "Dependency Rule Violation": ("CRITICAL", "Architecture",
                                      "A component depends on a forbidden architectural boundary.",
                                      "Route the dependency through an allowed contract or port."),
        "Forbidden Package Dependency": ("CRITICAL", "Architecture",
                                         "A layer imports an SDK/package owned by another boundary.",
                                         "Move the SDK usage to the owning layer or wrap it behind an interface."),
        "Layer Cycle": ("CRITICAL", "Architecture",
                        "Configured layers now depend on each other cyclically.",
                        "Restore one-way flow between layers."),
        "Component Cycle": ("CRITICAL", "Architecture",
                            "Components depend on each other in a cycle.",
                            "Break the cycle with interfaces or a new shared abstraction."),
        "File Cycle": ("HIGH", "Architecture",
                       "Files import each other cyclically.",
                       "Extract shared code or invert one side of the dependency."),
        "File Rule Violation": ("HIGH", "Architecture",
                                "A configured file-level import constraint was violated.",
                                "Remove the direct import and use an allowed entrypoint."),
        "God Class": ("HIGH", "Design", "Classes accumulate excessive responsibilities.",
                      "Apply Single Responsibility Principle — split the class."),
        "Dense Structure": ("HIGH", "Architecture", "Component has too many external dependencies.",
                            "Use dependency injection and reduce coupling."),
        "Feature Concentration": ("MEDIUM", "Architecture",
                                  "A single component mixes too many architectural concerns.",
                                  "Split the component into focused UI, state, domain, data, or infrastructure slices."),
        "Component Fanout Budget Exceeded": ("MEDIUM", "Architecture",
                                             "A component exceeds its allowed outgoing dependency budget.",
                                             "Reduce fan-out or split the component by responsibility."),
        "Component Size Budget Exceeded": ("MEDIUM", "Architecture",
                                           "A component exceeds its file budget.",
                                           "Split the component before coordination cost keeps growing."),
        "File Size Budget Exceeded": ("MEDIUM", "Architecture",
                                      "A file exceeds its configured LOC budget.",
                                      "Split the file into smaller collaborators or widgets."),
        "Hub-like Modularization": ("HIGH", "Design", "File is both imported by and imports many others.",
                                    "Extract shared logic to a dedicated module."),
        "Complex Method": ("HIGH", "Implementation", "Methods with high cyclomatic complexity.",
                           "Simplify branching; extract conditions to named methods."),
        "Insufficient Modularization": ("MEDIUM", "Design", "Classes are too large.",
                                        "Break into smaller, focused classes."),
        "Deficient Encapsulation": ("MEDIUM", "Design", "Too many public fields.",
                                    "Encapsulate fields; expose via getters/setters."),
        "Long Method": ("MEDIUM", "Implementation", "Methods are too long.",
                        "Extract logic into smaller helper methods."),
        "Empty Catch Clause": ("MEDIUM", "Implementation", "Exceptions are silently swallowed.",
                               "Handle or log every exception."),
        "Missing Default": ("MEDIUM", "Implementation", "Switch statements lack a default clause.",
                            "Always provide a default case."),
        "Magic Number": ("LOW", "Implementation", "Hardcoded numeric literals.",
                         "Extract to named constants."),
        "Long Statement": ("LOW", "Implementation", "Lines exceed 120 chars.",
                           "Break long lines for readability."),
    }

    for smell, (priority, category, issue, action) in priority_map.items():
        n = counts.get(smell, 0)
        if n > 0:
            recs.append({
                "priority": priority,
                "category": category,
                "issue": issue,
                "action": action,
                "affected_count": n,
            })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs.sort(key=lambda r: order.get(r["priority"], 99))
    return recs


# ─────────────────────────────────────────────
# SECTION 7: JSON Reporter
# ─────────────────────────────────────────────

class JSONReporter:
    def generate(self, files: List[FileInfo], components: Dict[str, ComponentInfo],
                 smells_arch: List[Smell], smells_design: List[Smell],
                 smells_impl: List[Smell], project_name: str,
                 config_path: Optional[str] = None,
                 applied_waivers: Optional[List[Dict[str, str]]] = None) -> str:
        health, debt = compute_health(smells_arch, smells_design, smells_impl)
        all_classes = [ci for fi in files for ci in fi.classes]
        all_methods = [mi for fi in files for ci in fi.classes for mi in ci.methods]
        avg_cc = (sum(m.cc for m in all_methods) / len(all_methods)) if all_methods else 0.0
        avg_wmc = (sum(c.wmc for c in all_classes) / len(all_classes)) if all_classes else 0.0

        recs = build_recommendations(smells_arch, smells_design, smells_impl)

        data = {
            "meta": {
                "project": project_name,
                "analysis_date": datetime.now().isoformat(),
                "generator": "Darta v1.0",
                "files_analyzed": len(files),
                "config_path": config_path,
            },
            "summary_kpis": {
                "total_files": len(files),
                "total_loc": sum(f.loc for f in files),
                "total_classes": len(all_classes),
                "avg_cc": round(avg_cc, 2),
                "avg_wmc": round(avg_wmc, 2),
            },
            "code_health": {
                "health_score": health,
                "technical_debt_score": debt,
                "architecture_smells_total": len(smells_arch),
                "god_classes": sum(1 for s in smells_design if s.smell == "God Class"),
                "god_components": sum(1 for s in smells_arch if s.smell == "God Component"),
                "unstable_dependencies": sum(1 for s in smells_arch if s.smell == "Unstable Dependency"),
                "feature_concentrations": sum(1 for s in smells_arch if s.smell == "Feature Concentration"),
                "dependency_rule_violations": sum(1 for s in smells_arch if s.smell == "Dependency Rule Violation"),
                "cycle_violations": sum(1 for s in smells_arch if s.smell in {"File Cycle", "Component Cycle", "Layer Cycle"}),
                "implementation_smells_total": len(smells_impl),
            },
            "architecture_smells": [
                {
                    "smell": s.smell,
                    "component": s.component,
                    "file": s.file,
                    "severity": s.severity,
                    "reasons": s.reasons,
                    "suggestion": s.suggestion,
                }
                for s in smells_arch
            ],
            "design_smells": [
                {
                    "smell": s.smell,
                    "class": s.class_name,
                    "file": s.file,
                    "severity": s.severity,
                    "reasons": s.reasons,
                    "suggestion": s.suggestion,
                }
                for s in smells_design
            ],
            "implementation_smells": [
                {
                    "smell": s.smell,
                    "method": s.method_name,
                    "class": s.class_name,
                    "file": s.file,
                    "severity": s.severity,
                    "line": s.line,
                }
                for s in smells_impl
            ],
            "components": [
                {
                    "name": ci.name,
                    "files": ci.file_count,
                    "loc": ci.loc,
                    "stability": round(ci.stability, 3),
                    "fanin": ci.fanin,
                    "fanout": ci.fanout,
                    "depends_on": sorted(ci.outgoing_components),
                    "used_by": sorted(ci.incoming_components),
                }
                for ci in components.values()
            ],
            "files_inventory": [
                {
                    "path": fi.rel_path,
                    "loc": fi.loc,
                    "classes": len(fi.classes),
                    "fanin": fi.fanin,
                    "fanout": fi.fanout,
                    "cc_avg": round(fi.avg_cc, 2),
                }
                for fi in sorted(files, key=lambda f: f.loc, reverse=True)
            ],
            "classes_inventory": [
                {
                    "name": ci.name,
                    "file": fi.rel_path,
                    "loc": ci.loc,
                    "nom": ci.nom,
                    "wmc": ci.wmc,
                    "dit": getattr(ci, 'dit', 0),
                    "nof": ci.nof,
                    "nopf": ci.nopf,
                }
                for fi in files
                for ci in fi.classes
            ],
            "actionable_recommendations": recs,
        }
        if applied_waivers:
            data["applied_waivers"] = applied_waivers
        return json.dumps(data, indent=2)


# ─────────────────────────────────────────────
# SECTION 8: Markdown Reporter
# ─────────────────────────────────────────────

class MarkdownReporter:
    def generate(self, files: List[FileInfo], components: Dict[str, ComponentInfo],
                 smells_arch: List[Smell], smells_design: List[Smell],
                 smells_impl: List[Smell], project_name: str,
                 config_path: Optional[str] = None,
                 applied_waivers: Optional[List[Dict[str, str]]] = None) -> str:
        health, debt = compute_health(smells_arch, smells_design, smells_impl)
        all_classes = [ci for fi in files for ci in fi.classes]
        all_methods = [mi for fi in files for ci in fi.classes for mi in ci.methods]
        avg_cc = (sum(m.cc for m in all_methods) / len(all_methods)) if all_methods else 0.0
        recs = build_recommendations(smells_arch, smells_design, smells_impl)

        subtitle = f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | Darta v1.0_"
        if config_path:
            subtitle = subtitle[:-1] + f" | Config: `{os.path.basename(config_path)}`_"

        lines = [
            f"# Darta Report — {project_name}",
            subtitle,
            "",
            "## Health Score",
            f"**{health}/100** (Technical Debt: {debt})",
            "",
            "## Summary KPIs",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Files | {len(files)} |",
            f"| Total LOC | {sum(f.loc for f in files)} |",
            f"| Classes | {len(all_classes)} |",
            f"| Avg CC | {avg_cc:.2f} |",
            "",
        ]

        if smells_arch:
            lines += ["## Architecture Smells", ""]
            for s in smells_arch:
                target = s.component or s.file or "project"
                lines.append(f"### [{s.severity}] {s.smell} — `{target}`")
                for r in s.reasons:
                    lines.append(f"- {r}")
                lines.append(f"> **Suggestion:** {s.suggestion}")
                lines.append("")

        if smells_design:
            lines += ["## Design Smells", ""]
            for s in smells_design:
                lines.append(f"### [{s.severity}] {s.smell} — `{s.class_name}` in `{s.file}`")
                for r in s.reasons:
                    lines.append(f"- {r}")
                lines.append(f"> **Suggestion:** {s.suggestion}")
                lines.append("")

        if smells_impl:
            lines += ["## Implementation Smells", ""]
            for s in smells_impl[:50]:  # cap for readability
                loc = f" (line {s.line})" if s.line else ""
                lines.append(f"- **[{s.severity}] {s.smell}** in `{s.file}`{loc}: {'; '.join(s.reasons)}")
            if len(smells_impl) > 50:
                lines.append(f"_...and {len(smells_impl) - 50} more._")
            lines.append("")

        if applied_waivers:
            lines += ["## Applied Waivers", ""]
            for waiver in applied_waivers:
                reason = f": {waiver['reason']}" if waiver.get('reason') else ""
                lines.append(
                    f"- `{waiver['rule']}` waived for `{waiver['from']}` -> `{waiver['to']}`{reason}"
                )
            lines.append("")

        if recs:
            lines += ["## Actionable Recommendations", ""]
            for r in recs:
                lines.append(f"**[{r['priority']}] {r['issue']}**  ")
                lines.append(f"Action: {r['action']} (affects {r['affected_count']} items)")
                lines.append("")

        lines += ["## Components", "",
                  "| Component | Files | LOC | Stability | FAN-IN | FAN-OUT |",
                  "|-----------|-------|-----|-----------|--------|---------|"]
        for ci in sorted(components.values(), key=lambda c: c.loc, reverse=True):
            lines.append(f"| {ci.name} | {ci.file_count} | {ci.loc} | {ci.stability:.2f} | {ci.fanin} | {ci.fanout} |")
        lines.append("")

        lines += ["## Files Inventory (Top 20 by LOC)", "",
                  "| File | LOC | Classes | FAN-IN | FAN-OUT | Avg CC |",
                  "|------|-----|---------|--------|---------|--------|"]
        for fi in sorted(files, key=lambda f: f.loc, reverse=True)[:20]:
            lines.append(f"| `{fi.rel_path}` | {fi.loc} | {len(fi.classes)} | {fi.fanin} | {fi.fanout} | {fi.avg_cc:.2f} |")

        return '\n'.join(lines)


# ─────────────────────────────────────────────
# SECTION 9: HTML Reporter
# ─────────────────────────────────────────────

class HTMLReporter:
    SEVERITY_COLOR = {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#eab308"}
    SEVERITY_LABEL = {"HIGH": "HIGH", "MEDIUM": "MED", "LOW": "LOW"}

    def generate(self, files: List[FileInfo], components: Dict[str, ComponentInfo],
                 smells_arch: List[Smell], smells_design: List[Smell],
                 smells_impl: List[Smell], project_name: str,
                 config_path: Optional[str] = None,
                 applied_waivers: Optional[List[Dict[str, str]]] = None) -> str:
        health, debt = compute_health(smells_arch, smells_design, smells_impl)
        all_classes = [ci for fi in files for ci in fi.classes]
        all_methods = [mi for fi in files for ci in fi.classes for mi in ci.methods]
        avg_cc = (sum(m.cc for m in all_methods) / len(all_methods)) if all_methods else 0.0
        avg_wmc = (sum(c.wmc for c in all_classes) / len(all_classes)) if all_classes else 0.0
        recs = build_recommendations(smells_arch, smells_design, smells_impl)
        config_label = f" &nbsp;|&nbsp; config: {os.path.basename(config_path)}" if config_path else ""

        if health >= 80:
            health_color = "#22c55e"
        elif health >= 60:
            health_color = "#eab308"
        else:
            health_color = "#ef4444"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Darta Report — {project_name}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  h1 {{ font-size: 1.8rem; font-weight: 700; }}
  h2 {{ font-size: 1.2rem; font-weight: 600; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin: 2rem 0 1rem; }}
  h3 {{ font-size: 1rem; font-weight: 600; }}
  .container {{ max-width: 1280px; margin: 0 auto; padding: 1.5rem; }}
  header {{ background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); border-bottom: 1px solid #1e293b; padding: 1.5rem 0; margin-bottom: 2rem; }}
  header .inner {{ max-width: 1280px; margin: 0 auto; padding: 0 1.5rem; display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }}
  .subtitle {{ color: #64748b; font-size: 0.85rem; margin-top: 0.25rem; }}
  .health-badge {{ background: {health_color}22; border: 2px solid {health_color}; border-radius: 1rem; padding: 0.5rem 1.25rem; text-align: center; }}
  .health-badge .score {{ font-size: 2rem; font-weight: 800; color: {health_color}; line-height: 1; }}
  .health-badge .label {{ font-size: 0.7rem; color: #94a3b8; text-transform: uppercase; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
  .kpi {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; padding: 1rem; }}
  .kpi .val {{ font-size: 1.6rem; font-weight: 700; color: #60a5fa; }}
  .kpi .lbl {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
  .smell-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.75rem; margin-bottom: 0.75rem; overflow: hidden; }}
  .smell-header {{ display: flex; align-items: center; gap: 0.75rem; padding: 0.85rem 1rem; cursor: pointer; user-select: none; }}
  .smell-header:hover {{ background: #243044; }}
  .badge {{ font-size: 0.65rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 0.25rem; letter-spacing: 0.05em; flex-shrink: 0; }}
  .smell-name {{ font-weight: 600; flex: 1; }}
  .smell-meta {{ font-size: 0.8rem; color: #64748b; }}
  .smell-body {{ padding: 0.75rem 1rem 1rem; border-top: 1px solid #334155; display: none; }}
  .smell-body.open {{ display: block; }}
  .reason {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 0.25rem; }}
  .suggestion {{ background: #0f2044; border-left: 3px solid #3b82f6; padding: 0.5rem 0.75rem; border-radius: 0 0.5rem 0.5rem 0; color: #93c5fd; font-size: 0.85rem; margin-top: 0.5rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{ background: #1e293b; color: #94a3b8; text-align: left; padding: 0.6rem 0.75rem; border-bottom: 2px solid #334155; font-weight: 600; text-transform: uppercase; font-size: 0.7rem; letter-spacing: 0.05em; white-space: nowrap; }}
  td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b; color: #cbd5e1; white-space: nowrap; }}
  tr:hover td {{ background: #1e293b33; }}
  .tbl-wrap {{ background: #0f1a2e; border: 1px solid #334155; border-radius: 0.75rem; overflow: auto; margin-bottom: 2rem; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .mono {{ font-family: 'Menlo', 'Consolas', monospace; font-size: 0.8rem; color: #7dd3fc; max-width: 350px; overflow: hidden; text-overflow: ellipsis; }}
  .rec-card {{ background: #1e293b; border-left: 4px solid #334155; border-radius: 0 0.75rem 0.75rem 0; padding: 0.85rem 1rem; margin-bottom: 0.6rem; }}
  .rec-priority {{ font-size: 0.65rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 0.25rem; }}
  .p-CRITICAL {{ background: #7f1d1d; color: #fca5a5; }}
  .p-HIGH {{ background: #7c2d12; color: #fdba74; }}
  .p-MEDIUM {{ background: #713f12; color: #fde68a; }}
  .p-LOW {{ background: #1e3a5f; color: #93c5fd; }}
  .rec-row {{ display: flex; align-items: flex-start; gap: 0.75rem; flex-wrap: wrap; }}
  .rec-text {{ flex: 1; }}
  .rec-issue {{ font-weight: 600; color: #e2e8f0; }}
  .rec-action {{ color: #94a3b8; font-size: 0.85rem; margin-top: 0.2rem; }}
  .count-chip {{ background: #334155; border-radius: 1rem; padding: 0.1rem 0.5rem; font-size: 0.75rem; color: #94a3b8; margin-left: auto; flex-shrink: 0; }}
  .toggle-all {{ background: #334155; border: none; color: #94a3b8; padding: 0.3rem 0.75rem; border-radius: 0.4rem; cursor: pointer; font-size: 0.8rem; margin-bottom: 0.75rem; }}
  .toggle-all:hover {{ background: #475569; color: #e2e8f0; }}
  .section-count {{ background: #334155; color: #94a3b8; padding: 0.1rem 0.5rem; border-radius: 1rem; font-size: 0.75rem; font-weight: 600; margin-left: 0.5rem; }}
  footer {{ border-top: 1px solid #1e293b; padding: 1.5rem 0; margin-top: 2rem; color: #475569; font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
<header>
  <div class="inner">
    <div>
      <h1>&#127775; Darta Report</h1>
      <div class="subtitle">Project: <strong>{project_name}</strong> &nbsp;|&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp; {len(files)} files analyzed{config_label}</div>
    </div>
    <div class="health-badge">
      <div class="score">{health}</div>
      <div class="label">Health Score</div>
    </div>
  </div>
</header>
<div class="container">
"""

        # KPIs
        html += '<div class="kpi-grid">\n'
        kpis = [
            ("Files", len(files)),
            ("Total LOC", sum(f.loc for f in files)),
            ("Classes", len(all_classes)),
            ("Avg CC", f"{avg_cc:.1f}"),
            ("Avg WMC", f"{avg_wmc:.1f}"),
            ("Arch Smells", len(smells_arch)),
            ("Design Smells", len(smells_design)),
            ("Impl Smells", len(smells_impl)),
            ("Waivers", len(applied_waivers or [])),
            ("Tech Debt", int(debt)),
        ]
        for label, val in kpis:
            html += f'  <div class="kpi"><div class="val">{val}</div><div class="lbl">{label}</div></div>\n'
        html += '</div>\n'

        # Recommendations
        if recs:
            html += '<h2>&#128270; Actionable Recommendations</h2>\n'
            for r in recs:
                html += f"""<div class="rec-card">
  <div class="rec-row">
    <span class="rec-priority p-{r['priority']}">{r['priority']}</span>
    <div class="rec-text">
      <div class="rec-issue">{r['issue']}</div>
      <div class="rec-action">{r['action']}</div>
    </div>
    <span class="count-chip">{r['affected_count']} issues</span>
  </div>
</div>\n"""

        # Architecture Smells
        html += f'<h2>&#127959; Architecture Smells <span class="section-count">{len(smells_arch)}</span></h2>\n'
        if smells_arch:
            html += '<button class="toggle-all" onclick="toggleSection(\'arch\')">Expand All</button>\n'
            for i, s in enumerate(smells_arch):
                label = s.component or s.file or "Project"
                html += self._smell_card(s, f"arch{i}", label=label)
        else:
            html += '<p style="color:#22c55e;padding:1rem 0;">&#10003; No architecture smells detected.</p>\n'

        # Design Smells
        html += f'<h2>&#127912; Design Smells <span class="section-count">{len(smells_design)}</span></h2>\n'
        if smells_design:
            html += '<button class="toggle-all" onclick="toggleSection(\'design\')">Expand All</button>\n'
            for i, s in enumerate(smells_design):
                html += self._smell_card(s, f"design{i}", label=f"{s.class_name} in {s.file}")
        else:
            html += '<p style="color:#22c55e;padding:1rem 0;">&#10003; No design smells detected.</p>\n'

        # Implementation Smells
        html += f'<h2>&#128736; Implementation Smells <span class="section-count">{len(smells_impl)}</span></h2>\n'
        if smells_impl:
            html += '<button class="toggle-all" onclick="toggleSection(\'impl\')">Expand All</button>\n'
            for i, s in enumerate(smells_impl):
                loc_str = f" (line {s.line})" if s.line else ""
                meta = f"{s.file}{loc_str}"
                if s.method_name:
                    meta = f"{s.method_name}() in {meta}"
                html += self._smell_card(s, f"impl{i}", label=meta)
        else:
            html += '<p style="color:#22c55e;padding:1rem 0;">&#10003; No implementation smells detected.</p>\n'

        if applied_waivers:
            html += f'<h2>Applied Waivers <span class="section-count">{len(applied_waivers)}</span></h2>\n'
            for waiver in applied_waivers:
                reason = waiver.get('reason') or 'No reason provided.'
                html += f"""<div class="rec-card">
  <div class="rec-row">
    <span class="rec-priority p-MEDIUM">WAIVER</span>
    <div class="rec-text">
      <div class="rec-issue">{waiver['from']} &rarr; {waiver['to']}</div>
      <div class="rec-action">{reason}</div>
    </div>
    <span class="count-chip">{waiver['rule']}</span>
  </div>
</div>\n"""

        # Components table
        html += '<h2>&#128193; Components</h2>\n'
        html += '<div class="tbl-wrap"><table>\n'
        html += '<tr><th>Component</th><th class="num">Files</th><th class="num">LOC</th><th class="num">Stability</th><th class="num">FAN-IN</th><th class="num">FAN-OUT</th></tr>\n'
        for ci in sorted(components.values(), key=lambda c: c.loc, reverse=True):
            html += f'<tr><td class="mono">{ci.name}</td><td class="num">{ci.file_count}</td><td class="num">{ci.loc}</td><td class="num">{ci.stability:.2f}</td><td class="num">{ci.fanin}</td><td class="num">{ci.fanout}</td></tr>\n'
        html += '</table></div>\n'

        # Files inventory
        html += '<h2>&#128196; Files Inventory</h2>\n'
        html += '<div class="tbl-wrap"><table>\n'
        html += '<tr><th>File</th><th class="num">LOC</th><th class="num">Classes</th><th class="num">FAN-IN</th><th class="num">FAN-OUT</th><th class="num">Avg CC</th></tr>\n'
        for fi in sorted(files, key=lambda f: f.loc, reverse=True):
            html += f'<tr><td class="mono">{fi.rel_path}</td><td class="num">{fi.loc}</td><td class="num">{len(fi.classes)}</td><td class="num">{fi.fanin}</td><td class="num">{fi.fanout}</td><td class="num">{fi.avg_cc:.2f}</td></tr>\n'
        html += '</table></div>\n'

        # Classes inventory
        html += '<h2>&#128215; Classes Inventory</h2>\n'
        html += '<div class="tbl-wrap"><table>\n'
        html += '<tr><th>Class</th><th>File</th><th class="num">LOC</th><th class="num">NOM</th><th class="num">WMC</th><th class="num">DIT</th><th class="num">NOF</th><th class="num">NOPF</th></tr>\n'
        for fi in files:
            for ci in fi.classes:
                dit = getattr(ci, 'dit', 0)
                html += f'<tr><td class="mono">{ci.name}</td><td class="mono">{fi.rel_path}</td><td class="num">{ci.loc}</td><td class="num">{ci.nom}</td><td class="num">{ci.wmc}</td><td class="num">{dit}</td><td class="num">{ci.nof}</td><td class="num">{ci.nopf}</td></tr>\n'
        html += '</table></div>\n'

        html += f"""<footer>Generated by <strong>Darta v1.0</strong> &mdash; Dart/Flutter Architecture Analyzer</footer>
</div>
<script>
function toggleSection(prefix) {{
  const bodies = document.querySelectorAll('[data-section="' + prefix + '"]');
  const allOpen = [...bodies].every(b => b.classList.contains('open'));
  bodies.forEach(b => b.classList.toggle('open', !allOpen));
}}
document.querySelectorAll('.smell-header').forEach(h => {{
  h.addEventListener('click', () => {{
    const body = h.nextElementSibling;
    if (body) body.classList.toggle('open');
  }});
}});
</script>
</body>
</html>"""
        return html

    def _smell_card(self, s: Smell, uid: str, label: str) -> str:
        color = self.SEVERITY_COLOR.get(s.severity, "#64748b")
        badge_label = self.SEVERITY_LABEL.get(s.severity, s.severity)
        prefix = uid.rstrip('0123456789')
        reasons_html = ''.join(f'<div class="reason">&#9679; {r}</div>' for r in s.reasons)
        return f"""<div class="smell-card">
  <div class="smell-header">
    <span class="badge" style="background:{color}33;color:{color};">{badge_label}</span>
    <span class="smell-name">{s.smell}</span>
    <span class="smell-meta">{label}</span>
  </div>
  <div class="smell-body" data-section="{prefix}">
    {reasons_html}
    <div class="suggestion">&#128161; {s.suggestion}</div>
  </div>
</div>\n"""


# ─────────────────────────────────────────────
# SECTION 10: Main Orchestration
# ─────────────────────────────────────────────

def walk_dart_files(lib_root: str, project_root: Optional[str] = None,
                    ignore_patterns: Optional[List[str]] = None) -> List[str]:
    """Recursively collect all .dart files under lib_root."""
    project_root = project_root or os.path.dirname(lib_root)
    ignore_patterns = ignore_patterns or []
    result = []
    for root, dirs, fnames in os.walk(lib_root):
        # Skip hidden dirs and common generated dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('generated', '.dart_tool')]
        for fn in fnames:
            if fn.endswith('.dart'):
                path = os.path.join(root, fn)
                project_rel = normalize_path(os.path.relpath(path, project_root))
                lib_rel = normalize_path(os.path.relpath(path, lib_root))
                if any(match_path_pattern(project_rel, pattern) for pattern in ignore_patterns):
                    continue
                if any(match_path_pattern(lib_rel, pattern) for pattern in ignore_patterns):
                    continue
                result.append(path)
    return sorted(result)


def find_lib_root(project_path: str) -> Optional[str]:
    """Find the lib/ directory inside the project."""
    lib = os.path.join(project_path, 'lib')
    if os.path.isdir(lib):
        return lib
    # Maybe the user passed lib/ directly
    if os.path.basename(project_path) == 'lib':
        return project_path
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Darta v1.0 — Dart/Flutter Architecture Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python darta.py\n  python darta.py --path ~/myapp --format json\n  python darta.py --component-depth 2 --format md --output stdout\n  python darta.py --config ~/myapp/darta.yaml"
    )
    parser.add_argument('--path', default='.', help='Path to Flutter/Dart project (default: current dir)')
    parser.add_argument('--format', choices=['html', 'json', 'md'], default='html', help='Output format')
    parser.add_argument('--output', default='file', help='"stdout" or a file path. Default: saves DARTA_REPORT.<ext>')
    parser.add_argument('--config', default=None, help='Path to darta.yaml. Default: auto-discover in project root')
    parser.add_argument(
        '--component-depth',
        type=int,
        default=None,
        help='Override component grouping depth under lib/. Default: auto (first dir, or first two for features/modules).'
    )
    args = parser.parse_args()

    input_path = os.path.abspath(args.path)
    lib_root = find_lib_root(input_path)
    if not lib_root:
        print(f"ERROR: No lib/ directory found in {input_path}", file=sys.stderr)
        sys.exit(1)

    project_root = input_path if os.path.basename(input_path) != 'lib' else os.path.dirname(lib_root)
    config = load_darta_config(project_root, args.config)
    component_depth = args.component_depth
    if component_depth is None and config:
        component_depth = config.component_depth

    if component_depth is not None and component_depth < 1:
        parser.error('--component-depth must be a positive integer')

    project_name = (config.project_name if config and config.project_name else os.path.basename(project_root))

    print(f"Darta v1.0 — Analyzing {project_name}", file=sys.stderr)
    if config:
        print(f"  Loaded config: {config.path}", file=sys.stderr)

    print(f"  Scanning {lib_root} ...", file=sys.stderr)
    dart_files = walk_dart_files(
        lib_root,
        project_root=project_root,
        ignore_patterns=(config.ignore_paths if config else None),
    )
    if not dart_files:
        print("ERROR: No .dart files found.", file=sys.stderr)
        sys.exit(1)
    print(f"  Found {len(dart_files)} Dart files.", file=sys.stderr)

    # Parse
    print("  Parsing files...", file=sys.stderr)
    dart_parser = DartParser(
        component_depth=component_depth,
        project_root=project_root,
        config=config,
    )
    files: List[FileInfo] = []
    for path in dart_files:
        fi = dart_parser.parse_file(path, lib_root)
        if fi:
            files.append(fi)
        print(f"    [{len(files)}/{len(dart_files)}] {os.path.relpath(path, lib_root)}", file=sys.stderr, end='\r')
    print(f"  Parsed {len(files)} files.                    ", file=sys.stderr)

    # Metrics
    print("  Computing metrics...", file=sys.stderr)
    mc = MetricsComputer(files, lib_root)
    mc.compute_all()
    components = mc.components

    # Smell detection
    print("  Detecting smells...", file=sys.stderr)
    detector = SmellDetector(files, components, mc.file_dependencies, config=config)
    detector.detect_all()

    print(f"  Architecture smells: {len(detector.architecture_smells)}", file=sys.stderr)
    print(f"  Design smells:       {len(detector.design_smells)}", file=sys.stderr)
    print(f"  Implementation smells: {len(detector.implementation_smells)}", file=sys.stderr)

    # Generate report
    print("  Generating report...", file=sys.stderr)
    if args.format == 'json':
        reporter = JSONReporter()
        content = reporter.generate(files, components, detector.architecture_smells,
                                    detector.design_smells, detector.implementation_smells, project_name,
                                    config_path=(config.path if config else None),
                                    applied_waivers=detector.applied_waivers)
        ext = 'json'
    elif args.format == 'md':
        reporter = MarkdownReporter()
        content = reporter.generate(files, components, detector.architecture_smells,
                                    detector.design_smells, detector.implementation_smells, project_name,
                                    config_path=(config.path if config else None),
                                    applied_waivers=detector.applied_waivers)
        ext = 'md'
    else:
        reporter = HTMLReporter()
        content = reporter.generate(files, components, detector.architecture_smells,
                                    detector.design_smells, detector.implementation_smells, project_name,
                                    config_path=(config.path if config else None),
                                    applied_waivers=detector.applied_waivers)
        ext = 'html'

    # Output
    if args.output == 'stdout':
        sys.stdout.write(content)
    else:
        if args.output == 'file':
            out_path = os.path.join(project_root, f"DARTA_REPORT.{ext}")
        else:
            out_path = args.output
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"\nReport saved to: {out_path}", file=sys.stderr)

    health, debt = compute_health(detector.architecture_smells, detector.design_smells,
                                  detector.implementation_smells)
    print(f"Health Score: {health}/100  (Technical Debt: {debt})", file=sys.stderr)


if __name__ == '__main__':
    main()
