# Darta v1.0 — Dart/Flutter Architecture Analyzer

A single-file Python 3.7+ static analysis tool for Dart/Flutter projects.
Produces rich HTML, JSON, or Markdown reports covering implementation,
design, and architecture smells — with no Dart toolchain required.
Optionally reads `darta.yaml` to enforce project-specific architectural rules.

---

## Installation

```bash
cd /path/to/Darta
bash install.sh
```

This creates a symlink at `/usr/local/bin/darta` so you can run `darta` from anywhere.

---

## Usage

```
python darta.py [--path <dir>] [--format json|html|md] [--output file|stdout] [--component-depth N] [--config path/to/darta.yaml]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | `.` (current dir) | Path to Flutter/Dart project root |
| `--format` | `html` | Output format: `html`, `json`, or `md` |
| `--output` | `file` | `file` saves `DARTA_REPORT.<ext>` in project root; `stdout` prints to terminal; or provide an explicit file path |
| `--config` | auto | Path to `darta.yaml`; if omitted, Darta auto-discovers `darta.yaml` / `darta.yml` in the project root |
| `--component-depth` | `auto` | Override how many directory levels under `lib/` define a component |

### Examples

```bash
# Analyze current directory, save DARTA_REPORT.html
darta

# Analyze a specific project
darta --path ~/projects/my_flutter_app

# JSON output to stdout (pipe-friendly)
darta --path ~/projects/my_flutter_app --format json --output stdout

# Markdown report saved to a custom path
darta --path ~/projects/my_flutter_app --format md --output ~/reports/report.md

# Force component grouping to two levels under lib/
darta --path ~/projects/my_flutter_app --component-depth 2

# Run with an explicit architecture contract
darta --path ~/projects/my_flutter_app --config ~/projects/my_flutter_app/darta.yaml

# HTML report for CI (write to stdout, redirect to file)
darta --format html --output stdout > report.html
```

---

## What It Analyzes

Darta walks the `lib/` directory and parses every `.dart` file using regex patterns.
If a `darta.yaml` is present, Darta also applies the project contract on top of the inferred smells.

### Metrics (per class and file)

| Metric | Description |
|--------|-------------|
| LOC | Non-blank, non-comment lines |
| CC | Cyclomatic complexity |
| PC | Parameter count per method |
| NOF | Number of fields |
| NOPF | Number of public fields |
| NOM | Number of methods |
| NOPM | Number of public methods |
| WMC | Weighted Method Count (sum of CC) |
| DIT | Depth of Inheritance Tree |
| FANIN | Files that import this file |
| FANOUT | Files this file references via import/export/part (internal only) |

### Smells Detected

**Implementation smells** (per method/file):
- Long Method (> 30 lines)
- Complex Method (CC > 10)
- Long Parameter List (> 4 params)
- Long Statement (line > 120 chars)
- Long Identifier (name > 30 chars)
- Magic Number (numeric literals > 2 not in const/final)
- Empty Catch Clause
- Missing Default (switch without default)
- Long Message Chain (> 3 chained calls)

**Design smells** (per class):
- God Class
- Insufficient Modularization
- Deficient Encapsulation
- Hub-like Modularization
- Multifaceted Abstraction

**Architecture smells** (per inferred component under `lib/`):
- God Component
- Dense Structure
- Unstable Dependency
- Feature Concentration
- Dependency Rule Violation (`darta.yaml`)
- Forbidden Package Dependency (`darta.yaml`)
- File Rule Violation (`darta.yaml`)
- File / Component / Layer Cycle (`darta.yaml`)
- Component / File Budget Exceeded (`darta.yaml`)

### Health Score

```
Technical Debt Score =
  God Class × 50 + God Component × 100 + Unstable Dependency × 80 +
  Dense Structure × 40 + Feature Concentration × 35 +
  Dependency Rule Violation × 90 + Forbidden Package Dependency × 85 +
  File Rule Violation × 70 + File Cycle × 90 + Component Cycle × 120 +
  Layer Cycle × 140 + Component Fanout Budget × 30 +
  Component Size Budget × 25 + File Size Budget × 10 +
  Hub-like × 60 + Insufficient Mod × 30 + Deficient Encap × 20 +
  Long Method × 5 + Complex Method × 10 + Magic Number × 2

Health Score = max(0, 100 - TechnicalDebt / 10)
```

- **Green (≥ 80):** Healthy codebase
- **Yellow (60–79):** Moderate issues
- **Red (< 60):** Significant refactoring needed

---

## Output Formats

### HTML (default)
Dark-theme single-file report with:
- Health score badge
- KPI cards
- Collapsible smell cards with severity badges
- Components and files inventory tables
- Actionable recommendations

No external CDN dependencies — fully self-contained.

### JSON
Machine-readable output following the schema:
```json
{
  "meta": { ... },
  "summary_kpis": { ... },
  "code_health": { ... },
  "architecture_smells": [ ... ],
  "design_smells": [ ... ],
  "implementation_smells": [ ... ],
  "components": [ ... ],
  "files_inventory": [ ... ],
  "classes_inventory": [ ... ],
  "actionable_recommendations": [ ... ]
}
```

### Markdown
Human-readable report suitable for GitHub issues, Confluence, or Notion.

---

## Requirements

- Python 3.7+
- Base analyzer uses only stdlib
- Optional: `PyYAML` for `darta.yaml` support (`pip install pyyaml`)

---

## How Components Are Defined

A **component** is inferred from directories under `lib/`:
- `lib/core/foo.dart` → component `core`
- `lib/features/auth/login.dart` → component `features/auth` (auto mode)
- `lib/main.dart` → component `root`

By default Darta uses:
- the first directory under `lib/`
- the first two directories for aggregate folders like `features/*` and `modules/*`

If your project uses a different convention, pass `--component-depth N`.
If your project ships a `darta.yaml` with explicit `components`, those mappings override inferred grouping.

Component **stability** = Ce / (Ca + Ce), where:
- Ce = efferent coupling (cross-component dependencies made)
- Ca = afferent coupling (cross-component dependencies received)

A stability of 1.0 means fully instable (all dependencies go outward).
A stability of 0.0 means fully stable (only depended upon, never depends outward).

---

## Limitations

Since Darta uses regex (not a full Dart AST parser):
- Deeply nested or unusual formatting may cause missed or incorrect detections
- Generic type parameters in complex positions may not parse perfectly
- Macro-generated or heavily annotated code may show false positives
- `export` and `part` links are counted as internal dependencies
- `part of` relations still rely on best-effort matching rather than full library resolution

For most real-world Flutter projects the accuracy is sufficient for architectural analysis.

---

## `darta.yaml` Support

Darta can enforce a project-specific architecture contract via `darta.yaml`.

Currently supported config areas:
- `analysis.component_depth`
- `analysis.ignore_paths`
- `components` (explicit file-to-component mapping)
- `layers`
- `architecture.dependency_rules`
- `architecture.forbidden_packages`
- `architecture.file_rules`
- `architecture.cycles`
- `architecture.budgets`
- `architecture.waivers`
- `smells.implementation.*` tuning for long methods, statements, identifiers, and magic numbers

When config rules are active, Darta includes:
- config path in the report metadata
- applied waivers in JSON / Markdown / HTML reports
- config-driven violations in health score and recommendations
