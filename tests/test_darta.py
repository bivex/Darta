import tempfile
import unittest
from pathlib import Path

from darta import DartParser, MetricsComputer, SmellDetector, load_darta_config


class DartaParserTests(unittest.TestCase):
    def _analyze_project(self, project_root: Path):
        config = load_darta_config(str(project_root))
        lib_root = project_root / 'lib'
        parser = DartParser(
            component_depth=(config.component_depth if config else None),
            project_root=str(project_root),
            config=config,
        )
        files = []
        for path in sorted(lib_root.rglob('*.dart')):
            fi = parser.parse_file(str(path), str(lib_root))
            if fi:
                files.append(fi)

        metrics = MetricsComputer(files, str(lib_root))
        metrics.compute_all()
        detector = SmellDetector(files, metrics.components, metrics.file_dependencies, config=config)
        detector.detect_all()
        return config, files, metrics, detector

    def test_parse_file_preserves_import_literals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lib_root = Path(tmpdir) / 'lib'
            lib_root.mkdir(parents=True, exist_ok=True)
            (lib_root / 'main.dart').write_text(
                "import 'foo.dart';\nvoid main() {}\n",
                encoding='utf-8',
            )
            (lib_root / 'foo.dart').write_text(
                "class Foo {}\n",
                encoding='utf-8',
            )

            fi = DartParser().parse_file(str(lib_root / 'main.dart'), str(lib_root))

            self.assertEqual(fi.imports, ['foo.dart'])

    def test_magic_numbers_ignore_numbers_inside_string_literals(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            lib_root = Path(tmpdir) / 'lib'
            lib_root.mkdir(parents=True, exist_ok=True)
            source = """class Demo {
  void log() {
    final message = "version 42";
    final multiline = '''
Room 101
Version 9000
''';
    const ignored = 7;
    var count = 5;
    // 999
  }
}
"""
            file_path = lib_root / 'demo.dart'
            file_path.write_text(source, encoding='utf-8')

            fi = DartParser().parse_file(str(file_path), str(lib_root))
            detector = SmellDetector([fi], {})
            detector._check_magic_numbers(fi)

            self.assertEqual(len(detector.implementation_smells), 1)
            smell = detector.implementation_smells[0]
            self.assertEqual(smell.smell, 'Magic Number')
            expected_line = source.splitlines().index('    var count = 5;') + 1
            self.assertEqual(smell.line, expected_line)

    def test_darta_yaml_applies_explicit_components_dependency_rules_and_waivers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            lib_root = project_root / 'lib'
            (lib_root / 'core').mkdir(parents=True, exist_ok=True)
            (lib_root / 'ads').mkdir(parents=True, exist_ok=True)
            (lib_root / 'ui').mkdir(parents=True, exist_ok=True)

            (project_root / 'darta.yaml').write_text(
                """project:
  name: fixture
analysis:
  component_mode: explicit
components:
  core:
    include:
      - lib/core/**
  ads:
    include:
      - lib/ads/**
  ui:
    include:
      - lib/ui/**
architecture:
  dependency_rules:
    - from: core
      allow: []
    - from: ads
      allow: []
    - from: ui
      allow: []
  waivers:
    - rule: dependency_rules
      from: lib/core/session_manager.dart
      to: lib/ads/ad_manager.dart
""",
                encoding='utf-8',
            )
            (lib_root / 'core' / 'session_manager.dart').write_text(
                "import '../ads/ad_manager.dart';\n"
                "import '../ui/widget.dart';\n"
                "class SessionManager {}\n",
                encoding='utf-8',
            )
            (lib_root / 'ads' / 'ad_manager.dart').write_text(
                "class AdManager {}\n",
                encoding='utf-8',
            )
            (lib_root / 'ui' / 'widget.dart').write_text(
                "class WidgetView {}\n",
                encoding='utf-8',
            )

            _, files, _, detector = self._analyze_project(project_root)

            components = {fi.project_rel_path: fi.component for fi in files}
            self.assertEqual(components['lib/core/session_manager.dart'], 'core')
            self.assertEqual(components['lib/ui/widget.dart'], 'ui')

            dependency_violations = [
                smell for smell in detector.architecture_smells
                if smell.smell == 'Dependency Rule Violation'
            ]
            self.assertEqual(len(dependency_violations), 1)
            self.assertIn('lib/ui/widget.dart', dependency_violations[0].reasons[1])
            self.assertEqual(len(detector.applied_waivers), 1)
            self.assertEqual(detector.applied_waivers[0]['to'], 'lib/ads/ad_manager.dart')

    def test_darta_yaml_tunes_magic_numbers_and_forbidden_packages(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            lib_root = project_root / 'lib'
            (lib_root / 'core').mkdir(parents=True, exist_ok=True)

            (project_root / 'darta.yaml').write_text(
                """analysis:
  component_mode: explicit
components:
  core:
    include:
      - lib/core/**
architecture:
  forbidden_packages:
    - from:
        - core
      packages:
        - package:flutter/material.dart
      reason: core must stay UI free
smells:
  implementation:
    magic_number:
      ignore_in_strings: true
      ignore_const_final: true
      ignore_common_ui_values:
        - 8
""",
                encoding='utf-8',
            )
            (lib_root / 'core' / 'theme_bridge.dart').write_text(
                "import 'package:flutter/material.dart';\n"
                "class ThemeBridge {\n"
                "  void build() {\n"
                "    var padding = 8;\n"
                "    var count = 9;\n"
                "  }\n"
                "}\n",
                encoding='utf-8',
            )

            _, _, _, detector = self._analyze_project(project_root)

            arch_smells = [smell.smell for smell in detector.architecture_smells]
            self.assertIn('Forbidden Package Dependency', arch_smells)

            magic_numbers = [
                smell for smell in detector.implementation_smells
                if smell.smell == 'Magic Number'
            ]
            self.assertEqual(len(magic_numbers), 1)
            self.assertIn('literal 9', magic_numbers[0].reasons[0])

    def test_darta_yaml_detects_file_cycles(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            project_root = Path(tmpdir)
            lib_root = project_root / 'lib'
            (lib_root / 'core').mkdir(parents=True, exist_ok=True)

            (project_root / 'darta.yaml').write_text(
                """analysis:
  component_mode: explicit
components:
  core:
    include:
      - lib/core/**
architecture:
  cycles:
    files: error
""",
                encoding='utf-8',
            )
            (lib_root / 'core' / 'a.dart').write_text(
                "import 'b.dart';\nclass A {}\n",
                encoding='utf-8',
            )
            (lib_root / 'core' / 'b.dart').write_text(
                "import 'a.dart';\nclass B {}\n",
                encoding='utf-8',
            )

            _, _, _, detector = self._analyze_project(project_root)

            cycle_smells = [
                smell for smell in detector.architecture_smells
                if smell.smell == 'File Cycle'
            ]
            self.assertEqual(len(cycle_smells), 1)
            self.assertIn('lib/core/a.dart', cycle_smells[0].reasons[0])
            self.assertIn('lib/core/b.dart', cycle_smells[0].reasons[0])


if __name__ == '__main__':
    unittest.main()
