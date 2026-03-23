import tempfile
import unittest
from pathlib import Path

from darta import DartParser, SmellDetector


class DartaParserTests(unittest.TestCase):
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
    final count = 5;
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
            self.assertEqual(smell.line, 8)


if __name__ == '__main__':
    unittest.main()
