"""Keep the unittest discovery boundary executable and observable."""

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
TOOLS_TESTS = ROOT / 'tools/tests'


def _is_test_case_base(node):
    return ast.unparse(node) in {'TestCase', 'unittest.TestCase'}


class ToolsTestDiscoveryTests(unittest.TestCase):
    def test_tool_test_modules_have_no_pytest_only_top_level_tests(self):
        top_level_tests = []
        test_case_classes = []
        for path in sorted(TOOLS_TESTS.glob('test_*.py')):
            module = ast.parse(path.read_text(), filename=str(path))
            top_level_tests.extend(
                f'{path.relative_to(ROOT)}:{node.lineno}'
                for node in module.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
            )
            test_case_classes.extend(
                f'{path.relative_to(ROOT)}:{node.name}'
                for node in module.body
                if isinstance(node, ast.ClassDef) and any(_is_test_case_base(base) for base in node.bases)
            )

        self.assertFalse(top_level_tests, f'top-level test functions bypass unittest discovery: {top_level_tests}')
        self.assertTrue(test_case_classes, 'tools/tests has no unittest.TestCase subclasses')

    def test_script_self_tests_are_covered_by_lint_workflow(self):
        workflow = (ROOT / '.github/workflows/lint.yml').read_text()
        scripts = sorted((ROOT / 'scripts').glob('test_*.py'))
        self.assertTrue(scripts, 'expected at least one script self-test')
        for script in scripts:
            relative = script.relative_to(ROOT).as_posix()
            with self.subTest(script=relative):
                self.assertIn(f'python {relative}', workflow)


if __name__ == '__main__':
    unittest.main()
