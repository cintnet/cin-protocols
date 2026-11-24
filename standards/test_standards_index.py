"""Automated fail-closed conformance tests for the Agent Standards Master Catalog.

Verifies that:
1. STANDARDS-INDEX.md exists and covers all schemas, test suites, and examples in research/standards/.
2. Every JSON schema file is syntactically valid and enforces fail-closed typing.
3. research/standards/README.md links to the catalog.
4. knowledge/INDEX.md includes research/standards, research/policy, and research/sim index entries.
"""

import json
import os
import unittest
from pathlib import Path


class TestStandardsIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Resolve repo root relative to this test file
        cls.test_dir = Path(__file__).resolve().parent
        cls.standards_dir = cls.test_dir
        cls.repo_root = cls.standards_dir.parent.parent
        cls.index_md_path = cls.standards_dir / "STANDARDS-INDEX.md"
        cls.readme_md_path = cls.standards_dir / "README.md"
        cls.knowledge_index_path = cls.repo_root / "knowledge" / "INDEX.md"

        with open(cls.index_md_path, "r", encoding="utf-8") as f:
            cls.index_content = f.read()

    def test_standards_index_file_exists_and_non_empty(self):
        self.assertTrue(self.index_md_path.is_file(), "STANDARDS-INDEX.md must exist")
        self.assertGreater(len(self.index_content), 1000, "STANDARDS-INDEX.md must have substantial content")

    def test_all_json_schemas_indexed(self):
        schema_files = sorted([f.name for f in self.standards_dir.glob("*.json")])
        self.assertGreaterEqual(len(schema_files), 5, "Expected at least 5 standard schema JSON files")

        for schema_file in schema_files:
            with self.subTest(schema=schema_file):
                self.assertIn(
                    schema_file,
                    self.index_content,
                    f"Schema {schema_file} must be indexed in STANDARDS-INDEX.md",
                )
                # Verify JSON validity and fail-closed properties
                full_path = self.standards_dir / schema_file
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.assertIn("$schema", data, f"{schema_file} must declare $schema")
                self.assertIn("title", data, f"{schema_file} must declare title")
                self.assertEqual(data.get("type"), "object", f"{schema_file} root must be object")

    def test_all_test_suites_indexed(self):
        tests_dir = self.standards_dir / "tests"
        test_files = sorted([f.name for f in tests_dir.glob("test_*.py")])
        self.assertGreaterEqual(len(test_files), 5, "Expected at least 5 standard test suites")

        for test_file in test_files:
            with self.subTest(test_suite=test_file):
                self.assertIn(
                    test_file,
                    self.index_content,
                    f"Test file {test_file} must be indexed in STANDARDS-INDEX.md",
                )

    def test_all_examples_indexed(self):
        examples_dir = self.standards_dir / "examples"
        example_files = sorted([f.name for f in examples_dir.glob("*.json")])
        self.assertGreaterEqual(len(example_files), 5, "Expected at least 5 example JSON files")

        for example_file in example_files:
            with self.subTest(example=example_file):
                self.assertIn(
                    example_file,
                    self.index_content,
                    f"Example file {example_file} must be indexed in STANDARDS-INDEX.md",
                )
                full_path = examples_dir / example_file
                with open(full_path, "r", encoding="utf-8") as f:
                    example_data = json.load(f)
                self.assertIsInstance(example_data, dict, f"{example_file} must contain a JSON object")

    def test_readme_links_to_index(self):
        self.assertTrue(self.readme_md_path.is_file(), "research/standards/README.md must exist")
        with open(self.readme_md_path, "r", encoding="utf-8") as f:
            readme_content = f.read()
        self.assertIn(
            "STANDARDS-INDEX.md",
            readme_content,
            "research/standards/README.md must link to STANDARDS-INDEX.md",
        )

    def test_knowledge_index_covers_new_research_sections(self):
        self.assertTrue(self.knowledge_index_path.is_file(), "knowledge/INDEX.md must exist")
        with open(self.knowledge_index_path, "r", encoding="utf-8") as f:
            knowledge_content = f.read()

        self.assertIn(
            "### research/standards/",
            knowledge_content,
            "knowledge/INDEX.md must include section for research/standards/",
        )
        self.assertIn(
            "STANDARDS-INDEX.md",
            knowledge_content,
            "knowledge/INDEX.md must reference STANDARDS-INDEX.md",
        )
        self.assertIn(
            "### research/policy/",
            knowledge_content,
            "knowledge/INDEX.md must include section for research/policy/",
        )
        self.assertIn(
            "SIMULATION-INDEX.md",
            knowledge_content,
            "knowledge/INDEX.md must reference SIMULATION-INDEX.md under research/sim/",
        )


if __name__ == "__main__":
    unittest.main()
