"""Unit tests for the counting rules of import_calls.py (run by CTest as tools.import_calls)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from import_calls import site_kind  # noqa: E402


class SiteKind(unittest.TestCase):
    IMPORTS = {"puts", "abort"}
    LOCAL = {"free"}

    def test_an_undefined_symbol_is_an_import(self):
        self.assertEqual(site_kind("puts", self.IMPORTS, self.LOCAL), "import")

    def test_an_image_defined_stub_target_is_not_an_import(self):
        # libc's free@plt: a stub, printed as sub_<hex> or by name, of a function libc defines.
        self.assertEqual(site_kind("free", self.IMPORTS, self.LOCAL), "local")

    def test_any_other_name_is_not_counted(self):
        self.assertIsNone(site_kind("main", self.IMPORTS, self.LOCAL))


if __name__ == "__main__":
    unittest.main()
