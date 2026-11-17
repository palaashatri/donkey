"""Unit tests for the counting rules of import_calls.py (run by CTest as tools.import_calls)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from import_calls import Image, Tally, site_kind  # noqa: E402


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



# One image: .plt at [0x1000, 0x1100); 0x1010 is puts@plt (an import), 0x1020 is free@plt (a stub of
# a function the image defines itself, as libc's interposable free is).
IMAGE = Image(stubs=[(0x1000, 0x1100)], gots=[], names={0x1010: "puts", 0x1020: "free"}, slots={},
              import_names={"puts"}, local_stub_names={"free"})


def counted(pseudocode, status="Partial"):
    tally = Tally()
    tally.add_function({"pseudocode": pseudocode, "status": status}, IMAGE)
    return tally.result()


class Measure(unittest.TestCase):
    def test_an_image_defined_stub_printed_as_sub_is_counted_apart(self):
        result = counted("u64 sub_2000(void) {\n  sub_1020(rdi);\n  return rax;\n}")
        counts = result["counts"]
        self.assertEqual(counts["stub_call_sites"], 1)
        self.assertEqual(counts["local_stub_call_sites_printed_as_sub"], 1)
        self.assertNotIn("functions_with_a_stub_call", counts)
        self.assertEqual(result["stub_call_sites_by_import"], [])
        self.assertEqual(result["functions_by_import"], [])

    def test_an_import_stub_printed_as_sub_counts_as_an_import(self):
        result = counted("u64 sub_2000(void) {\n  sub_1010(rdi);\n  return rax;\n}")
        self.assertEqual(result["stub_call_sites_by_import"], [("puts", 1)])
        self.assertEqual(result["functions_by_import"], [("puts", 1)])
        self.assertNotIn("local_stub_call_sites_printed_as_sub", result["counts"])

    def test_a_call_inside_a_string_or_a_comment_is_not_counted(self):
        result = counted('u64 sub_2000(void) {\n  rax = (u64)("puts(");  // abort();\n'
                         '  return rax;\n}')
        counts = result["counts"]
        self.assertNotIn("import_call_sites_printed_by_name", counts)
        self.assertNotIn("named_no_return_call_sites", counts)
        result = counted('u64 sub_2000(void) {\n  puts("abort(");\n  return rax;\n}')
        self.assertEqual(result["counts"]["import_call_sites_printed_by_name"], 1)
        self.assertNotIn("named_no_return_call_sites", result["counts"])

    def test_calls_printed_by_name_are_split_the_same_way(self):
        result = counted("u64 sub_2000(void) {\n  puts(rdi);\n  free(rdi);\n  return rax;\n}")
        counts = result["counts"]
        self.assertEqual(counts["import_call_sites_printed_by_name"], 1)
        self.assertEqual(counts["local_stub_call_sites_printed_by_name"], 1)
        self.assertEqual(result["functions_by_import"], [("puts", 1)])


if __name__ == "__main__":
    unittest.main()
