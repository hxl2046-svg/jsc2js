"""Source-text checks for the 15.2.124.28 index diagnostic.

These tests do not compile d8, deserialize a V8 code cache, or identify which
vector the unavailable Windows sample indexed.
"""

from pathlib import Path
import unittest

from patches.modern.diagnose_reference_index import (
    MARKER,
    REQUIRED_VERSION,
    DiagnosticError,
    read_v8_version,
    transform_deserializer,
)


ROOT = Path(__file__).resolve().parents[1]

# Lines copied from v8/v8 tag 15.2.124.28 src/snapshot/deserializer.cc.
# They are the edit anchors, not a cache and not a stack trace.
_FIXTURE = """\
#include <inttypes.h>

void sample() {
  Handle<HeapObject> obj = back_refs_[index];
  ReadOnlyPage* page = read_only_space->pages()[chunk_index];
  DirectHandle<HeapObject> heap_object = attached_objects_[index];
  auto& forward_ref = unresolved_forward_refs_[index];
  JSDispatchHandle handle = js_dispatch_entries_[entry_id];
  return table->address(reference_id);
}
"""

_VERSION_15_2_124_28 = """\
#define V8_MAJOR_VERSION 15
#define V8_MINOR_VERSION 2
#define V8_BUILD_NUMBER 124
#define V8_PATCH_LEVEL 28
"""


class ReferenceIndexDiagnosticTest(unittest.TestCase):
    def test_version_gate_accepts_only_the_exact_tag(self):
        self.assertEqual(read_v8_version(_VERSION_15_2_124_28), REQUIRED_VERSION)
        other = _VERSION_15_2_124_28.replace("V8_PATCH_LEVEL 28", "V8_PATCH_LEVEL 5")
        self.assertEqual(read_v8_version(other), "15.2.124.5")
        self.assertNotEqual(read_v8_version(other), REQUIRED_VERSION)

    def test_inserts_a_flushed_log_and_keeps_the_original_index(self):
        patched = transform_deserializer(_FIXTURE)
        self.assertIn(MARKER, patched)
        self.assertEqual(patched.count("fflush(stderr);"), 5)
        for original in (
            "Handle<HeapObject> obj = back_refs_[index];",
            "ReadOnlyPage* page = read_only_space->pages()[chunk_index];",
            "DirectHandle<HeapObject> heap_object = attached_objects_[index];",
            "auto& forward_ref = unresolved_forward_refs_[index];",
            "JSDispatchHandle handle = js_dispatch_entries_[entry_id];",
            "return table->address(reference_id);",
        ):
            self.assertEqual(patched.count(original), 1)
        self.assertLess(
            patched.index("out-of-range read-only-heap-page"),
            patched.index("read_only_space->pages()[chunk_index]"),
        )
        self.assertNotIn("_LIBCPP_HARDENING_MODE", patched)
        self.assertNotIn("ExitProcess", patched)
        self.assertNotIn("disassembly produced", patched)
        self.assertEqual(transform_deserializer(patched), patched)

    def test_refuses_a_deserializer_that_does_not_match_the_tag(self):
        with self.assertRaises(DiagnosticError):
            transform_deserializer("#include <inttypes.h>\n")

    def test_production_patcher_and_builder_do_not_apply_this_diagnostic(self):
        modern = (ROOT / "patches/modern/apply_modern_patch.py").read_text(
            encoding="utf-8"
        )
        builder = (ROOT / "build_versions_batch_v3.py").read_text(encoding="utf-8")
        self.assertIn('"deserializer_modified": False', modern)
        self.assertNotIn("diagnose_reference_index", modern)
        self.assertNotIn("diagnose_reference_index", builder)
        self.assertNotIn(MARKER, modern)


if __name__ == "__main__":
    unittest.main()
