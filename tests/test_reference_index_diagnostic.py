"""Checks for the 15.2.124.28 index diagnostic.

The clang++ step compiles the generated statements. It does not compile
deserializer.cc, link d8, or deserialize a code cache.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import build_versions_batch_v3 as builder
from patches.modern.diagnose_reference_index import (
    MARKER,
    REQUIRED_VERSION,
    _SITES,
    _prelude,
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

    def test_shared_modern_patcher_stays_unchanged(self):
        modern = (ROOT / "patches/modern/apply_modern_patch.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"deserializer_modified": False', modern)
        self.assertNotIn("diagnose_reference_index", modern)
        self.assertNotIn(MARKER, modern)

    def test_builder_limits_the_diagnostic_and_icu_requirement_to_one_tag(self):
        workflow = (ROOT / ".github/workflows/compile.yml").read_text(encoding="utf-8")
        self.assertIn("windows_only:", workflow)
        self.assertIn('["ubuntu-22.04", "windows-2022"]', workflow)
        self.assertIn('["windows-2022"]', workflow)
        self.assertIsNone(builder.reference_index_diagnostic_command("15.2.124.5"))
        command = builder.reference_index_diagnostic_command(REQUIRED_VERSION)
        self.assertIsNotNone(command)
        self.assertTrue(Path(command[1]).is_file())
        self.assertEqual(command[2:], ["--root", "."])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "out"
            stage = root / "stage"
            out.mkdir()
            stage.mkdir()
            (out / "icudtl.dat").write_bytes(b"icu")
            self.assertTrue(builder.copy_icu_data(out, stage, "14.8.178.38"))
            self.assertEqual((stage / "icudtl.dat").read_bytes(), b"icu")
            self.assertFalse(
                builder.copy_icu_data(root / "missing", stage, "14.8.178.38")
            )
            with self.assertRaises(RuntimeError):
                builder.copy_icu_data(root / "missing", stage, REQUIRED_VERSION)

    def test_generated_statements_compile_and_fall_through(self):
        compiler = shutil.which("clang++")
        if compiler is None:
            self.fail("clang++ is not available; the statements were not compiled")
        source = _compiled_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cpp = root / "diagnostic_statements.cc"
            binary = root / "diagnostic_statements"
            cpp.write_text(source, encoding="utf-8")
            obj = root / "diagnostic_statements.o"
            # This VM's clang++ does not search the installed libstdc++ headers
            # or its linker path. g++ only links. -Wno-sign-conversion matches
            # V8: prevent_unsafe_narrowing is opt-in, and two original sites
            # already pass an int to operator[].
            compiled = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wsign-compare",
                    "-Wno-sign-conversion",
                    "-Wno-unused-variable",
                    "-Wformat=2",
                    "-Wformat-security",
                    "-I/usr/include/c++/13",
                    "-I/usr/include/x86_64-linux-gnu/c++/13",
                    "-c",
                    str(cpp),
                    "-o",
                    str(obj),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                compiled.returncode,
                0,
                compiled.stderr,
            )
            linked = subprocess.run(
                ["g++", "-std=c++20", str(obj), "-o", str(binary)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(linked.returncode, 0, linked.stderr)
            in_range = subprocess.run(
                [str(binary), "in-range"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(in_range.returncode, 0, in_range.stderr)
            self.assertEqual(in_range.stderr, "")
            self.assertIn("in-range-ok", in_range.stdout)
            out_of_range = subprocess.run(
                [str(binary), "out-of-range"],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(out_of_range.returncode, 0, out_of_range.stderr)
            for kind in (
                "back-reference",
                "read-only-heap-page",
                "attached-object",
                "unresolved-forward-ref",
                "js-dispatch-entry",
            ):
                self.assertIn(
                    f"[jsc2js-diag] out-of-range {kind} index=4 size=2",
                    out_of_range.stderr,
                )
            self.assertIn("out-of-range-reached-index", out_of_range.stdout)
            prelude = root / "preludes.cc"
            prelude.write_text(_prelude_only_fixture(), encoding="utf-8")
            prelude_cc = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wsign-compare",
                    "-Wsign-conversion",
                    "-Wformat=2",
                    "-Wformat-security",
                    "-I/usr/include/c++/13",
                    "-I/usr/include/x86_64-linux-gnu/c++/13",
                    "-c",
                    str(prelude),
                    "-o",
                    str(root / "preludes.o"),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(prelude_cc.returncode, 0, prelude_cc.stderr)


def _prelude_only_fixture() -> str:
    """The inserted checks alone, under -Wsign-conversion."""
    checks = []
    for site in _SITES:
        checks.append(_prelude(site["kind"], site["index"], site["size"]))
    return (
        "#include <stdio.h>\n"
        "#include <stddef.h>\n"
        "#include <stdint.h>\n"
        "struct Vec { size_t n = 0; size_t size() const { return n; } };\n"
        "struct Pages { Vec storage; const Vec& pages() const { return storage; } };\n"
        "void checks(Vec& back_refs_, Vec& attached_objects_,\n"
        "            Vec& unresolved_forward_refs_, Vec& js_dispatch_entries_,\n"
        "            Pages* read_only_space, int index, uint32_t chunk_index,\n"
        "            uint32_t entry_id) {\n"
        + "".join(checks)
        + "}\n"
    )


def _compiled_fixture() -> str:
    """Compile the generated prelude plus each original index expression.

    The containers are std::vector stand-ins with the same operations the
    patch calls. They count operator[] instead of aborting, so the
    out-of-range path can show that the original index still runs. This is
    not deserializer.cc and not d8.
    """
    bodies = []
    for site in _SITES:
        bodies.append(
            "  {\n"
            f"{_prelude(site['kind'], site['index'], site['size'])}"
            f"{site['old']}"
            "    ++indexes_reached;\n"
            "  }\n"
        )
    return r'''#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

struct HeapObject {};
template <typename T>
struct Handle { T* ptr = nullptr; };
template <typename T>
struct DirectHandle { T* ptr = nullptr; };
struct ReadOnlyPage {};
struct JSDispatchHandle { int value = 0; };
struct ForwardRef { int value = 0; };

template <typename T>
struct CountingVector {
  mutable std::vector<T> items;
  mutable int indexes = 0;
  size_t size() const { return items.size(); }
  T& operator[](size_t i) const {
    ++indexes;
    return items[i < items.size() ? i : 0];
  }
};

struct ReadOnlySpace {
  CountingVector<ReadOnlyPage*> storage;
  const CountingVector<ReadOnlyPage*>& pages() const { return storage; }
};

static int exercise(size_t n, uint32_t index_value) {
  int indexes_reached = 0;
  CountingVector<Handle<HeapObject>> back_refs_;
  CountingVector<DirectHandle<HeapObject>> attached_objects_;
  CountingVector<ForwardRef> unresolved_forward_refs_;
  CountingVector<JSDispatchHandle> js_dispatch_entries_;
  ReadOnlySpace space;
  ReadOnlySpace* read_only_space = &space;
  back_refs_.items.resize(n);
  attached_objects_.items.resize(n);
  unresolved_forward_refs_.items.resize(n);
  js_dispatch_entries_.items.resize(n);
  space.storage.items.resize(n);
  int index = static_cast<int>(index_value);
  uint32_t chunk_index = index_value;
  uint32_t entry_id = index_value;
''' + "".join(bodies) + r'''
  if (indexes_reached != 5) return 4;
  return back_refs_.indexes + attached_objects_.indexes +
         unresolved_forward_refs_.indexes + js_dispatch_entries_.indexes +
         space.storage.indexes;
}

int main(int argc, char** argv) {
  if (argc != 2) return 2;
  std::string mode(argv[1]);
  int indexed = 0;
  if (mode == "in-range") indexed = exercise(2, 1);
  else if (mode == "out-of-range") indexed = exercise(2, 4);
  else return 2;
  if (indexed != 5) return 3;
  std::printf("%s\n", mode == "in-range" ? "in-range-ok" : "out-of-range-reached-index");
  return 0;
}
'''


if __name__ == "__main__":
    unittest.main()
