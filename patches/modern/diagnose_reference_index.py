#!/usr/bin/env python3
"""Name the std::vector index before V8 15.2.124.28 code-cache deserialization.

This edits only src/snapshot/deserializer.cc at that exact tag. It does not
change the shared modern patcher, skip the index, disable libc++ hardening, or
turn a failed load into disassembly. On an in-range index the original
operator[] runs with no added log. On an out-of-range index it fflush's one
stderr line and then still executes that same operator[], so a hardened build
still aborts.

Nothing here deserializes a code cache or proves which vector the Windows
sample hit.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


MARKER = "JSC2JS_REFERENCE_INDEX_DIAGNOSTIC"
REQUIRED_VERSION = "15.2.124.28"
DESERIALIZER_CC = "src/snapshot/deserializer.cc"
VERSION_H = "include/v8-version.h"

# Exact, unique statements in tag 15.2.124.28 deserializer.cc.
# ExternalReferenceTable::address uses a C array, not std::vector, so it is
# intentionally absent: it cannot emit the libc++ "vector[]" assertion.
_SITES = (
    {
        "kind": "back-reference",
        "index": "index",
        "size": "back_refs_.size()",
        "old": "  Handle<HeapObject> obj = back_refs_[index];\n",
    },
    {
        "kind": "read-only-heap-page",
        "index": "chunk_index",
        "size": "read_only_space->pages().size()",
        "old": "  ReadOnlyPage* page = read_only_space->pages()[chunk_index];\n",
    },
    {
        "kind": "attached-object",
        "index": "index",
        "size": "attached_objects_.size()",
        "old": "  DirectHandle<HeapObject> heap_object = attached_objects_[index];\n",
    },
    {
        "kind": "unresolved-forward-ref",
        "index": "index",
        "size": "unresolved_forward_refs_.size()",
        "old": "  auto& forward_ref = unresolved_forward_refs_[index];\n",
    },
    {
        "kind": "js-dispatch-entry",
        "index": "entry_id",
        "size": "js_dispatch_entries_.size()",
        "old": "  JSDispatchHandle handle = js_dispatch_entries_[entry_id];\n",
    },
)


class DiagnosticError(RuntimeError):
    pass


def read_v8_version(version_header: str) -> str:
    parts = []
    for name in (
        "V8_MAJOR_VERSION",
        "V8_MINOR_VERSION",
        "V8_BUILD_NUMBER",
        "V8_PATCH_LEVEL",
    ):
        match = re.search(rf"(?m)^#define\s+{name}\s+(\d+)\s*$", version_header)
        if not match:
            raise DiagnosticError(f"missing {name} in include/v8-version.h")
        parts.append(str(int(match.group(1))))
    return ".".join(parts)


def _prelude(kind: str, index: str, size: str) -> str:
    return (
        "  if (static_cast<size_t>("
        f"{index}) >= {size}) {{\n"
        "    fprintf(stderr,\n"
        '            "[jsc2js-diag] out-of-range '
        f"{kind} index=%llu size=%llu\\n\",\n"
        f"            static_cast<unsigned long long>({index}),\n"
        f"            static_cast<unsigned long long>({size}));\n"
        "    fflush(stderr);\n"
        "  }\n"
    )


def transform_deserializer(text: str) -> str:
    """Insert the diagnostic before each known vector index.

    Re-applying the transform is a no-op. The original operator[] line is kept.
    """
    if MARKER in text:
        return text
    counts = {site["kind"]: text.count(site["old"]) for site in _SITES}
    missing = [kind for kind, count in counts.items() if count != 1]
    if missing:
        raise DiagnosticError(
            "deserializer.cc does not have exactly one copy of each "
            f"15.2.124.28 index site: {counts}"
        )
    for site in _SITES:
        text = text.replace(
            site["old"], _prelude(site["kind"], site["index"], site["size"]) + site["old"], 1
        )
    include = "#include <inttypes.h>\n"
    if text.count(include) != 1:
        raise DiagnosticError("expected one #include <inttypes.h> anchor")
    text = text.replace(
        include,
        include + f"#include <stdio.h>  // {MARKER}\n",
        1,
    )
    for site in _SITES:
        if text.count(site["old"]) != 1:
            raise DiagnosticError(f"original index was not preserved: {site['kind']}")
        if text.count(_prelude(site["kind"], site["index"], site["size"])) != 1:
            raise DiagnosticError(f"diagnostic prelude missing: {site['kind']}")
    return text


def apply_to_tree(root: Path) -> dict:
    version_path = root / VERSION_H
    deserializer_path = root / DESERIALIZER_CC
    if not version_path.is_file() or not deserializer_path.is_file():
        raise DiagnosticError(
            "need include/v8-version.h and src/snapshot/deserializer.cc"
        )
    version = read_v8_version(version_path.read_text(encoding="utf-8"))
    if version != REQUIRED_VERSION:
        raise DiagnosticError(
            f"refusing to edit V8 {version}; this diagnostic is for "
            f"{REQUIRED_VERSION} only"
        )
    original = deserializer_path.read_text(encoding="utf-8")
    updated = transform_deserializer(original)
    if updated != original:
        deserializer_path.write_text(updated, encoding="utf-8", newline="\n")
    return {
        "version": version,
        "file": DESERIALIZER_CC,
        "changed": updated != original,
        "marker": MARKER,
        "sites": [site["kind"] for site in _SITES],
        "disables_hardening": False,
        "skips_out_of_range_index": False,
        "parses_code_cache": False,
        "evidence": "source edit of the exact tag; not a d8 run and not a sample",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument(
        "--report",
        type=Path,
        help="Write the JSON report here. Also printed to stdout.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = apply_to_tree(args.root.resolve())
    except DiagnosticError as error:
        print(f"[reference-index-diagnostic] ERROR: {error}", file=sys.stderr)
        return 2
    payload = json.dumps(report, indent=2) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
