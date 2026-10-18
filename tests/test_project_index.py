"""The project index's tsconfig reader (JSONC, as TypeScript accepts it)."""

from __future__ import annotations

from aibom.detectors.javascript.parser import parse_javascript
from aibom.detectors.project import ProjectIndex

NEXT_TSCONFIG = """{
  // comment
  "compilerOptions": {
    /* block */
    "paths": { "@/*": ["./*"], "~lib/*": ["src/lib/*"] },
    "strict": true,
  },
  "include": ["next-env.d.ts", "**/*.ts", ".next/types/**/*.ts"]
}
"""


def _index() -> ProjectIndex:
    index = ProjectIndex()
    index.load_tsconfig(NEXT_TSCONFIG)
    for path in ("app/page.ts", "lib/agent.ts", "src/lib/tools/run.ts"):
        index.add_javascript(parse_javascript("export const x = 1;\n", path))
    return index


def test_globs_inside_strings_are_not_comments() -> None:
    assert [prefix for prefix, _, _ in _index().ts_paths] == ["~lib/", "@/"]


def test_path_aliases_resolve_to_files() -> None:
    index = _index()
    importer = index.javascript["app/page.ts"]
    found = index.js_module(importer, "@/lib/agent")
    assert found is not None and found.relative_path == "lib/agent.ts"
    found = index.js_module(importer, "~lib/tools/run")
    assert found is not None and found.relative_path == "src/lib/tools/run.ts"


def test_unparseable_tsconfig_is_ignored() -> None:
    index = ProjectIndex()
    index.load_tsconfig('{"compilerOptions": ')
    assert index.ts_paths == []
