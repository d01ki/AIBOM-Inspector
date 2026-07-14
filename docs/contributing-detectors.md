# Contributing detectors

A detector implements the protocol in `aibom.detectors.base`:

```python
class ExampleDetector:
    detector_id = "python.example.ast"

    def supports(self, path: str) -> bool:
        return path.endswith(".py")

    def detect(self, context: ScanContext) -> Iterable[Detection]:
        ...
```

Requirements:

1. Use a globally stable, namespaced detector ID.
2. Never import or execute scanned code.
3. Attach evidence with a repository-relative file and valid line span.
4. Preserve unresolved values instead of guessing.
5. Set usage and confidence factors according to observed syntax.
6. Add recall and precision tests, including comments, docstrings, imports-only,
   alias imports, indirect values, and malformed-source fallback.
7. Register the detector in `default_registry`; users can then disable it with
   `--disable-detector <id>`.

Inventory normalization handles duplicate natural keys and merges evidence,
usage states, source contexts, confidence factors, and resolution paths.
