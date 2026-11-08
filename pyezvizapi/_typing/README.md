# Static-only owner interfaces

These `.pyi` modules re-export the nominal types needed by implementation
annotations. They are imported only under `TYPE_CHECKING`, not at runtime.
The interfaces preserve the actual API types rather than replacing them with
`Any`, and the build includes them in the installed wheel.

Operational dependencies are still passed explicitly. No lazy module proxy or
runtime type namespace is introduced here. `tests/compat/test_dependency_graph.py`
checks the actual import-time graph separately from typing dependencies.
