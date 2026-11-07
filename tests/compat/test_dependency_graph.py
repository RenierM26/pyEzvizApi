"""Implementation packages must remain acyclic during module initialisation."""
import ast
from importlib.util import resolve_name

from tests._paths import ROOT


def _initial_imports(nodes):
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue  # Deferred operational imports are not initialisation edges.
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == "TYPE_CHECKING":
            yield from _initial_imports(node.orelse)
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        else:
            yield from _initial_imports(ast.iter_child_nodes(node))


def test_runtime_import_graph_is_acyclic():
    files = {}
    for path in (ROOT / "pyezvizapi").rglob("*.py"):
        parts = path.relative_to(ROOT).with_suffix("").parts
        if parts[-1] == "__init__":
            parts = parts[:-1]
        files[".".join(parts)] = path
    edges: dict[str, set[str]] = {name: set() for name in files}
    for name, path in files.items():
        package = name if path.name == "__init__.py" else name.rpartition(".")[0]
        for node in _initial_imports(ast.parse(path.read_text()).body):
            if isinstance(node, ast.Import):
                candidates = [alias.name for alias in node.names]
            else:
                prefix = (
                    resolve_name("." * node.level + (node.module or ""), package)
                    if node.level else node.module or ""
                )
                candidates = [
                    prefix + "." + alias.name if prefix + "." + alias.name in files else prefix
                    for alias in node.names
                ]
            edges[name].update(dep for dep in candidates if dep in files and dep != name)
    active, finished = set(), set()

    def visit(name, trail):
        assert name not in active, "Import cycle: " + " -> ".join([*trail, name])
        if name in finished:
            return
        active.add(name)
        for dependency in sorted(edges[name]):
            visit(dependency, [*trail, name])
        active.remove(name)
        finished.add(name)

    for name in edges:
        visit(name, [])
