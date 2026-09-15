"""The AI layer's layer-wide rules, read from source (docs/ai-threat-model.md §6).

S1, S2 and S4 are what turn P5 ("model output crosses none of these lines") and P8 ("the
endpoint is hostile on the way back") from promises into mechanisms. They need no
builder and no model, so they guard every slot from the first one on. Source is parsed,
not imported, in the spirit of `tests/test_jamf_privileges.py`: the question is what the
code contains, and an import inside a function counts as much as one at the top of the
file.

S3, the feature registry, is not here because it is not built. Pure; no database, no
network.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_APP = _ROOT / "backend" / "app"
_AI = _APP / "ai"
_FEATURES = _ROOT / "frontend" / "src" / "features"


def _rel(path: Path) -> str:
    return path.relative_to(_ROOT / "backend").as_posix()


def _python_files(*roots: Path) -> Iterator[Path]:
    for root in roots:
        yield from sorted(root.rglob("*.py")) if root.is_dir() else [root]


def _module_name(path: Path) -> str:
    parts = path.relative_to(_ROOT / "backend").with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(), filename=str(path))


def _from_module(node: ast.ImportFrom, path: Path) -> str:
    """The absolute module a `from … import` reads, relative imports resolved."""
    if not node.level:
        return node.module or ""
    package = _module_name(path).split(".")
    if path.name != "__init__.py":
        package = package[:-1]
    base = ".".join(package[: len(package) - node.level + 1])
    return f"{base}.{node.module}" if node.module else base


def _imports(path: Path) -> set[str]:
    """Every module a file imports, anywhere in it, as absolute dotted names. `from a.b
    import c` counts as both `a.b` and `a.b.c`, because `c` may be a module: `from app
    import ai` is an import of `app.ai`. `importlib.import_module("…")` with a literal
    counts too."""
    found: set[str] = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = _from_module(node, path)
            found.add(module)
            found.update(f"{module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in {"import_module", "__import__"} and isinstance(node.args[0].value, str):
                found.add(node.args[0].value)
    return found


def _within(names: Iterable[str], package: str) -> list[str]:
    return sorted(name for name in names if name == package or name.startswith(package + "."))


# --- S1. The import boundary ----------------------------------------------------------------

# The wire and the evidence: what observes a fleet, derives its changes and alerts, and
# sends it anywhere. None of it may reach a model, so none of it may import one.
_FENCED = [
    _APP / "mdm",
    _APP / "observations",
    _APP / "changes",
    _APP / "alerts",
    _APP / "core" / "outbox.py",
    _APP / "core" / "sharing.py",
]
# What the AI layer may never reach: the outbox and the exchange (so model output cannot
# ride a wire destination), and the ORM (so it cannot be written as if it were evidence).
_UNREACHABLE_FROM_AI = ("app.core.outbox", "app.core.sharing", "app.models")


def test_s1_nothing_that_observes_or_sends_the_fleet_imports_the_ai_layer() -> None:
    missing = [_rel(path) for path in _FENCED if not path.exists()]
    assert missing == [], f"S1 fences {missing}, which no longer exist; move the fence with the code, never drop it"

    offenders = {_rel(path): _within(_imports(path), "app.ai") for path in _python_files(*_FENCED)}
    offenders = {path: names for path, names in offenders.items() if names}
    assert offenders == {}, (
        "S1: the observation, change, alert and wire paths must not import app.ai, or model output has a "
        f"route onto the wire and into the evidence (docs/ai-threat-model.md P5): {offenders}"
    )


def test_s1_the_ai_layer_imports_neither_the_wire_nor_the_database() -> None:
    offenders: dict[str, list[str]] = {}
    for path in _python_files(_AI):
        imported = _imports(path)
        names = [name for package in _UNREACHABLE_FROM_AI for name in _within(imported, package)]
        if names:
            offenders[_rel(path)] = names
    assert offenders == {}, (
        f"S1: app.ai must not import {', '.join(_UNREACHABLE_FROM_AI)}; a route that needs one of them does "
        f"the database or wire work itself and hands app.ai plain values: {offenders}"
    )


# --- S2. One door ------------------------------------------------------------------------------

# A client, or one of httpx's one-shot helpers, which build a client inside.
_HTTPX_DOORS = {"AsyncClient", "Client", "get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
# Any other HTTP stack under app/ai would be a second door with none of the bounds.
_OTHER_HTTP = ("urllib.request", "http.client", "aiohttp", "requests", "urllib3", "httpcore", "pycurl")
# The adapter's two calls that dial an endpoint.
_EGRESS = {"complete", "list_models"}


def _httpx_doors(path: Path) -> list[tuple[str, int]]:
    """(enclosing function, line) of every httpx client or one-shot request a file makes."""
    tree = _parse(path)
    module_names: set[str] = set()
    direct: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            module_names.update(alias.asname or alias.name for alias in node.names if alias.name == "httpx")
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            direct.update(alias.asname or alias.name for alias in node.names if alias.name in _HTTPX_DOORS)

    sites: list[tuple[str, int]] = []

    def visit(node: ast.AST, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call):
                func = child.func
                via_module = (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id in module_names
                    and func.attr in _HTTPX_DOORS
                )
                if via_module or (isinstance(func, ast.Name) and func.id in direct):
                    sites.append((function, child.lineno))
            inner = child.name if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef) else function
            visit(child, inner)

    visit(tree, "<module>")
    return sites


def test_s2_the_only_http_client_in_the_ai_layer_is_the_adapters_bounded_door() -> None:
    doors = {(_rel(path), function) for path in _python_files(_AI) for function, _ in _httpx_doors(path)}
    assert doors == {("app/ai/adapters.py", "_request")}, (
        "S2: every model call goes through adapters._request, the one place with the wall clock, the size "
        f"cap, no redirects and two calls in flight; another client here has none of them: {sorted(doors)}"
    )
    others: dict[str, list[str]] = {}
    for path in _python_files(_AI):
        imported = _imports(path)
        names = [name for lib in _OTHER_HTTP for name in _within(imported, lib)]
        if names:
            others[_rel(path)] = names
    assert others == {}, f"S2: a second HTTP stack under app/ai is a second door: {others}"


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted(node.value)
        return f"{head}.{node.attr}" if head else None
    return None


def _uses_the_adapter(path: Path) -> bool:
    """Whether a module reaches `complete` or `list_models` of `app.ai.adapters`, by name
    or through the module. A reference counts as much as a call: `ask = complete` is
    still a call to the endpoint, one line later."""
    tree = _parse(path)
    bound: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = _from_module(node, path)
            if module == "app.ai.adapters":
                bound.update(alias.asname or alias.name for alias in node.names if alias.name in _EGRESS)
            elif module == "app.ai":
                modules.update(alias.asname or alias.name for alias in node.names if alias.name == "adapters")
        elif isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names if alias.name == "app.ai.adapters")
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in bound:
            return True
        if isinstance(node, ast.Attribute) and node.attr in _EGRESS and _dotted(node.value) in modules:
            return True
    return False


def _asks_the_gate(path: Path) -> bool:
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Call):
            func = node.func
            if (isinstance(func, ast.Name) and func.id == "require_ai") or (
                isinstance(func, ast.Attribute) and func.attr == "require_ai"
            ):
                return True
    return False


def test_s2_every_module_that_dials_a_model_asks_the_gate() -> None:
    callers = [path for path in _python_files(_APP) if path != _AI / "adapters.py" and _uses_the_adapter(path)]
    # Vacuity guard: the test box is a caller today, so a scan that finds none is broken.
    assert "app/api/ai.py" in {_rel(path) for path in callers}, "S2's scan no longer finds app/api/ai.py's calls"

    ungated = [_rel(path) for path in callers if not _asks_the_gate(path)]
    assert ungated == [], (
        "S2: a module that calls the adapter's complete( or list_models( must also call require_ai( — the "
        f"flag, the consent and the share-log row come before the first byte (P6): {ungated}"
    )


# --- S4. Text only, in the frontend ----------------------------------------------------------


# Where model text is shown: the AI settings area, and the Changes page's Prompt bar and
# the page that hosts it. Globbed, so the files are covered from the day they exist.
def _rendering_files() -> list[Path]:
    changes = _FEATURES / "changes"
    files = [path for path in (_FEATURES / "ai").rglob("*") if path.suffix in {".ts", ".tsx"}]
    for pattern in ("[Pp]rompt*.ts", "[Pp]rompt*.tsx", "ChangesPage.tsx"):
        files.extend(changes.glob(pattern))
    return sorted(set(files))


# (what it is, how it looks in code). Any of these turns a model's text into markup.
_RENDERERS = [
    ("dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    (".innerHTML / .outerHTML", re.compile(r"\.(?:inner|outer)HTML\b")),
    ("insertAdjacentHTML", re.compile(r"insertAdjacentHTML")),
    ("react-markdown", re.compile(r"react-markdown")),
    ("marked(", re.compile(r"\bmarked\s*\(")),
    ("markdown-it", re.compile(r"markdown-it")),
    ("DOMPurify", re.compile(r"dompurify", re.I)),
    (
        "a markdown or HTML renderer package",
        re.compile(r"""(?:from|import)\s*\(?\s*["'][^"']*(?:markdown|marked|remark|rehype|showdown|html-react-parser)"""),
    ),
]

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
# `//` after whitespace or punctuation only, so `https://` inside a string is left alone.
_LINE_COMMENT = re.compile(r"(^|[\s;,{}()])//.*$", re.M)


def _code(text: str) -> str:
    """The file with its comments blanked, line numbers kept: a comment that says "never
    dangerouslySetInnerHTML" is the rule being followed, not broken."""
    text = _BLOCK_COMMENT.sub(lambda match: "\n" * match.group(0).count("\n"), text)
    return _LINE_COMMENT.sub(lambda match: match.group(1), text)


def test_s4_model_text_is_rendered_as_text_never_as_markup() -> None:
    files = _rendering_files()
    assert any(path.parent.name == "ai" for path in files), "S4's scan no longer finds frontend/src/features/ai"

    offences: dict[str, list[str]] = {}
    for path in files:
        for number, line in enumerate(_code(path.read_text()).splitlines(), start=1):
            for what, pattern in _RENDERERS:
                if pattern.search(line):
                    offences.setdefault(path.relative_to(_ROOT).as_posix(), []).append(f"{number}: {what}")
    assert offences == {}, (
        f"S4: model text renders as plain text, escaped, never markdown, HTML or a link (docs/ai-threat-model.md P4): {offences}"
    )


def test_s4_the_scan_sees_through_comments_but_not_past_code() -> None:
    """The comment stripper is what keeps S4 from failing on its own rule written down,
    so it is pinned both ways."""
    source = 'const a = 1; // never dangerouslySetInnerHTML\n/* no react-markdown */\nel.innerHTML = t; // "x"\n'
    code = _code(source)
    assert "dangerouslySetInnerHTML" not in code
    assert "react-markdown" not in code
    assert ".innerHTML" in code
    assert _code('const u = "https://example.com";') == 'const u = "https://example.com";'
