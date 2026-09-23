"""The README states two structural properties. These hold them.

Both were claimed in prose and enforced by nothing, which is how one of them quietly became
false: `eastwest/errors.py` imported Falcon for two status-line constants that are plain
strings. A property worth stating is worth failing the build over.
"""

import ast
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "falcon_auth"

#: The only subpackage permitted to know about the web framework.
ADAPTERS = "adapters"

#: Imported by the cores, and legitimately: they are libraries, not the framework.
FRAMEWORK_ROOTS = {"falcon"}


def _modules():
    """Every module in the package, with the path it sits at."""
    for path in sorted(SRC.rglob("*.py")):
        yield path, path.relative_to(SRC)


def _imported_names(path: pathlib.Path) -> set[str]:
    """Every module path this file imports, relative ones resolved to a dotted suffix.

    AST, not substring matching: `eastwest/verifier.py` has the words "enforcer" and
    "adapters" in its DOCSTRINGS, which is documentation pointing at a seam, not a dependency
    crossing one. A text search cannot tell those apart; this can.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level
            names.add(f"{prefix}{node.module or ''}")
    return names


def _imported_roots(path: pathlib.Path) -> set[str]:
    """Top-level package names this module imports, deferred imports included.

    Walks the whole tree rather than the module body, so an import moved inside a function --
    which is how `verify_app` legitimately reaches Falcon -- is still seen. A deferred import
    keeps a module importable without the framework; it does not make the module independent
    of it, and this test is about the latter.
    """
    roots: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


# ── the framework stays in adapters/ ──────────────────────────────────────────


def test_nothing_outside_adapters_imports_falcon():
    """The README's "framework-agnostic cores" claim, enforced.

    The cores are driven by plain values -- a token string, two reference strings, a raw ASGI
    scope -- so each is exercisable without a web framework, and a non-Falcon consumer could
    use them unchanged. That stops being true the moment a core imports Falcon for something
    it could have spelled out, which is exactly what happened with two status-line constants.
    """
    offenders = [
        str(rel)
        for path, rel in _modules()
        if rel.parts[0] != ADAPTERS and _imported_roots(path) & FRAMEWORK_ROOTS
    ]
    assert not offenders, (
        f"these modules import the web framework outside {ADAPTERS}/: {offenders}. "
        f"If the import is for a constant, spell the value out; if it is for behaviour, the "
        f"code belongs in {ADAPTERS}/"
    )


def test_the_adapters_layer_is_allowed_to():
    """The other half of the claim: this is a boundary, not a ban."""
    adapters = [p for p, rel in _modules() if rel.parts[0] == ADAPTERS]
    assert any(_imported_roots(p) & FRAMEWORK_ROOTS for p in adapters), (
        "no adapter imports Falcon, so the test above is passing vacuously"
    )


def test_a_core_module_can_be_imported_without_falcon(monkeypatch):
    """Not just "does not import" but "does not need to" -- the property a consumer feels."""
    import sys

    for name in [n for n in sys.modules if n.startswith("falcon_auth")]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "falcon", None)

    with pytest.raises(Exception):
        import falcon  # noqa: F401

        falcon.HTTP_401  # pragma: no cover

    from falcon_auth.eastwest import errors

    assert errors.MissingClientCertError(code=9001).http_status == "401 Unauthorized"


# ── the decision boundary ─────────────────────────────────────────────────────


def test_only_entitlement_imports_the_enforcer():
    """The README's other claim: east-west, identity and assurance may ESTABLISH who a caller
    is and how strongly. They may never DECIDE permission -- only entitlement/ decides.

    Packaging used to hold this line; module structure holds it now, and this holds the module
    structure. A capability check appearing inside `identity/` would mean two places answer
    "may they", and the second one is the one nobody audits.
    """
    establishers = ("eastwest", "identity", "assurance")
    offenders = []
    for path, rel in _modules():
        if rel.parts[0] not in establishers:
            continue
        if any("enforcer" in name for name in _imported_names(path)):
            offenders.append(str(rel))
    assert not offenders, (
        f"these modules reach for the capability gate: {offenders}. Establishing identity and "
        f"deciding permission are different jobs, and only entitlement/ does the second"
    )


def test_the_cores_do_not_import_the_adapters():
    """The dependency runs one way. An adapter knows about a core; a core that knew about its
    adapter would make the framework-agnostic claim circular."""
    offenders = [
        str(rel)
        for path, rel in _modules()
        if rel.parts[0] != ADAPTERS
        and any(ADAPTERS in name.lstrip(".").split(".") for name in _imported_names(path))
    ]
    assert not offenders, f"these cores reference the adapters layer: {offenders}"
