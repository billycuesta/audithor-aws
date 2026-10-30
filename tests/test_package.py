import ast
import importlib
import importlib.resources
import re
from pathlib import Path

import audithor


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "audithor"


def test_package_version_is_semver():
    assert isinstance(audithor.__version__, str)
    assert re.fullmatch(r"\d+\.\d+\.\d+", audithor.__version__)


def test_package_resources_are_available():
    package = importlib.resources.files("audithor")
    paths = (
        "templates/dashboard.html",
        "static/vendor/tailwind-3.4.17.js",
        "static/js/app.js",
        "static/js/safe_html.js",
        "collectors/acm.py",
    )
    for path in paths:
        assert (package / path).is_file(), path


def test_package_entry_point_imports_without_starting_server():
    entry_point = importlib.import_module("audithor.__main__")
    assert entry_point is not None
    app = importlib.import_module("audithor.audithor_app")
    assert callable(app.main)


def test_package_python_modules_use_relative_sibling_imports():
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(alias.name.split(".")[0] in {"rules", "collectors", "utils", "audithor_app"} for alias in node.names), str(path)
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                assert node.module not in {"rules", "collectors", "utils", "audithor_app"}, str(path)


def test_old_project_name_is_absent_from_package_and_project_metadata():
    paths = [path for path in PACKAGE.rglob("*") if path.is_file() and "__pycache__" not in path.parts]
    paths.extend([ROOT / "README.md", ROOT / "pyproject.toml"])
    for path in paths:
        assert "audithor_project" not in path.read_text(encoding="utf-8", errors="ignore"), str(path)
