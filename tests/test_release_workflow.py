from pathlib import Path
import re
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yml"


def test_release_workflow_has_pinned_build_and_publish_contract():
    data = yaml.safe_load(WORKFLOW.read_text())
    triggers = data.get("on", data.get(True))
    assert list(triggers) == ["push"]
    assert triggers["push"] == {"tags": ["v*"]}
    assert data["permissions"] == {"contents": "read"}

    jobs = data["jobs"]
    writers = [name for name, job in jobs.items()
               if job.get("permissions", {}).get("contents") == "write"]
    assert writers == ["release"]
    uses = [step["uses"] for job in jobs.values() for step in job["steps"] if "uses" in step]
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", ref) for ref in uses)

    build = jobs["build"]
    scripts = "\n".join(step.get("run", "") for step in build["steps"])
    assert "__version__" in scripts and "GITHUB_REF_NAME" in scripts
    assert all(url in scripts for url in (
        "http://127.0.0.1:5099/",
        "http://127.0.0.1:5099/static/vendor/tailwind-3.4.17.js",
        "http://127.0.0.1:5099/static/js/app.js",
    ))
    artifact = next(step for step in build["steps"] if "upload-artifact" in step.get("uses", ""))
    assert "SHA256SUMS" in artifact["with"]["path"]
    assert tomllib.loads((ROOT / "pyproject.toml").read_text())['tool']['hatch']['version']['path'] == "audithor/__init__.py"
