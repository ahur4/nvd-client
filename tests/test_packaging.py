"""Import and packaging checks for the pytz regression (issue #3)."""

import subprocess
import sys
import zipfile
from importlib.metadata import metadata, requires, version
from pathlib import Path

import nvd_client
from nvd_client import CveRecord, NvdApi, NvdConfig

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(nvd_client.__file__).resolve().parent


def test_project_urls_and_docs_extra() -> None:
    meta = metadata("nvd-client")
    urls = meta.get_all("Project-URL") or []
    assert "Documentation, https://ahur4.github.io/nvd-client/" in urls
    assert "Homepage, https://github.com/ahur4/nvd-client" in urls
    assert "Source, https://github.com/ahur4/nvd-client" in urls
    assert "Repository, https://github.com/ahur4/nvd-client" in urls
    assert "Issues, https://github.com/ahur4/nvd-client/issues" in urls
    assert "Changelog, https://github.com/ahur4/nvd-client/blob/main/CHANGELOG.md" in urls
    extras = meta.get_all("Provides-Extra") or []
    assert "docs" in extras
    requires_dist = meta.get_all("Requires-Dist") or []
    assert any("mkdocs-material" in item and 'extra == "docs"' in item for item in requires_dist)
    assert any("mkdocstrings" in item and 'extra == "docs"' in item for item in requires_dist)


def test_import_succeeds_without_pytz() -> None:
    script = (
        "import sys\n"
        "import nvd_client\n"
        "from nvd_client import CveRecord, NvdApi, NvdConfig\n"
        "assert 'pytz' not in sys.modules\n"
        "assert NvdApi and NvdConfig and CveRecord\n"
    )
    subprocess.check_call([sys.executable, "-c", script], cwd=ROOT)


def test_distribution_does_not_depend_on_pytz() -> None:
    declared = requires("nvd-client") or []
    blob = "\n".join(declared).lower()
    assert "pytz" not in blob
    names = []
    for item in declared:
        head = item.split(";", 1)[0]
        for separator in (">", "<", "=", "!"):
            head = head.split(separator, 1)[0]
        names.append(head.strip().lower())
    assert "requests" in names
    assert "urllib3" in names
    assert "pydantic" in names
    assert "idna" in names
    assert version("nvd-client") == nvd_client.__version__
    assert NvdApi.__name__ == "NvdApi"
    assert NvdConfig.__name__ == "NvdConfig"
    assert CveRecord.__name__ == "CveRecord"


def test_package_source_does_not_import_pytz() -> None:
    for path in PACKAGE.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "import pytz" not in text
        assert "from pytz" not in text


def test_py_typed_is_present_and_packaged(tmp_path: Path) -> None:
    assert (PACKAGE / "py.typed").is_file()
    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(tmp_path),
            str(ROOT),
        ],
        cwd=ROOT,
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
        assert "nvd_client/py.typed" in names
        metadata_name = next(name for name in names if name.endswith(".dist-info/METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8").lower()
    requirements = [line for line in metadata.splitlines() if line.startswith("requires-dist:")]
    assert requirements
    assert all("pytz" not in line for line in requirements)
    assert any(line.startswith("requires-dist: pydantic") for line in requirements)
    assert any(line.startswith("requires-dist: requests") for line in requirements)
