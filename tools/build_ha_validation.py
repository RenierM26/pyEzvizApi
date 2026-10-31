"""Build local-only wheel/sdist and a deterministic HA example zip from clean Git.

Requires uv. No install, release, relay replacement, HA access or source acquisition.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def build(root: Path, output: Path, python: str) -> None:
    if git(root, "status", "--porcelain").strip():
        raise RuntimeError("Commit or isolate changes before building a reviewable snapshot")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    epoch = git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip()
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="ezviz-package-") as temporary:
        source = Path(temporary)
        with tarfile.open(fileobj=io.BytesIO(git(root, "archive", "HEAD"))) as archive:
            archive.extractall(source, filter="data")
        project_file = source / "pyproject.toml"
        project_text = project_file.read_text()
        original = tomllib.loads(project_text)["project"]["version"]
        version = original.split("+")[0] + "+ha.relay.g" + commit[:12]
        project_file.write_text(project_text.replace(
            f'version = "{original}"', f'version = "{version}"', 1,
        ))
        constraints = source / "build-constraints.txt"
        constraints.write_text("setuptools==80.9.0\nwheel==0.45.1\n")
        subprocess.run([
            "uv", "build", "--python", python, "--build-constraint", str(constraints),
            "--out-dir", str(output / "dist"), str(source),
        ], env={**os.environ, "SOURCE_DATE_EPOCH": epoch}, check=True)

        integration = source / "examples/home_assistant/custom_components/ezviz_native"
        integration_zip = output / f"ezviz_native-validation-g{commit[:12]}.zip"
        with zipfile.ZipFile(integration_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(integration.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix not in {".py", ".json"}:
                    raise RuntimeError(f"Unexpected integration artifact: {path.name}")
                name = "custom_components/ezviz_native/" + path.relative_to(integration).as_posix()
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                archive.writestr(info, path.read_bytes())
            info = zipfile.ZipInfo("LICENSE.md", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, (source / "LICENSE.md").read_bytes())

        wheel, = (output / "dist").glob("*.whl")
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            if not {"pyezvizapi/native_stream.py", "pyezvizapi/native_ps.py", "pyezvizapi/py.typed"} <= names:
                raise RuntimeError("Wheel is missing required native modules or typing marker")
            if any(n.startswith(("custom_components/", "examples/")) for n in names):
                raise RuntimeError("The HA example must not become a library wheel dependency")
        files = {
            path.relative_to(output).as_posix(): {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(output.rglob("*")) if path.is_file()
        }
        (output / "manifest.json").write_text(json.dumps({
            "git_commit": commit, "source_date_epoch": int(epoch),
            "original_version": original, "local_validation_version": version,
            "build_constraints": constraints.read_text().splitlines(),
            "files": files, "production_ready": False,
            "relay_included": False, "camera_or_ha_access": False,
        }, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory outside checkout")
    parser.add_argument("--python", default="3.12", help="Build interpreter selected by uv")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        parser.error("Output must be outside the source checkout")
    build(root, output, args.python)


if __name__ == "__main__":
    main()
