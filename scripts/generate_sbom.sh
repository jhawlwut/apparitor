#!/usr/bin/env bash
# Generate a CycloneDX Software Bill of Materials (SBOM) for the shipped package.
#
# We describe the *runtime* dependency tree — not this checkout's dev/build tooling — by
# installing the project (no extras) into a throwaway "runtime" virtualenv and scanning it.
# The CycloneDX generator lives in a SEPARATE throwaway "tool" virtualenv (installed via the
# pinned `[sbom]` extra), so it neither leaks into the SBOM nor mutates the caller's
# environment. Output is schema-validated, content-checked, and reproducible (no timestamps
# / random serial numbers) so identical resolved inputs yield an identical artifact.
#
# Usage:
#   scripts/generate_sbom.sh [OUTPUT_PATH]
# Default OUTPUT_PATH: sbom/apparitor.cdx.json
#
# NOTE: the output deliberately defaults outside dist/. The release publish step runs
# `twine upload dist/*`, which rejects a non-distribution file — so the SBOM must never land
# in dist/.
set -euo pipefail

OUT="${1:-sbom/apparitor.cdx.json}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Runtime venv: exactly what ships (`pip install .`, no extras) — this is the scan target.
# `python -m venv` seeds pip (and sometimes setuptools); those venv-seed packages may appear
# in the SBOM even though they are not declared dependencies of the wheel.
echo "Building runtime-only environment for the SBOM scan..."
python -m venv "$WORK/runtime"
"$WORK/runtime/bin/pip" install --quiet .

# Tool venv: the CycloneDX generator, pinned via the project's `[sbom]` extra. Isolated so it
# never pollutes the runtime tree or the caller's interpreter.
echo "Installing the CycloneDX generator (pinned via the [sbom] extra)..."
python -m venv "$WORK/tool"
"$WORK/tool/bin/pip" install --quiet ".[sbom]"

mkdir -p "$(dirname "$OUT")"
echo "Generating SBOM -> ${OUT}"
"$WORK/tool/bin/python" -m cyclonedx_py environment "$WORK/runtime/bin/python" \
  --pyproject pyproject.toml \
  --mc-type library \
  --output-reproducible \
  --validate \
  --of JSON \
  -o "$OUT"

# Schema validation (--validate) proves well-formedness, not usefulness: an empty component
# list is still valid. Assert the SBOM actually captured the runtime tree, so a degenerate
# SBOM fails the build instead of shipping green.
python - "$OUT" <<'PY'
import json, sys

out = sys.argv[1]
components = json.load(open(out)).get("components", [])
names = {c["name"].lower() for c in components}
assert components, f"SBOM has no components: {out}"
missing = [dep for dep in ("httpx", "pydantic") if dep not in names]
assert not missing, f"SBOM is missing expected runtime deps {missing}; got {sorted(names)}"
print(f"SBOM OK: {len(components)} components, core runtime deps present.")
PY
