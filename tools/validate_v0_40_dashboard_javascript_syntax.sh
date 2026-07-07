#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.40 Dashboard JavaScript Syntax Validator"
echo "======================================================="

python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

python3 -W error::SyntaxWarning - <<'PY'
from pathlib import Path
import ast
import importlib.util
import re
import sys


SOURCE = Path("deltaaegis.py")
source = SOURCE.read_text(encoding="utf-8")
tree = ast.parse(source)

malformed_patterns = (
    (
        "join with literal newline",
        re.compile(r'\.join\((["\'])\r?\n\1\)'),
    ),
    (
        "split with literal newline",
        re.compile(r'\.split\((["\'])\r?\n\1\)'),
    ),
    (
        "replace with literal newline",
        re.compile(r'\.replace(?:All)?\((["\'])\r?\n\1'),
    ),
)

findings = []

for node in ast.walk(tree):
    values = []

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        values.append(node.value)
    elif isinstance(node, ast.JoinedStr):
        values.extend(
            part.value
            for part in node.values
            if isinstance(part, ast.Constant)
            and isinstance(part.value, str)
        )

    for value in values:
        for label, pattern in malformed_patterns:
            if pattern.search(value):
                findings.append(
                    f"source line {getattr(node, 'lineno', '?')}: {label}"
                )

if findings:
    raise SystemExit(
        "malformed decoded JavaScript newline strings remain:\n"
        + "\n".join(findings)
    )

print("PASS: no malformed decoded JavaScript newline strings")


def import_module():
    module_name = "deltaaegis_v040_dashboard_js_validator"
    spec = importlib.util.spec_from_file_location(
        module_name,
        SOURCE.resolve(),
    )

    if spec is None or spec.loader is None:
        raise SystemExit("could not load deltaaegis.py")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module

    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(module_name, None)

    return module


def extract_scripts(html):
    return [
        match.group(1)
        for match in re.finditer(
            r"<script(?:\s[^>]*)?>(.*?)</script>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
    ]


module = import_module()

renderers = {
    "main dashboard": "dashboard_index_html_base_v025_operator_link",
    "NetSniper page": "render_netsniper_page",
    "operator users": "dashboard_operator_users_shell_html",
    "operator reset": "dashboard_operator_reset_shell_html",
}

rendered_count = 0
script_count = 0
rendered_findings = []

for label, name in renderers.items():
    function = getattr(module, name, None)

    if function is None:
        if label == "main dashboard":
            raise SystemExit(f"required renderer missing: {name}")
        continue

    try:
        html = function()
    except TypeError as exc:
        raise SystemExit(f"could not invoke {name}: {exc}")

    if not isinstance(html, str):
        raise SystemExit(f"{name} did not return HTML text")

    rendered_count += 1
    scripts = extract_scripts(html)
    script_count += len(scripts)

    for number, script in enumerate(scripts, start=1):
        for pattern_label, pattern in malformed_patterns:
            if pattern.search(script):
                rendered_findings.append(
                    f"{label} script {number}: {pattern_label}"
                )

if rendered_findings:
    raise SystemExit(
        "malformed rendered JavaScript newline strings remain:\n"
        + "\n".join(rendered_findings)
    )

print(
    f"PASS: rendered {rendered_count} dashboard page(s) "
    f"and checked {script_count} script block(s)"
)

main_html = module.dashboard_index_html_base_v025_operator_link()

for required in (
    'data-tab-target="overview"',
    'button.addEventListener("click"',
    'deltaaegis-dashboard-tab',
    'renderDashboardActionReceipt',
):
    if required not in main_html:
        raise SystemExit(
            f"main dashboard lost required JavaScript marker: {required}"
        )

# The decoded-string and rendered-script scans above are the authoritative
# newline-safety checks. Receipt renderers are assembled through multiple
# HTML extension layers, so do not require their exact source text to appear
# in the base-renderer return value.
print("PASS: main dashboard tab and receipt JavaScript markers")
PY

echo "PASS: DeltaAegis v0.40 dashboard JavaScript syntax validator"
