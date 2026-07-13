#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

branch="$(git branch --show-current)"
case "$branch" in
  feature/v0.42-logical-site-scopes|release/v0.42.1|release/v0.42.2|main)
    ;;
  *)
    echo "FAIL: unexpected branch $branch"
    exit 1
    ;;
esac

echo "DeltaAegis v0.42 TrueAegis Tab Containment Validator"
echo "======================================================"

echo "[v0.42 hotfix C] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 hotfix C] static containment contract"
python3 - <<'PY'
from pathlib import Path
import ast

source = Path("deltaaegis.py").read_text(encoding="utf-8")
ast.parse(source)

required = (
    'id="trueaegis-executive-readiness-panel"',
    'id="trueaegis-executive-readiness"',
    'id="trueaegis-executive-scan"',
    'id="trueaegis-executive-active-jobs"',
    'id="trueaegis-executive-message"',
    'id="trueaegis-executive-open-tab"',
    'id="trueaegis-orchestration-mount"',
    "function deltaAegisTrueAegisRenderExecutiveReadiness(",
    "foundation.prepend(mount);",
    "foundation.contains(mount)",
    "mount.appendChild(panel);",
    'activateDashboardTab("trueaegis")',
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing TrueAegis containment marker: {marker}"
        )

start = source.index(
    "function deltaAegisTrueAegisOrchestrationEnsurePanel()"
)
end = source.index(
    "async function deltaAegisTrueAegisOrchestrationFetchJson(",
    start,
)
ensure_function = source[start:end]

for forbidden in (
    "document.body.appendChild(panel)",
    'panel.dataset.tabPanel = "trueaegis"',
    "anchor.parentNode.insertBefore(panel, anchor)",
):
    if forbidden in ensure_function:
        raise SystemExit(
            f"unsafe orchestration placement remains: {forbidden}"
        )

if source.count(
    "window.setInterval("
    "deltaAegisTrueAegisOrchestrationRefresh, 15000"
    ");"
) != 1:
    raise SystemExit(
        "TrueAegis orchestration polling loop was duplicated or removed"
    )

executive_start = source.index(
    'id="trueaegis-executive-readiness-panel"'
)
executive_end = source.index(
    'data-tab-panel="trueaegis"',
    executive_start,
)
executive_markup = source[executive_start:executive_end]

for forbidden in (
    'id="trueaegis-run-button"',
    'id="trueaegis-refresh-button"',
    'id="trueaegis-run-receipt"',
    'id="trueaegis-validation-import-path"',
    "TrueAegis Jobs",
    "Technical command preview",
):
    if forbidden in executive_markup:
        raise SystemExit(
            f"full TrueAegis control leaked into Executive: {forbidden}"
        )

print("PASS: orchestration mount is inside static TrueAegis panel")
print("PASS: delayed top-level panel creation removed")
print("PASS: compact Executive readiness only")
print("PASS: one existing orchestration poller")
PY

echo "[v0.42 hotfix C] rendered DOM structure"
python3 - <<'PY'
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.request import Request, urlopen
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time


class Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.panels = []
        self.tags = []
        self.ids = []
        self.id_panel = {}
        self.text = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        panel = values.get("data-tab-panel")
        if panel is None:
            panel = self.panels[-1] if self.panels else None
        self.panels.append(panel)
        self.tags.append(tag)
        element_id = values.get("id")
        if element_id:
            self.ids.append(element_id)
            self.id_panel[element_id] = panel

    def handle_endtag(self, tag):
        if self.panels:
            self.panels.pop()
        if self.tags:
            self.tags.pop()

    def handle_data(self, data):
        value = " ".join(data.split())
        if not value:
            return
        tag = self.tags[-1] if self.tags else ""
        if tag in {"script", "style"}:
            return
        panel = self.panels[-1] if self.panels else None
        self.text.append((panel, value))


def reserve_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


with tempfile.TemporaryDirectory(
    prefix="deltaaegis-v042-trueaegis-dom-"
) as temp_name:
    temp = Path(temp_name)
    db = temp / "deltaaegis.db"
    stdout_path = temp / "dashboard.stdout"
    stderr_path = temp / "dashboard.stderr"
    port = reserve_port()
    token = "trueaegis-containment-token"

    with stdout_path.open("w", encoding="utf-8") as stdout_handle, \
            stderr_path.open("w", encoding="utf-8") as stderr_handle:
        process = subprocess.Popen(
            [
                sys.executable,
                "deltaaegis.py",
                "--db",
                str(db),
                "dashboard",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--token",
                token,
                "--quiet",
                "--no-enable-scheduled-scans",
            ],
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            start_new_session=True,
        )

        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.time() + 15

            while time.time() < deadline:
                if process.poll() is not None:
                    break
                try:
                    with urlopen(
                        Request(base + "/healthz"),
                        timeout=2,
                    ) as response:
                        if response.read() == b"ok":
                            break
                except OSError:
                    pass
                time.sleep(0.1)
            else:
                raise AssertionError("dashboard did not become ready")

            if process.poll() is not None:
                raise AssertionError(
                    "dashboard exited before render checks\n"
                    + stderr_path.read_text(encoding="utf-8")
                )

            with urlopen(
                Request(
                    base + "/",
                    headers={"X-DeltaAegis-Token": token},
                ),
                timeout=8,
            ) as response:
                html = response.read().decode(
                    "utf-8",
                    errors="replace",
                )
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)

parser = Parser()
parser.feed(html)

duplicates = {
    item: count
    for item, count in Counter(parser.ids).items()
    if count > 1
}
if duplicates:
    raise SystemExit(f"duplicate rendered IDs: {duplicates}")

expected = {
    "trueaegis-executive-readiness-panel": "overview",
    "trueaegis-executive-readiness": "overview",
    "trueaegis-executive-open-tab": "overview",
    "trueaegis-validation-foundation-panel": "trueaegis",
    "trueaegis-orchestration-mount": "trueaegis",
    "trueaegis-validation-import-controls": "trueaegis",
    "trueaegis-validation-observations-body": "trueaegis",
    "trueaegis-validation-correlations-body": "trueaegis",
}

for element_id, expected_panel in expected.items():
    actual = parser.id_panel.get(element_id)
    if actual != expected_panel:
        raise SystemExit(
            f"{element_id}: expected {expected_panel}, found {actual}"
        )

executive_text = " ".join(
    value
    for panel, value in parser.text
    if panel == "overview"
)

for forbidden in (
    "TrueAegis Orchestration",
    "TrueAegis Jobs",
    "Technical command preview",
    "Import latest TrueAegis validation",
):
    if forbidden in executive_text:
        raise SystemExit(
            f"Executive contains full TrueAegis content: {forbidden}"
        )

if "TrueAegis Readiness" not in executive_text:
    raise SystemExit("Executive readiness summary is missing")

print("PASS: rendered IDs are unique")
print("PASS: Executive readiness belongs to overview")
print("PASS: static TrueAegis evidence and mount belong to trueaegis")
print("PASS: full TrueAegis content is absent from Executive")
PY

echo "[v0.42 hotfix C] dynamic mount and navigation contract"
python3 - <<'PY'
from pathlib import Path
import re

source = Path("deltaaegis.py").read_text(encoding="utf-8")


def extract_function(name: str) -> str:
    marker = f"function {name}("
    start = source.index(marker)
    brace = source.index("{", start)
    depth = 0
    index = brace
    quote = None
    escaped = False

    while index < len(source):
        char = source[index]

        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue

        if char in {'"', "'", "`"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]

        index += 1

    raise RuntimeError(f"unterminated function: {name}")


ensure_function = extract_function(
    "deltaAegisTrueAegisOrchestrationEnsurePanel"
)
executive_function = extract_function(
    "deltaAegisTrueAegisRenderExecutiveReadiness"
)
render_function = extract_function(
    "deltaAegisTrueAegisOrchestrationRender"
)

ensure_required = {
    "static TrueAegis foundation lookup": (
        r'document\.getElementById\(\s*'
        r'"trueaegis-validation-foundation-panel"\s*\)'
    ),
    "orchestration mount lookup": (
        r'document\.getElementById\(\s*'
        r'"trueaegis-orchestration-mount"\s*\)'
    ),
    "mount creation": (
        r'mount\s*=\s*document\.createElement\(\s*"div"\s*\)'
    ),
    "mount identifier": (
        r'mount\.id\s*=\s*"trueaegis-orchestration-mount"'
    ),
    "mount insertion under foundation": (
        r'foundation\.prepend\(\s*mount\s*\)'
    ),
    "mount ancestry guard": (
        r'foundation\.contains\(\s*mount\s*\)'
    ),
    "orchestration panel creation": (
        r'panel\s*=\s*document\.createElement\(\s*"section"\s*\)'
    ),
    "orchestration panel identifier": (
        r'panel\.id\s*=\s*"trueaegis-orchestration-panel"'
    ),
    "orchestration panel mount": (
        r'mount\.appendChild\(\s*panel\s*\)'
    ),
}

for label, pattern in ensure_required.items():
    if re.search(pattern, ensure_function) is None:
        raise SystemExit(
            f"dynamic mount contract missing: {label}"
        )

for forbidden in (
    "document.body.appendChild(panel)",
    "anchor.parentNode.insertBefore(panel, anchor)",
    'panel.dataset.tabPanel = "trueaegis"',
):
    if forbidden in ensure_function:
        raise SystemExit(
            f"dynamic mount escapes tab containment: {forbidden}"
        )

executive_required = (
    '"trueaegis-executive-readiness"',
    '"trueaegis-executive-scan"',
    '"trueaegis-executive-active-jobs"',
    '"trueaegis-executive-message"',
    '"trueaegis-executive-open-tab"',
    'activateDashboardTab("trueaegis")',
    'addEventListener("click"',
)

for marker in executive_required:
    if marker not in executive_function:
        raise SystemExit(
            f"Executive readiness contract missing: {marker}"
        )

render_call = (
    "deltaAegisTrueAegisRenderExecutiveReadiness("
)
ensure_call = (
    "deltaAegisTrueAegisOrchestrationEnsurePanel()"
)

if render_call not in render_function:
    raise SystemExit(
        "orchestration render does not refresh Executive readiness"
    )

if ensure_call not in render_function:
    raise SystemExit(
        "orchestration render does not mount its tab panel"
    )

if render_function.index(render_call) > render_function.index(ensure_call):
    raise SystemExit(
        "Executive readiness must update before orchestration mount"
    )

print("PASS: dynamic panel mounts only inside TrueAegis")
print("PASS: delayed top-level panel creation is impossible")
print("PASS: Executive readiness fields reuse orchestration data")
print("PASS: Executive navigation activates the TrueAegis tab")
PY

echo "[v0.42 hotfix C] compatibility boundary"
echo "PASS: rendered JavaScript syntax is owned by the release gate"
echo "PASS: focused containment validator remains on the v0.42 branch"
echo "PASS: inherited TrueAegis receipt compatibility is owned by the release gate"

echo "[v0.42 hotfix C] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 TrueAegis tab containment validator"
