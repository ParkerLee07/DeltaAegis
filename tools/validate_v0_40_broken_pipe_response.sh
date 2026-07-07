#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "DeltaAegis v0.40 Client-Disconnect Response Validator"
echo "====================================================="

python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

python3 -W error::SyntaxWarning - <<'PY'
from __future__ import annotations

from pathlib import Path
import ast
import importlib.util
import json
import sys


SOURCE = Path("deltaaegis.py")
source = SOURCE.read_text(encoding="utf-8")
tree = ast.parse(source)

functions = [
    node
    for node in tree.body
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    and node.name == "dashboard_json_response"
]

if len(functions) != 1:
    raise SystemExit(
        "expected exactly one dashboard_json_response function, "
        f"found {len(functions)}"
    )

function = functions[0]
handled_names = set()
write_calls = 0

for node in ast.walk(function):
    if isinstance(node, ast.Call):
        target = node.func
        if (
            isinstance(target, ast.Attribute)
            and target.attr == "write"
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "wfile"
        ):
            write_calls += 1

    if isinstance(node, ast.ExceptHandler):
        exception_type = node.type
        if isinstance(exception_type, ast.Tuple):
            for item in exception_type.elts:
                if isinstance(item, ast.Name):
                    handled_names.add(item.id)
        elif isinstance(exception_type, ast.Name):
            handled_names.add(exception_type.id)

if write_calls != 1:
    raise SystemExit(
        "expected exactly one wfile.write call in "
        f"dashboard_json_response, found {write_calls}"
    )

required_exceptions = {
    "BrokenPipeError",
    "ConnectionResetError",
}

if not required_exceptions.issubset(handled_names):
    raise SystemExit(
        "dashboard_json_response does not narrowly handle both "
        "BrokenPipeError and ConnectionResetError"
    )

print("PASS: narrow client-disconnect exception handling is present")


def import_module():
    module_name = "deltaaegis_v040_broken_pipe_validator"
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


class Writer:
    def __init__(self, exception=None):
        self.exception = exception
        self.body = b""

    def write(self, body):
        if self.exception is not None:
            raise self.exception("simulated client disconnect")
        self.body += body
        return len(body)


class Handler:
    def __init__(self, exception=None):
        self.wfile = Writer(exception)
        self.statuses = []
        self.headers = []
        self.ended = False

    def send_response(self, status):
        self.statuses.append(status)

    def send_header(self, name, value):
        self.headers.append((name, value))

    def end_headers(self):
        self.ended = True


module = import_module()
response = module.dashboard_json_response

payload = {
    "ok": True,
    "message": "normal response",
    "count": 2,
}

normal = Handler()
result = response(normal, payload)

if result is not None:
    raise SystemExit("normal response unexpectedly returned a value")

if normal.statuses != [200]:
    raise SystemExit(
        f"normal response status changed: {normal.statuses}"
    )

if not normal.ended:
    raise SystemExit("normal response did not end headers")

decoded = json.loads(normal.wfile.body.decode("utf-8"))

if decoded != payload:
    raise SystemExit(
        f"normal JSON response changed: {decoded!r}"
    )

print("PASS: normal JSON response behavior is unchanged")

for exception_type in (
    BrokenPipeError,
    ConnectionResetError,
):
    handler = Handler(exception_type)

    try:
        response(handler, payload)
    except exception_type as exc:
        raise SystemExit(
            f"{exception_type.__name__} escaped response helper: {exc}"
        )

print("PASS: BrokenPipeError and ConnectionResetError are suppressed")

unexpected = Handler(RuntimeError)

try:
    response(unexpected, payload)
except RuntimeError:
    pass
else:
    raise SystemExit(
        "unexpected RuntimeError was masked; response helper is too broad"
    )

print("PASS: unrelated write failures still propagate")
PY

echo "PASS: DeltaAegis v0.40 client-disconnect response validator"
