#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(git branch --show-current)" in
  feature/v0.42-logical-site-scopes|hotfix/v0.42.1-followup|release/v0.42.1|release/v0.42.2|main) ;;
  *) echo "FAIL: unexpected branch"; exit 1 ;;
esac

python3 -W error::SyntaxWarning -m py_compile deltaaegis.py

python3 - <<'PY'
from pathlib import Path
import ast
import importlib.util
import sys
import tempfile

text = Path("deltaaegis.py").read_text(encoding="utf-8")
n = ast.parse(text)
required = (
    "# v0.42 dashboard LAN binding",
    '"--lan"',
    'bind_host = "0.0.0.0" if lan_mode else args.host',
    "non_loopback_bind = not dashboard_bind_host_is_loopback(bind_host)",
    "if non_loopback_bind and not (token or has_active_password_users):",
    "refusing unauthenticated network exposure",
    "network exposure",
)
for item in required:
    if item not in text:
        raise SystemExit(f"missing marker: {item}")

fn = next(x for x in n.body if isinstance(x, ast.FunctionDef) and x.name == "command_dashboard")
assigns = [
    x for x in ast.walk(fn)
    if isinstance(x, ast.Assign)
    and any(isinstance(t, ast.Name) and t.id == "server_address" for t in x.targets)
]
if len(assigns) != 1 or "bind_host" not in ast.unparse(assigns[0].value):
    raise SystemExit("server_address does not use bind_host")

spec = importlib.util.spec_from_file_location("da_v042_lan", Path("deltaaegis.py").resolve())
module = importlib.util.module_from_spec(spec)
sys.modules["da_v042_lan"] = module
spec.loader.exec_module(module)
sys.modules.pop("da_v042_lan", None)

local_args = module.build_parser().parse_args(["dashboard"])
lan_args = module.build_parser().parse_args(["dashboard", "--lan"])
if local_args.host != "127.0.0.1" or local_args.lan:
    raise SystemExit("local-only default changed")
if not lan_args.lan or lan_args.port != 8090:
    raise SystemExit("--lan parser behavior is incorrect")
for host in ("127.0.0.1", "::1", "localhost"):
    if not module.dashboard_bind_host_is_loopback(host):
        raise SystemExit(f"loopback host rejected: {host}")
for host in ("0.0.0.0", "::", "192.168.1.10"):
    if module.dashboard_bind_host_is_loopback(host):
        raise SystemExit(f"non-loopback host accepted: {host}")

with tempfile.TemporaryDirectory(prefix="deltaaegis-v042-lan-") as temp:
    cases = (
        ["dashboard", "--lan", "--quiet"],
        ["dashboard", "--host", "0.0.0.0", "--no-require-login", "--quiet"],
    )
    for index, dashboard_args in enumerate(cases):
        args = module.build_parser().parse_args([
            "--db", str(Path(temp) / f"test-{index}.db"), *dashboard_args
        ])
        try:
            module.command_dashboard(args)
        except module.DeltaAegisError as exc:
            if "non-loopback dashboard bind requires" not in str(exc):
                raise
        else:
            raise SystemExit("unauthenticated network exposure did not fail closed")

print("PASS: parser, binding, and authentication guard")
PY

python3 deltaaegis.py dashboard --help | grep -F -- "--lan" >/dev/null
git diff --check

echo "PASS: DeltaAegis v0.42 dashboard LAN flag validator"
