#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(git branch --show-current)" in
  feature/v0.42-logical-site-scopes|main) ;;
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
    "if lan_mode and not (token or has_active_password_users):",
    "refusing unauthenticated ",
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

with tempfile.TemporaryDirectory(prefix="deltaaegis-v042-lan-") as temp:
    args = module.build_parser().parse_args([
        "--db", str(Path(temp) / "test.db"), "dashboard", "--lan", "--quiet"
    ])
    try:
        module.command_dashboard(args)
    except module.DeltaAegisError as exc:
        if "requires an active password user" not in str(exc):
            raise
    else:
        raise SystemExit("unauthenticated LAN exposure did not fail closed")

print("PASS: parser, binding, and authentication guard")
PY

python3 deltaaegis.py dashboard --help | grep -F -- "--lan" >/dev/null
./tools/validate_v0_42_logical_site_foundation.sh
git diff --check

echo "PASS: DeltaAegis v0.42 dashboard LAN flag validator"
