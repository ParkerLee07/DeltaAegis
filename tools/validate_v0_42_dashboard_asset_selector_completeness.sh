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

echo "DeltaAegis v0.42 Dashboard Asset Selector Completeness Validator"
echo "================================================================="

echo "[v0.42 asset completeness] source syntax"
python3 -W error::SyntaxWarning -m py_compile deltaaegis.py
echo "PASS: source syntax"

echo "[v0.42 asset completeness] rendered fetch contract"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    "# v0.42 dashboard complete investigation asset inventory.",
    'api(scopedPath("/api/assets?limit=10000"))',
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing asset completeness marker: {marker}"
        )

spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_asset_completeness",
    Path("deltaaegis.py"),
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

page = module.dashboard_index_html()
bounded = 'api(scopedPath("/api/assets?limit=25"))'
complete = 'api(scopedPath("/api/assets?limit=10000"))'

if bounded in page:
    raise SystemExit(
        "rendered dashboard still limits the investigation selector "
        "to 25 assets"
    )

if page.count(complete) != 1:
    raise SystemExit(
        "rendered dashboard must contain exactly one complete "
        "asset inventory fetch"
    )

print("PASS: complete scoped asset inventory fetch")
print("PASS: former 25-row selector limit removed")
PY


echo "[v0.42 asset completeness] numeric IP ordering"
python3 - <<'PY'
from pathlib import Path
import importlib.util
import sys

source = Path("deltaaegis.py").read_text(encoding="utf-8")

required = (
    "# v0.42 numeric dashboard asset-selector ordering.",
    "def dashboard_asset_numeric_ip_sort_key(",
    "ipaddress.ip_address(raw_ip)",
    "int(parsed_ip)",
)

for marker in required:
    if marker not in source:
        raise SystemExit(
            f"missing numeric asset ordering marker: {marker}"
        )

spec = importlib.util.spec_from_file_location(
    "deltaaegis_v042_numeric_asset_order",
    Path("deltaaegis.py"),
)

if spec is None or spec.loader is None:
    raise SystemExit("could not load deltaaegis.py")

module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

rows = [
    {
        "network_scope": "192.168.4.0/24",
        "current_ip": "192.168.4.100",
        "mac_address": "00:00:00:00:00:03",
        "asset_key": "asset-100",
    },
    {
        "network_scope": "192.168.4.0/24",
        "current_ip": "192.168.4.67",
        "mac_address": "00:00:00:00:00:02",
        "asset_key": "asset-67",
    },
    {
        "network_scope": "192.168.4.0/24",
        "current_ip": "192.168.4.9",
        "mac_address": "ff:ff:ff:ff:ff:ff",
        "asset_key": "asset-9",
    },
    {
        "network_scope": "192.168.4.0/24",
        "current_ip": "192.168.4.129",
        "mac_address": "00:00:00:00:00:01",
        "asset_key": "asset-129",
    },
]

ordered = sorted(
    rows,
    key=module.dashboard_asset_numeric_ip_sort_key,
)
ordered_ips = [row["current_ip"] for row in ordered]

expected = [
    "192.168.4.9",
    "192.168.4.67",
    "192.168.4.100",
    "192.168.4.129",
]

if ordered_ips != expected:
    raise SystemExit(
        f"asset selector is not in numeric IP order: {ordered_ips}"
    )

if ordered[0]["mac_address"] != "ff:ff:ff:ff:ff:ff":
    raise SystemExit(
        "MAC address still has precedence over numeric IP ordering"
    )

print("PASS: IPv4 addresses sort numerically")
print("PASS: MAC address no longer controls primary ordering")
print("PASS: 192.168.4.67 sorts before 192.168.4.100")
PY

echo "[v0.42 asset completeness] repository hygiene"
git diff --check
echo "PASS: repository hygiene"

echo "PASS: DeltaAegis v0.42 dashboard asset selector completeness"
