# DeltaAegis v0.43 Performance Baseline

Schema: `deltaaegis-performance-baseline-v1`

Generated: `2026-07-13T17:47:02+00:00`

This baseline measures the unchanged v0.42.2 runtime with synthetic temporary data. It establishes comparison evidence; it does not create performance pass/fail thresholds.

## Environment

| Property | Value |
|---|---|
| Platform | `Linux-7.0.0-27-generic-x86_64-with-glibc2.43` |
| Machine | `x86_64` |
| Logical CPUs | `4` |
| Python | `CPython 3.14.4` |
| SQLite | `3.46.1` |
| Node.js | `v22.22.1` |
| Source tree | `e491383d59c6f93a34001f5e1060d62d3c944405` |
| DeltaAegis runtime | `0.42.2` |

## Synthetic fixture

- Snapshots: **3**
- Assets per snapshot: **240**
- Services per asset: **3**
- Scope: `10.200.0.0/16 synthetic only`
- Real operator data used: **no**

## Measurements

| Measurement | Result |
|---|---:|
| Cold module import (median) | 558.686 ms |
| Fresh schema initialization (median) | 28.078 ms |
| Synthetic database generation | 44.749 ms |
| Synthetic database size | 1007616 bytes |
| Bytes per asset observation | 1399.467 bytes |
| Dashboard summary payload (median) | 5.666 ms |
| Dashboard assets payload (median) | 4.804 ms |
| Markdown report generation | 489.329 ms |
| Markdown report size | 20879 bytes |
| Complete v0.42 release gate | 91.432 s |

SQLite integrity check: `ok`

SQLite foreign-key violations: `0`

Release-gate status: `passed` using a disposable clean local clone.

## Method

1. Load `deltaaegis.py` without starting its CLI.
2. Measure cold imports in separate Python processes.
3. Initialize fresh temporary SQLite databases.
4. Populate deterministic synthetic snapshots, assets, services, and lifecycle rows.
5. Measure representative summary, asset-list, and Markdown-report paths.
6. Run SQLite integrity and foreign-key checks.
7. Run the complete predecessor release gate in a disposable clean local clone.

The v0.43 benchmark generator is intentionally retired from current `main`.
Regenerate both frozen baseline artifacts from the verified archive tag:

```bash
temporary="$(mktemp -d)"
git worktree add --detach "$temporary" v0.44.0
(
  cd "$temporary"
  python3 tools/benchmark_v0_43.py --write
)
git worktree remove --force "$temporary"
```

## Interpretation

- These are descriptive v0.43 baselines, not release thresholds.
- The fixture is synthetic and is created under a temporary directory.
- The later v1 Stage 3–5 candidate derives explicit pass/fail targets from this frozen baseline in `docs/v1-performance-targets.json`; this historical artifact itself remains unchanged evidence.
- Compare future runs only when fixture size, environment, and benchmark schema match.
