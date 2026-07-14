# DeltaAegis Troubleshooter

The repository-aware troubleshooter provides a guided terminal menu, isolated
validator execution, concise health summaries, retained reports, and stable
diagnostic error codes. It reads validators from the selected checkout instead
of carrying a stale embedded copy of historical scripts.

## Start the menu

From the DeltaAegis repository:

```bash
python3 tools/deltaaegis_troubleshooter.py
```

When connected to an interactive terminal, running without arguments opens the
menu. Explicitly open it with:

```bash
python3 tools/deltaaegis_troubleshooter.py --menu
```

Noninteractive execution without arguments runs the highest versioned release
gate present under `tools/`. In the v0.44 repository, that is
`tools/validate_v0_44_release_gate.sh`.

## Menu choices

1. **Quick health check** checks Git state, required commands, related
   processes, validator syntax and references, and the effective database.
2. **Current release diagnostics** runs the current release gate in an isolated
   temporary checkout named `main`.
3. **Current staged diagnostics** runs the current release's `stage*_all.sh`
   checkpoint wrappers.
4. **Specific validator** searches the repository inventory and runs one
   selected validator.
5. **Validator inventory verification** checks Bash syntax and the executable
   validator reference graph.
6. **Latest report** displays the newest retained Markdown report.
7. **Error-code catalog** lists all stable diagnostic codes.
8. **Explain a code** prints its meaning and recommended action.
9. **Advanced diagnostics** exposes static roots, complete historical
   execution, and strict graph auditing.

## Error-code design

Codes use the format `DAE-TRB-NNNN`.

| Range | Area |
|---|---|
| `1000–1999` | Repository, Git state, and command availability |
| `2000–2999` | Validator inventory and syntax |
| `3000–3999` | Validator dependency architecture |
| `4000–4999` | Validator execution and validator contract failures |
| `5000–5999` | Database safety and integrity |
| `6000–6999` | Operating-system and process conflicts |
| `7000–7999` | Report generation |
| `8000–8999` | Operator interaction |

## Error-code reference

| Code | Severity | Meaning | Recommended action |
|---|---|---|---|
| `DAE-TRB-1001` | ERROR | Repository not found | Run from the DeltaAegis checkout or pass `--repo`. |
| `DAE-TRB-1002` | ERROR | `deltaaegis.py` is missing | Restore the checkout or select the correct repository. |
| `DAE-TRB-1003` | ERROR | The active database path could not be resolved | Run `deltaaegis.py paths` and correct the configuration. |
| `DAE-TRB-1101` | ERROR | Git state unavailable | Verify Git and repository metadata access. |
| `DAE-TRB-1102` | WARN | Working tree has changes | Review `git status`; isolated runs use committed `HEAD`. |
| `DAE-TRB-1103` | WARN | Required command unavailable | Install the command needed by the affected validator. |
| `DAE-TRB-2101` | ERROR | Validator inventory unavailable | Restore the `tools/` validator files. |
| `DAE-TRB-2102` | ERROR | Validator Bash syntax failure | Repair the first reported script. |
| `DAE-TRB-3101` | WARN | Executed validator reference missing | Restore the dependency or remove the stale reference. |
| `DAE-TRB-3102` | WARN | Executable dependency cycle | Flatten the recursive suite. |
| `DAE-TRB-4001` | ERROR | Validator returned nonzero | Open the log and resolve the first failing assertion. |
| `DAE-TRB-4002` | ERROR | Validator timed out | Inspect the log and rerun with a justified larger timeout. |
| `DAE-TRB-4003` | ERROR | Validator execution error | Inspect clone, filesystem, command, and environment errors. |
| `DAE-TRB-4101` | ERROR | Candidate branch rejected | Use the current gate or repair obsolete branch policy. |
| `DAE-TRB-4102` | ERROR | Expected source or fixture missing | Restore the file or fix the path assumption. |
| `DAE-TRB-4103` | ERROR | Source syntax failure | Fix the first syntax error before downstream diagnosis. |
| `DAE-TRB-5101` | INFO | Optional database absent | No action unless the deployment expects it. |
| `DAE-TRB-5102` | ERROR | SQLite integrity failure | Stop writers, preserve a copy, and recover safely. |
| `DAE-TRB-5103` | ERROR | SQLite foreign-key violation | Preserve the database and investigate reported rows. |
| `DAE-TRB-5104` | ERROR | Database locked | Let the active writer finish; do not delete lock files. |
| `DAE-TRB-5105` | ERROR | Active database file missing | Confirm the configured path and initialize or restore it. |
| `DAE-TRB-5106` | INFO | Another non-backup database was found | Review it to avoid using an obsolete database. |
| `DAE-TRB-5201` | CRITICAL | Protected database changed | Stop, preserve evidence, and compare with a backup. |
| `DAE-TRB-6101` | ERROR | Permission denied | Check ownership, mode bits, directory access, and mount policy. |
| `DAE-TRB-6102` | ERROR | Address or port in use | Identify and cleanly stop the conflicting listener. |
| `DAE-TRB-6103` | WARN | Related process active | Let work finish or stop it cleanly before intrusive diagnostics. |
| `DAE-TRB-7001` | ERROR | Report creation failed | Check storage, permissions, and `--report-dir`. |
| `DAE-TRB-8001` | INFO | Operator interrupted the run | Review completed logs and rerun when ready. |

## Useful noninteractive commands

```bash
python3 tools/deltaaegis_troubleshooter.py --quick-check
python3 tools/deltaaegis_troubleshooter.py --self-check
python3 tools/deltaaegis_troubleshooter.py --self-check --strict-graph
python3 tools/deltaaegis_troubleshooter.py --codes
python3 tools/deltaaegis_troubleshooter.py --explain-code DAE-TRB-4001
python3 tools/deltaaegis_troubleshooter.py --latest-report
python3 tools/deltaaegis_troubleshooter.py --mode current
python3 tools/deltaaegis_troubleshooter.py --mode stages
python3 tools/deltaaegis_troubleshooter.py --match 'v0_44' --list
```

Use `--json` with `--quick-check` or `--self-check` for machine-readable
output. Validator runs write a Markdown summary, JSON summary, and individual
logs. Each run uses a fresh clone and a temporary `HOME`; the original database
is only inspected through read-only SQLite connections.

## Effective database discovery

The troubleshooter asks DeltaAegis directly for the effective paths:

```bash
python3 deltaaegis.py paths
```

The returned `Database:` value is used for health checks. This preserves the
same environment and command-line configuration recognized by DeltaAegis. An
absent legacy root-level database is not treated as a fault. Other non-backup
`.db` files near the checkout are reported with `DAE-TRB-5106` for operator
review.
