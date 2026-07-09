# DeltaAegis Troubleshooter

The standalone troubleshooter provides a guided terminal menu, isolated
validator execution, concise health summaries, retained reports, and stable
diagnostic error codes.

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

Noninteractive execution without arguments preserves the original behavior and
runs the current embedded release gate.

## Menu choices

1. **Quick health check** checks Git state, required commands, related
   processes, embedded validator integrity, and both known database locations.
2. **Current release diagnostics** runs the newest embedded release gate in an
   isolated temporary `$HOME/DeltaAegis` clone.
3. **v0.42 component diagnostics** runs the component validators referenced by
   the embedded v0.42 component suite.
4. **Specific validator** searches the embedded inventory and runs one selected
   validator.
5. **Bundle verification** checks sealed hashes, Bash syntax, and the advisory
   historical reference graph.
6. **Latest report** displays the newest retained Markdown report.
7. **Error-code catalog** lists all stable diagnostic codes.
8. **Explain a code** prints its meaning and recommended action.
9. **Advanced diagnostics** exposes all static-reference-free validators,
   complete historical execution, and strict graph auditing.

## Error-code design

Codes use the format `DAE-TRB-NNNN`.

| Range | Area |
|---|---|
| `1000–1999` | Repository, Git state, and command availability |
| `2000–2999` | Embedded validator integrity |
| `3000–3999` | Historical dependency and reference architecture |
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
| `DAE-TRB-1101` | ERROR | Git state unavailable | Verify Git and repository metadata access. |
| `DAE-TRB-1102` | WARN | Working tree has changes | Review `git status`; commit, stash, or intentionally preserve changes. |
| `DAE-TRB-1103` | WARN | Required command unavailable | Install the command needed by the affected validator. |
| `DAE-TRB-2101` | ERROR | Embedded payload hash mismatch | Regenerate from a trusted repository state. |
| `DAE-TRB-2102` | ERROR | Embedded Bash syntax failure | Repair the validator and regenerate the bundle. |
| `DAE-TRB-3101` | WARN | Historical validator reference missing | Audit during validator-architecture cleanup. |
| `DAE-TRB-3102` | WARN | Static dependency cycle | Distinguish execution from documentation references and flatten true recursion. |
| `DAE-TRB-4001` | ERROR | Validator returned nonzero | Open the log and resolve the first failing assertion. |
| `DAE-TRB-4002` | ERROR | Validator timed out | Inspect the log and rerun with a justified larger timeout. |
| `DAE-TRB-4003` | ERROR | Validator execution error | Inspect clone, filesystem, command, and environment errors. |
| `DAE-TRB-4101` | ERROR | Candidate branch rejected | Use a supported release branch or correct the validator. |
| `DAE-TRB-4102` | ERROR | Expected source or fixture missing | Restore the file or fix the path assumption. |
| `DAE-TRB-4103` | ERROR | Source syntax failure | Fix the first syntax error before downstream diagnosis. |
| `DAE-TRB-5101` | INFO | Optional database absent | No action unless the deployment expects it. |
| `DAE-TRB-5102` | ERROR | SQLite integrity failure | Stop writers, preserve a copy, and recover safely. |
| `DAE-TRB-5103` | ERROR | SQLite foreign-key violation | Preserve the database and investigate reported rows. |
| `DAE-TRB-5104` | ERROR | Database locked | Let the active writer finish; do not delete lock files. |
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
python3 tools/deltaaegis_troubleshooter.py --codes
python3 tools/deltaaegis_troubleshooter.py --explain-code DAE-TRB-4001
python3 tools/deltaaegis_troubleshooter.py --latest-report
python3 tools/deltaaegis_troubleshooter.py --mode current
python3 tools/deltaaegis_troubleshooter.py --match 'v0_42'
```

Use `--json` with `--quick-check` or `--self-check` for machine-readable
output. Every menu-driven validator run writes `diagnostic_codes.json` beside
the normal Markdown and JSON reports.
