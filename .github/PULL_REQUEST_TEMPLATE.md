## What and why
<!-- One or two sentences. Link the issue: "Closes #12" -->

## Forensic impact
- [ ] This change does **not** write to, or alter, the source being collected
- [ ] This change does **not** alter what is hashed, or how timestamps and metadata are recorded
- [ ] If it does either, I explain it here and in the README:

## Checklist
- [ ] Tests added or updated, and `uv run pytest -q` passes
- [ ] `uv run ruff check .` passes
- [ ] New collection rules (`rules.py`) have a test with a synthetic fixture tree
- [ ] Failures are **recorded** (a `not_collected` row or an `error`), never silently skipped
- [ ] No real evidence, case folders, device identifiers or personal data in this PR
