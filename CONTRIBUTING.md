# Contributing to logharvest

## Ground rules for a forensic tool
1. **Never modify the source.** Open evidence read-only. If a feature needs to write to the target, say so in the PR.
2. **Never fail silently.** Anything that can't be collected becomes a `not_collected` row or an `error`, with the reason.
3. **Never commit evidence.** No case folders, manifests, audit logs, device identifiers or real logs, in code, tests, issues or PRs.
   Test data must be synthetic and live under `tests/fixtures/`. The *Evidence guard* check enforces this.
4. **Raw first, parsed second.** Keep the original artifact; derived data must be rebuildable from it.

## Workflow
1. Pick a card from **Ready** on the project board (or open an issue using a template). Move it to **In progress**.
   Keep at most **2-3 cards** in progress: finish before starting more.
2. Branch from `main`: `<type>/<issue-number>-<short-slug>`, e.g. `feat/12-windows-rules`, `fix/4-ios-usb`, `ci/21-bandit`.
   Types: `feat`, `fix`, `ci`, `docs`, `test`, `refactor`.
3. Check locally before pushing:
   ```bash
   uv sync --group dev
   uv run ruff check .
   uv run pytest -q
   python3 scripts/evidence_guard.py
   ```
4. Open a pull request (the template has a forensic-impact checklist). Write `Closes #<n>` so the card moves to **Done** on merge.
5. CI must be green on Linux, Windows and macOS before merging.

Commit messages: short imperative subject, e.g. `Add Windows minidump rule`.
If you use Jira, put the ticket key in the branch name and PR title (`LH-12-windows-rules`).

## Definition of done
- Behaviour is covered by a test using a synthetic fixture tree
- CI is green on all three operating systems
- README / rules documentation updated if behaviour changed
- No new silent-skip paths; failures are visible in the viewer

## Adding or changing collection rules
Rules live in `logharvest/rules.py` as `(category, glob)` pairs relative to the source root.
Add a fixture tree to the test that proves the rule matches, and one showing an unreadable directory is recorded and skipped, not fatal.

## Board columns
Backlog -> Ready -> In progress -> In review -> Done. A card is *Ready* when it has a clear outcome and a test idea.

## Security
Report vulnerabilities privately through the repository's **Security** tab ("Report a vulnerability"), not in a public issue.
