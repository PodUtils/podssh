**Resume work**

1. Use the existing checkout. The Claude Code hook and the Codex startup
   instructions both use `sh scripts/session-start.sh`. In Antigravity /
   Gemini Cloud, `.agents/environment.json` runs
   `sh scripts/session-start.sh --no-watchers` and
   `sh scripts/cloud-setup.sh --native --dev-tools` on VM startup; run
   `sh scripts/session-start.sh --no-watchers` if needed, start both
   watchers as daemon tasks (`--run-watcher watch` and `--run-watcher runs`),
   and load `. ./scripts/cloud-env.sh` in each shell. If startup reports a
   failure, see [hosted sessions](../docs/hosted-sessions.md).
2. Read [PROGRESS.md](PROGRESS.md) for the work order and
   [the handoff](../docs/HANDOFF.md) for recent CI, drafts, and coordination.
   Read [AGENTS.md](../AGENTS.md) and [the decisions](../docs/decisions.md)
   before changing the selected entry. [INDEX.md](INDEX.md) links to its
   verification steps.
3. From the repository root, run the record checks before editing.

   ```sh
   . ./scripts/cloud-env.sh
   cargo todo check
   python3 scripts/check-repo.py
   ```

4. Review recent CI and issues. Build the target needed for the work in
   [the development guide](../docs/development.md). Run the relevant tests
   and follow [the procedure for a change](../AGENTS.md#6-procedure-for-a-change)
   before pushing.
   For a manual CI run, [try Actions directly first](../docs/development.md#a-run-of-github-actions-asked-of-the-owners-agent).
