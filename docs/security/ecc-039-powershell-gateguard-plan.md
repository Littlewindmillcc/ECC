# ECC-039: PowerShell Coverage for the GateGuard Destructive-Bash Gate

Status: proposed
Owner: security / hooks maintainers
Related: `skills/gateguard/SKILL.md`, `scripts/hooks/gateguard-fact-force.js`,
`docs/security/supply-chain-incident-response.md`

## Problem

GateGuard's destructive-Bash gate (`isDestructiveBash` in
`scripts/hooks/gateguard-fact-force.js`) is the safety net that forces a
fact-force challenge before Claude runs a command like `rm -rf`,
`git reset --hard`, or `drop table`. Its detectors are written for POSIX
shell only:

- `isDestructiveRm` recognizes `rm` and its combined/split `-r`/`-f` flags,
  not PowerShell's `Remove-Item` (or aliases `ri`, `rd`, `del`, `erase`) with
  `-Recurse -Force`.
- `isDestructiveGit` and `commandBasename` already normalize `git.exe` /
  `/usr/bin/git`, so git-based destructive detection (`reset --hard`,
  `push --force`, `clean -f`, …) works identically on Windows — that part is
  not the gap.
- `SHELL_WRAPPERS` (`sh`, `bash`, `zsh`, `dash`, `ksh`) controls which
  wrapper commands get their `-c` payload recursively re-checked
  (`isDestructiveQuoteAware`). It does not include `powershell`, `pwsh`,
  `cmd`, or their `.exe` forms, so a payload passed via
  `powershell -Command "..."` or `cmd /c "..."` is never inspected even
  though the equivalent `bash -c "rm -rf ..."` is.
- `stripQuotedStrings` assumes backslash-escaped quotes
  (`'(?:[^'\\]|\\.)*'`). PowerShell's escape character is the backtick
  (`` ` ``), and it supports here-strings (`@"..."@` / `@'...'@`) that this
  regex does not model. This is a robustness gap in the tokenizer, not
  itself a missed-detection class, but it means quote-stripping can behave
  unpredictably on PowerShell-flavored input.
- `DESTRUCTIVE_SQL_DD` and the `rm`/`git` checks all key off Unix command
  names (`rm`, `dd`, `drop table`). PowerShell/cmd destructive primitives
  (`Remove-Item`, `Clear-Content`, `rd /s /q`, `del /f /s /q`,
  `Set-Content` overwrites) have no equivalent entry.

The gate only fires on `tool_name === 'Bash'`, and on a Windows host running
Claude Code (or another harness this hook is installed into), the Bash tool
can be backed by `powershell.exe`, `pwsh`, or `cmd.exe` rather than a POSIX
shell. That means the same class of destructive command GateGuard is
designed to catch has an unprotected path on the one platform where the
project already invests in first-class support:

- `install.ps1` is the documented Windows install entrypoint.
- `.github/workflows/ci.yml` and `.github/workflows/release.yml` both run a
  `windows-latest` matrix leg (`release.yml` lifecycle job, `ci.yml` main and
  matrix jobs), so Windows is a supported, tested target — not an edge case.
- `skills/windows-desktop-e2e/SKILL.md` and the Windows-specific fixes noted
  in `WORKING-CONTEXT.md` (home-dir/`USERPROFILE` handling, path
  normalization) show the project already treats Windows-only regressions as
  real bugs worth dedicated coverage.

Net effect: a Windows user (or a Windows CI runner) can execute
`Remove-Item -Recurse -Force <path>` or `powershell -Command "Remove-Item -Recurse -Force ..."`
through the Bash tool and GateGuard's destructive gate will not challenge it,
even though the functionally identical `rm -rf` on Linux/macOS is caught.

## Non-Goals

- This is not a full PowerShell/cmd.exe parser. GateGuard's existing POSIX
  handling is intentionally a pragmatic tokenizer, not a shell-grammar
  implementation, and the PowerShell addition should match that scope:
  pattern-match the well-known destructive verbs and flag shapes, not
  execute or fully parse the command.
- Not attempting to detect every obfuscation technique (e.g. dynamic string
  concatenation building `Remove-Item` at runtime, `Invoke-Expression`
  wrapping). Match the existing bar for POSIX: catch the common, direct
  forms; document the rest as a known limitation, same as the SKILL.md
  anti-patterns list already does for shell commands.
- Not changing the gate's fail-open posture. If state cannot be persisted or
  a pattern is ambiguous, GateGuard allows rather than blocks (see
  `allowWithStateWarning`) — the PowerShell work must preserve that.
- Not touching the Edit/Write/MultiEdit fact-forcing gates. Those are
  filesystem-path based and already platform-agnostic.

## Proposed Plan

### Phase 1 — Detection primitives

Add PowerShell/cmd destructive-command recognition alongside the existing
`isDestructiveRm` / `isDestructiveGit`:

- `isDestructiveRemoveItem(tokens)`: match `Remove-Item` and its built-in
  aliases (`ri`, `rd`, `del`, `erase`, `rmdir`) combined with `-Recurse` and
  `-Force` (in either order, case-insensitively — PowerShell parameters are
  case-insensitive and can be abbreviated, e.g. `-Rec -Fo`; match on
  case-insensitive prefix rather than exact flag spelling).
- `isDestructiveCmdDelete(tokens)`: match cmd.exe `rd`/`rmdir` with `/s`
  (recursive) and cmd `del`/`erase` with `/f` `/s` `/q` combinations.
- Extend `commandBasename` handling (already strips path + `.exe`) to also
  recognize `powershell`, `pwsh`, and `cmd` as basenames so they can be added
  to a Windows-equivalent of `SHELL_WRAPPERS`.
- Add a `WINDOWS_SHELL_WRAPPERS` set (`powershell`, `pwsh`, `cmd`) and thread
  it through `isDestructiveQuoteAware` so `-Command`/`-EncodedCommand`/`/c`
  payloads are recursively re-checked the same way `sh -c` / `bash -c` are
  today.
- Reuse `DESTRUCTIVE_SQL_DD` as-is (SQL keywords are shell-agnostic); no
  change needed there.

### Phase 2 — Tokenizer robustness

- Add a PowerShell-aware quote/segment splitter used only as an *additional*
  pass (not a replacement): backtick as escape character, `;` and `|` as
  segment separators (already shared with POSIX), and basic here-string
  recognition (`@"` … `"@`, `@'` … `'@`) so content inside a here-string
  isn't mistaken for command tokens.
- Run both the POSIX and PowerShell detectors unconditionally on every Bash
  tool invocation, regardless of host OS. A false positive here only costs
  an extra fact-force prompt (same cost model the gate already accepts for
  its POSIX checks); it does not break functionality. This avoids needing
  reliable OS/shell detection from hook input alone.

### Phase 3 — Tests

- Mirror the existing coverage style in
  `tests/hooks/gateguard-fact-force.test.js` (2,876 lines of fixtures today)
  with a parallel set of PowerShell/cmd fixtures: bare `Remove-Item -Recurse -Force`,
  alias forms, split/combined flags, `-Command`/`-EncodedCommand` wrapping,
  quoted arguments, and known-safe lookalikes that must NOT trigger (e.g.
  `Remove-Item -Force` without `-Recurse` on a single file, matching how a
  bare `rm -f` is treated today if that's already non-destructive by the
  existing POSIX rule — confirm parity before shipping).
- Extend `tests/ci/gateguard-env-documented.test.js` only if new env vars are
  introduced (current plan does not add any — Phase 1/2 are pattern
  additions, not new toggles).

### Phase 4 — CI validation

- Add a `windows-latest` step (or job) that runs the GateGuard hook test
  suite under real `pwsh`/`cmd`, not just Node-simulated string fixtures, so
  the plan is validated against actual Windows quoting/escaping behavior and
  not only the JS approximation of it. This closes the gap between "the
  tokenizer's model of PowerShell" and "what PowerShell actually does,"
  which is exactly the kind of drift that caused the POSIX quote-stripping
  bypass fixed under GHSA-4v57-ph3x-gf55.
- No changes needed to `.github/workflows/release.yml` itself — its existing
  `windows-latest` lifecycle leg (`lifecycle` job, `matrix.os`) already
  proves the packaged artifact installs on Windows; the new hook-test step
  belongs in `ci.yml` alongside the other hook/unit test steps, not in the
  release pipeline.

### Phase 5 — Docs

- Update `skills/gateguard/SKILL.md`'s "Destructive Bash Gate" section to
  list the Windows-equivalent trigger commands next to the existing
  `rm -rf`, `git reset --hard`, `git push --force`, `drop table` examples.
- Record the shipped state (which patterns are covered, which are explicitly
  out of scope) back into this file once Phases 1-4 land, following the
  "Current External Trigger" / dated-entry convention used in
  `docs/security/supply-chain-incident-response.md`.

## Compatibility

- `ECC_GATEGUARD=off`, `GATEGUARD_DISABLED=1`, and
  `GATEGUARD_BASH_EXTRA_DESTRUCTIVE` remain the existing escape hatches;
  nothing in this plan removes or narrows them.
- No behavior change for existing POSIX destructive detection — this is
  strictly additive.
- `GATEGUARD_EXEMPT_GLOBS` (Edit/Write path exemptions) is unaffected; this
  plan is scoped to the Bash destructive gate only.

## Validation Checklist

- [ ] New PowerShell/cmd destructive patterns land with fixture coverage in
      `tests/hooks/gateguard-fact-force.test.js`.
- [ ] `WINDOWS_SHELL_WRAPPERS` payloads (`-Command`, `-EncodedCommand`, `/c`)
      are recursively checked the same way `sh -c` / `bash -c` are today.
- [ ] A `windows-latest` CI step runs the hook suite (or a targeted subset)
      under real `pwsh`/`cmd`, not only Node string fixtures.
- [ ] `skills/gateguard/SKILL.md` documents the new trigger commands.
- [ ] No change to fail-open behavior, existing env-var semantics, or
      non-Windows detection paths (regression-tested via the existing
      fixture suite).

## When To Escalate

Escalate to a maintainer security review before merging if:

- the new patterns produce false negatives against any command form already
  covered by the POSIX side (parity regression);
- the PowerShell tokenizer pass measurably slows the hook on the common
  (non-destructive) path, since this hook runs on every Bash tool call;
- a reviewer identifies an obfuscation form (e.g. alias chaining,
  `Invoke-Expression` construction) that is cheap to add and low-risk to
  include within the existing pattern-matching scope.
