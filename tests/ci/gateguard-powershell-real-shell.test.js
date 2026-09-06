/**
 * ECC-039 phase 4: validate GateGuard's PowerShell-syntax assumptions
 * against a real PowerShell process, not just the Node-side approximation
 * of its quoting/escaping rules.
 *
 * scripts/hooks/gateguard-fact-force.js's PowerShell-aware tokenizer
 * (powerShellQuoteAwareSegments, stripPowerShellHereStrings) hard-codes a
 * model of how PowerShell parses quotes, backtick escapes, and here-strings.
 * If that model ever drifted from what PowerShell actually does, the gate's
 * fixture tests (all of which run the JS tokenizer against JS string
 * literals) would keep passing while the real detector silently stopped
 * matching real Windows commands -- the same class of gap that caused the
 * POSIX quote-stripping bypass fixed under GHSA-4v57-ph3x-gf55.
 *
 * This test shells out to a real `pwsh`/`powershell` process (whichever is
 * found on PATH) and confirms the parsing assumptions the tokenizer depends
 * on:
 *   1. A trailing backslash right before a closing single-quote is literal,
 *      not an escape (backslash has no escaping role in PowerShell strings).
 *   2. A doubled single-quote ('') inside '...' is a literal single quote.
 *   3. A backtick before a character inside "..." escapes it (e.g. `" is a
 *      literal double-quote).
 *   4. A here-string (@"..."@) preserves its multi-line body verbatim.
 *
 * If no PowerShell executable is found on PATH (expected on most Linux/macOS
 * CI runners, and in this sandbox), the test is skipped rather than failed --
 * it can only validate something where a real shell is available to ask.
 *
 * Run with: node tests/ci/gateguard-powershell-real-shell.test.js
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  \u2713 ${name}`);
    return true;
  } catch (err) {
    console.log(`  \u2717 ${name}`);
    console.log(`    Error: ${err.message}`);
    return false;
  }
}

/**
 * Probe for a working PowerShell executable. Tries `pwsh` (PowerShell 7+,
 * cross-platform) before `powershell` (Windows PowerShell 5.1, Windows-only).
 *
 * @returns {string | null}
 */
function findPowerShell() {
  for (const exe of ['pwsh', 'powershell']) {
    const probe = spawnSync(exe, ['-NoProfile', '-NonInteractive', '-Command', 'exit 0'], {
      encoding: 'utf8',
      timeout: 15000
    });
    if (!probe.error && probe.status === 0) {
      return exe;
    }
  }
  return null;
}

/**
 * Write `scriptContent` to a temp .ps1 file and run it with the given
 * PowerShell executable, returning stdout. Using a script file (rather than
 * an inline -Command string built in Node) avoids Node/bash-level
 * re-quoting entirely -- the bytes on disk are exactly what PowerShell
 * parses.
 *
 * @param {string} exe
 * @param {string} scriptContent
 * @returns {string}
 */
function runScript(exe, scriptContent) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gg-ps-real-'));
  const tmpFile = path.join(tmpDir, 'probe.ps1');
  try {
    fs.writeFileSync(tmpFile, scriptContent, 'utf8');
    const result = spawnSync(exe, ['-NoProfile', '-NonInteractive', '-File', tmpFile], {
      encoding: 'utf8',
      timeout: 15000
    });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      throw new Error(`${exe} exited ${result.status}: ${result.stderr || result.stdout}`);
    }
    return result.stdout || '';
  } finally {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch (_) {
      /* ignore */
    }
  }
}

console.log('GateGuard PowerShell real-shell validation (ECC-039 phase 4)\n');

const exe = findPowerShell();

if (!exe) {
  console.log('  SKIPPED: no pwsh/powershell executable found on PATH.');
  console.log('  This is expected on most Linux/macOS runners; the check only runs where a');
  console.log('  real PowerShell process is available to validate against.\n');
  console.log('Passed: 0');
  console.log('Failed: 0');
  process.exit(0);
}

console.log(`  Using ${exe} on PATH\n`);

if (
  test('a trailing backslash right before a closing single-quote is literal, not an escape', () => {
    const output = runScript(exe, "Write-Output 'C:\\Important Data\\'");
    assert.strictEqual(output.trim(), 'C:\\Important Data\\', 'PowerShell should preserve the trailing backslash as a literal character, not treat it as escaping the closing quote');
  })
)
  passed++;
else failed++;

if (
  test("a doubled single-quote ('') inside '...' is a literal single quote", () => {
    const output = runScript(exe, "Write-Output 'it''s here'");
    assert.strictEqual(output.trim(), "it's here", 'PowerShell should unescape the doubled single-quote to one literal quote');
  })
)
  passed++;
else failed++;

if (
  test('a backtick before a character inside "..." escapes it (e.g. `" is a literal quote)', () => {
    const output = runScript(exe, 'Write-Output "escaped `"quote`" test"');
    assert.strictEqual(output.trim(), 'escaped "quote" test', 'PowerShell should unescape the backtick-quote sequences to literal double-quotes');
  })
)
  passed++;
else failed++;

if (
  test('a here-string (@"..."@) preserves its multi-line body verbatim', () => {
    const output = runScript(exe, ['$msg = @"', 'alpha', 'beta', '"@', 'Write-Output $msg'].join('\n'));
    const lines = output.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    assert.deepStrictEqual(lines, ['alpha', 'beta'], 'the here-string body should contain both lines verbatim');
  })
)
  passed++;
else failed++;

console.log(`\nPassed: ${passed}`);
console.log(`Failed: ${failed}\n`);

if (failed > 0) {
  process.exit(1);
}
