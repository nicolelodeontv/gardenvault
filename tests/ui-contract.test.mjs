import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const html = await readFile(new URL("../ui/index.html", import.meta.url), "utf8");
const js = await readFile(new URL("../ui/app.js", import.meta.url), "utf8");
const css = await readFile(new URL("../ui/app.css", import.meta.url), "utf8");

test("dashboard exposes device discovery and profile capture controls", () => {
  assert.match(html, /id="refreshDevices"/);
  assert.match(html, /id="deviceSelect"/);
  assert.match(html, /id="readProfile"/);
  assert.match(html, /id="vaultPassphrase"/);
});
test("frontend invokes only the fixed native profile commands", () => {
  assert.match(js, /invoke\("list_devices"\)/);
  assert.match(js, /invoke\("read_profile"/);
  assert.match(js, /invoke\("list_vaults"\)/);
  assert.match(js, /invoke\("export_vault"/);
  assert.match(js, /invoke\("inspect_vault"/);
  assert.match(js, /entropyAssessment/);
  assert.match(js, /zstdProbes/);
  assert.match(js, /plxeHeaderWords/);
  assert.match(js, /plxeHeaderDecodedSizeMatches/);
  assert.doesNotMatch(js, /localStorage|sessionStorage/);
});
test("encrypted backup browser exposes refresh and export controls", () => {
  assert.match(html, /id="refreshVaults"/);
  assert.match(html, /id="vaultList"/);
  assert.match(html, /id="inspectPassphrase"/);
  assert.match(js, /detectedFormat/);
  assert.match(js, /entropyBitsPerByte/);
  assert.match(js, /printableAsciiPercent/);
  assert.match(js, /embeddedSignatures/);
  assert.match(js, /header256EntropyBitsPerByte/);
  assert.match(js, /tail256EntropyBitsPerByte/);
  assert.match(js, /sizeMod4096/);
  assert.match(js, /tailHex/);
  assert.match(js, /frameContentSizeBytes/);
  assert.match(js, /observedOutputBytes/);
  assert.match(js, /zstdCandidatesOverlappingSkipped/);
  assert.match(js, /zstdSkippableFrames/);
  assert.match(js, /checksumValidation/);
  assert.match(js, /unvalidated/);
  assert.match(js, /sqliteDatabase/);
  assert.match(js, /quickCheck/);
  assert.match(js, /completeFrames/);
  assert.match(js, /data-file-name/);
});
test("passphrase is cleared after a successful capture and kept for retry on failure", () => {
  assert.match(js, /renderResult\(result\);\s*passphraseInput\.value = ""/);
  assert.doesNotMatch(js, /finally \{\s*passphraseInput\.value = ""/);
});
test("desktop theme defaults to dark mode", () => {
  assert.match(html, /name="color-scheme" content="dark"/);
  assert.match(css, /color-scheme:dark/);
});

test("capture UI distinguishes device attestation from vault-only integrity and labels absent optional files", () => {
  assert.match(js, /device-stat-sha256-v1/);
  assert.match(js, /device-copy-pull-sha256-v1/);
  assert.match(js, /adb pull size and SHA-256 matched the device copy/);
  assert.match(js, /legacy device stat and SHA-256 matched the received stream/);
  assert.match(js, /Optional files not present/);
  assert.match(js, /Device SHA-256 matched/);
  assert.doesNotMatch(js, /SHA-256 verified/);
});

test("inspector exposes bounded 4 KiB block and XOR heuristic diagnostics", () => {
  assert.match(js, /blockProfile/);
  assert.match(js, /singleByteXor/);
  assert.match(js, /repeatingKeyXor/);
  assert.match(js, /SQLite magic key/);
  assert.match(js, /middle blocks analyzed but omitted/);
});

test("capture success panel describes binary-safe adb pull verification", () => {
  assert.match(js, /Device source and temporary copy matched; ADB pull size and SHA-256 matched before encryption/);
  assert.doesNotMatch(js, /Device-reported stat size and SHA-256 matched the received bytes before encryption/);
});

test("restore and delete require a second confirming click", () => {
  assert.match(js, /armConfirm\(button, "Confirm restore"/);
  assert.match(js, /armConfirm\(button, "Confirm delete"/);
  assert.match(js, /invoke\("restore_profile", \{ serial, fileName, passphrase \}\)/);
  assert.match(js, /invoke\("delete_vault", \{ fileName \}\)/);
});
test("restore reports the pre-restore safety backup", () => {
  assert.match(js, /safetyBackupPath/);
});
test("device selection survives a refresh in-session without browser storage", () => {
  assert.match(js, /const previousSerial = deviceSelect\.value/);
  assert.match(js, /d\.serial === previousSerial/);
  assert.doesNotMatch(js, /localStorage|sessionStorage/);
});
test("diagnostics copy exposes status only, never passphrase fields", () => {
  const start = js.indexOf('"#copyDiagnostics"');
  const block = js.slice(start, js.indexOf('].join', start));
  assert.match(block, /connectionBadge/);
  assert.doesNotMatch(block, /passphraseInput|inspectPassphraseInput|vaultPassphrase/);
});

test("ADB settings expose save, test, reset and browse through fixed commands", () => {
  for (const id of ["adbPath", "adbSave", "adbTest", "adbReset", "adbBrowse"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(js, /invoke\("get_adb_settings"\)/);
  assert.match(js, /invoke\("set_adb_path", \{ path \}\)/);
  assert.match(js, /invoke\("test_adb"\)/);
  assert.match(js, /invoke\("browse_adb"\)/);
  assert.match(css, /\.adb-settings/);
});

test("backup row actions use an equal-width grid and the passphrase field has a visible border", () => {
  assert.match(css, /\.vault-row-actions\{display:grid;grid-template-columns:repeat\(2,minmax\(92px,1fr\)\)/);
  assert.match(css, /\.vault-tools input\{border-color:#2c4758/);
});
