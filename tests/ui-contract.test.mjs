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
  assert.match(js, /zstdCandidatesOverlappingSkipped/);\n  assert.match(js, /sqliteDatabase/);\n  assert.match(js, /quickCheck/);\n  assert.match(js, /completeFrames/);
  assert.match(js, /data-file-name/);
});
test("passphrase is cleared after a capture attempt", () => {
  assert.match(js, /passphraseInput\.value = ""/);
});
test("desktop theme defaults to dark mode", () => {
  assert.match(html, /name="color-scheme" content="dark"/);
  assert.match(css, /color-scheme:dark/);
});
