const invoke = window.__TAURI__?.core?.invoke;
const deviceSelect = document.querySelector("#deviceSelect");
const deviceSummary = document.querySelector("#deviceSummary");
const connectionBadge = document.querySelector("#connectionBadge");
const refreshButton = document.querySelector("#refreshDevices");
const readButton = document.querySelector("#readProfile");
const passphraseInput = document.querySelector("#vaultPassphrase");
const readStatus = document.querySelector("#readStatus");
const resultPanel = document.querySelector("#resultPanel");
const refreshVaultsButton = document.querySelector("#refreshVaults");
const vaultList = document.querySelector("#vaultList");
const inspectPassphraseInput = document.querySelector("#inspectPassphrase");

function setStatus(message, kind = "") {
  readStatus.textContent = message;
  readStatus.className = `read-status ${kind}`.trim();
}
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function armConfirm(button, confirmLabel, action) {
  const original = button.textContent;
  let armed = false;
  let timer = null;
  const disarm = () => { armed = false; button.textContent = original; button.classList.remove("danger"); if (timer) { clearTimeout(timer); timer = null; } };
  button.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      button.textContent = confirmLabel;
      button.classList.add("danger");
      timer = setTimeout(disarm, 6000);
      return;
    }
    disarm();
    await action();
  });
}
const utf8Bytes = value => new TextEncoder().encode(value).length;
function passphraseProblem(value) {
  if ([...value].length < 12) return "Enter a vault passphrase of at least 12 characters.";
  if (utf8Bytes(value) > 256) return "That passphrase is longer than 256 bytes. Shorten it (non-ASCII characters use more than one byte).";
  return "";
}
function refreshReadButton() {
  const selected = window.gardenVaultDevices?.find(d => d.serial === deviceSelect.value);
  readButton.disabled = !selected || !selected.gameInstalled || !selected.rootAvailable;
}
async function refreshDevices() {
  if (!invoke) {
    deviceSummary.textContent = "The native Tauri bridge is unavailable.";
    connectionBadge.textContent = "NOT READY";
    connectionBadge.className = "status-badge warn";
    return;
  }
  const previousSerial = deviceSelect.value;
  refreshButton.disabled = true;
  deviceSelect.disabled = true;
  deviceSummary.textContent = "Scanning connected LDPlayer instances…";
  connectionBadge.textContent = "SCANNING";
  connectionBadge.className = "status-badge neutral";
  try {
    const devices = await invoke("list_devices");
    window.gardenVaultDevices = devices;
    deviceSelect.innerHTML = "";
    if (devices.length === 0) {
      deviceSelect.innerHTML = '<option value="">No supported LDPlayer found</option>';
      deviceSummary.textContent = "Start LDPlayer (9 or 14) and enable ADB debugging.";
      connectionBadge.textContent = "DISCONNECTED";
      connectionBadge.className = "status-badge warn";
      refreshReadButton();
      return;
    }
    for (const device of devices) {
      const option = document.createElement("option");
      option.value = device.serial;
      option.textContent = `${device.serial} · ${device.gameInstalled ? "Gardenscapes found" : "Game not found"} · ${device.rootAvailable ? "root ready" : "root unavailable"}`;
      deviceSelect.append(option);
    }
    deviceSelect.disabled = false;
    if (previousSerial && devices.some(d => d.serial === previousSerial)) deviceSelect.value = previousSerial;
    const ready = devices.some(d => d.gameInstalled && d.rootAvailable);
    deviceSummary.textContent = `${devices.length} supported emulator(s) detected.`;
    connectionBadge.textContent = ready ? "DEVICE READY" : "CHECK SETUP";
    connectionBadge.className = ready ? "status-badge ok" : "status-badge warn";
    refreshReadButton();
  } catch (error) {
    window.gardenVaultDevices = [];
    deviceSelect.innerHTML = '<option value="">No device available</option>';
    refreshReadButton();
    deviceSummary.textContent = String(error);
    connectionBadge.textContent = "ADB ERROR";
    connectionBadge.className = "status-badge warn";
    setStatus("Check that LDPlayer ADB is available.", "error");
  } finally {
    refreshButton.disabled = false;
  }
}
function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
let previousInspection;

function summarizeFileChanges(before, after) {
  const beforeByName = new Map(before.map(file => [file.name, file]));
  const afterByName = new Map(after.map(file => [file.name, file]));
  const names = [...new Set([...beforeByName.keys(), ...afterByName.keys()])];
  return names.map(name => {
    const oldFile = beforeByName.get(name);
    const newFile = afterByName.get(name);
    if (!oldFile) return `${name} — added (${formatBytes(newFile.sizeBytes)})`;
    if (!newFile) return `${name} — removed (${formatBytes(oldFile.sizeBytes)})`;
    if (oldFile.sha256 === newFile.sha256) return `${name} — identical`;
    return `${name} — changed (${formatBytes(oldFile.sizeBytes)} → ${formatBytes(newFile.sizeBytes)})`;
  }).join("\n");
}

function renderVaults(vaults) {
  if (!vaults.length) {
    vaultList.innerHTML = '<div class="vault-empty"><strong>No encrypted backups yet</strong><p>Create a snapshot from your connected LDPlayer profile to see it here.</p></div>';
    return;
  }
  vaultList.innerHTML = `<div class="vault-items">${vaults.map(vault => {
    const fileName = escapeHtml(vault.fileName);
    const modified = new Date(Number(vault.modifiedAt) * 1000).toLocaleString();
    return `<article class="vault-row">
      <div class="vault-file-icon">◈</div>
      <div class="vault-file-info"><strong>${fileName}</strong><span>${formatBytes(vault.sizeBytes)} · ${escapeHtml(modified)}</span></div>
      <div class="vault-row-actions"><button class="button secondary inspect-vault" type="button" data-file-name="${fileName}">Inspect</button><button class="button secondary export-vault" type="button" data-file-name="${fileName}">Export</button><button class="button secondary restore-vault" type="button" data-file-name="${fileName}">Restore</button><button class="button secondary delete-vault" type="button" data-file-name="${fileName}">Delete</button><span class="vault-row-status" aria-live="polite"></span></div>
    </article>`;
  }).join("")}</div>`;
  for (const button of vaultList.querySelectorAll(".inspect-vault")) {
    button.addEventListener("click", async () => {
      const fileName = button.dataset.fileName;
      const status = button.closest(".vault-row").querySelector(".vault-row-status");
      const passphrase = inspectPassphraseInput?.value || "";
      const inspectProblem = passphraseProblem(passphrase);
      if (inspectProblem) { status.textContent = inspectProblem; status.className = "vault-row-status error"; inspectPassphraseInput?.focus(); return; }
      button.disabled = true; status.textContent = "Decrypting in memory and analyzing binary structure…"; status.className = "vault-row-status";
      try {
        const report = await invoke("inspect_vault", { fileName, passphrase });
        const devicePullAttested = report.captureIntegrity === "device-copy-pull-sha256-v1";
        const legacyDeviceAttested = report.captureIntegrity === "device-stat-sha256-v1";
        const deviceCaptureAttested = devicePullAttested || legacyDeviceAttested;
        const captureIntegritySummary = devicePullAttested
          ? "Capture transfer attestation: source and device temp copy matched; adb pull size and SHA-256 matched the device copy."
          : legacyDeviceAttested
            ? "Capture transfer attestation: legacy device stat and SHA-256 matched the received stream."
            : "Capture transfer attestation: unavailable for this older vault; only the encrypted vault payload is being integrity-checked.";
        const missingOptionalSummary = deviceCaptureAttested && (report.missingOptionalFiles || []).length
          ? `Optional files not present: ${report.missingOptionalFiles.join(", ")}. No file entry was stored.`
          : "";
        const details = report.files.map(file => {
          const embedded = (file.embeddedSignatures || []).join("\n  ");
          const headerWords = (file.plxeHeaderWords || []).join("\n  ") || "No PLXE header fields found";
          const decodedSizeMatches = (file.plxeHeaderDecodedSizeMatches || []).join("\n  ") || "No PLXE words matched a successfully decoded output size";
          const transform = file.transformDiagnostics || {};
          const blocks = transform.blockProfile || {};
          const blockRows = blocks.blocks || [];
          const shownBlockRows = blockRows.length <= 32 ? blockRows : [...blockRows.slice(0, 16), ...blockRows.slice(-16)];
          const blockLines = shownBlockRows.map(block =>
            `#${block.blockIndex} @ 0x${Number(block.offsetBytes).toString(16).toUpperCase()} · ${Number(block.sizeBytes).toLocaleString()} B · entropy ${Number(block.entropyBitsPerByte).toFixed(3)} · printable ${Number(block.printableAsciiPercent).toFixed(1)}% · zero ${Number(block.zeroBytePercent).toFixed(1)}% · unique ${block.uniqueByteValues}`
          ).join("\n  ");
          const omittedBlocks = Math.max(0, blockRows.length - shownBlockRows.length);
          const blockSummary = `4 KiB block profile: ${blocks.blockCount || 0} blocks · entropy min/mean/max ${Number(blocks.minEntropyBitsPerByte || 0).toFixed(3)} / ${Number(blocks.meanEntropyBitsPerByte || 0).toFixed(3)} / ${Number(blocks.maxEntropyBitsPerByte || 0).toFixed(3)} · mean printable ${Number(blocks.meanPrintableAsciiPercent || 0).toFixed(1)}% · mean zero ${Number(blocks.meanZeroBytePercent || 0).toFixed(1)}%
  ${blockLines || "No blocks"}
  ${omittedBlocks ? `… ${omittedBlocks} middle blocks analyzed but omitted from this compact view.` : ""}`;
          const xor = transform.singleByteXor || {};
          const xorCandidates = (xor.topCandidates || []).map(candidate =>
            `0x${Number(candidate.keyByte).toString(16).padStart(2, "0").toUpperCase()} · score ${Number(candidate.textScore).toFixed(1)} · printable ${Number(candidate.printableAsciiPercent).toFixed(1)}%${candidate.sqliteMagicMatch ? " · SQLite magic match" : ""}`
          ).join("\n  ") || "No candidates";
          const xorSummary = `Single-byte XOR sweep: ${Number(xor.sampledBytes || 0).toLocaleString()} sampled bytes · SQLite magic key: ${xor.sqliteMagicXorKey == null ? "none" : `0x${Number(xor.sqliteMagicXorKey).toString(16).padStart(2, "0").toUpperCase()}`}
  ${xorCandidates}
  ${xor.note || ""}`;
          const repeating = transform.repeatingKeyXor || {};
          const repeatingCandidates = [...(repeating.candidates || [])].sort((a, b) => Number(b.textScore) - Number(a.textScore)).slice(0, 8).map(candidate =>
            `length ${candidate.keyLength} · key ${candidate.keyHex} · score ${Number(candidate.textScore).toFixed(1)} · printable ${Number(candidate.printableAsciiPercent).toFixed(1)}% · letters/spaces ${Number(candidate.lettersAndSpacesPercent).toFixed(1)}%`
          ).join("\n  ") || "No candidates";
          const repeatingSummary = `Repeating-key XOR: lengths ${repeating.minKeyLength || 1}–${repeating.maxKeyLength || 32} tested (${repeating.keyLengthsTested || 0}) · ${Number(repeating.sampledBytes || 0).toLocaleString()} bytes in ${repeating.sampleSegments || 0} contiguous sample window(s)
  Top heuristic candidates:
  ${repeatingCandidates}
  ${repeating.note || ""}`;
          const skippableFrames = (file.zstdSkippableFrames || []).map(frame =>
            `Skippable frame @ 0x${Number(frame.offset).toString(16).toUpperCase()} · id ${frame.frameId} · ${frame.status}
Magic: ${frame.magicHex} · declared payload: ${formatBytes(frame.declaredPayloadBytes)} · available: ${formatBytes(frame.availablePayloadBytes)}
${frame.note}`
          ).join("\n\n") || "No Zstandard skippable-frame signatures found";
          const describeSqlite = database => {
            if (!database) return "No SQLite header detected";
            const wal = database.wal;
            return `SQLite: ${database.status} · opened read-only: ${database.openedReadOnly}
SQLite version: ${database.sqliteVersion || "not available"} · quick_check: ${database.quickCheck || "not available"}
Schema objects: ${(database.schemaObjects || []).join(", ") || "none listed"}
WAL: ${wal ? wal.status : "not checked"} · present: ${wal ? wal.present : "unknown"} · size: ${wal ? formatBytes(wal.sizeBytes) : "unknown"}
WAL validation: ${wal?.checksumValidation || "unvalidated"} · page size: ${wal?.pageSizeBytes ?? "unknown"} · complete frames: ${wal?.completeFrames ?? "unknown"} · salt matches: ${wal?.saltMatchingFrames ?? "unknown"} · trailing bytes: ${wal?.trailingBytes ?? "unknown"}
${database.note || ""} ${wal?.note || ""}`;
          };
          const sqlite = describeSqlite(file.sqliteDatabase);
          const zstd = (file.zstdProbes || []).map(probe => {
            const frameSize = probe.compressedFrameSizeBytes == null ? "unknown" : formatBytes(probe.compressedFrameSizeBytes);
            const declared = probe.frameContentSizeBytes == null ? "not declared" : formatBytes(probe.frameContentSizeBytes);
            const trailing = probe.trailingBytesAfterFrame == null ? "unknown" : formatBytes(probe.trailingBytesAfterFrame);
            const observed = probe.observedOutputBytes == null ? "none (no accepted output)" : formatBytes(probe.observedOutputBytes);
            const decoded = probe.decoded
              ? `Decoded output: ${formatBytes(probe.decoded.sizeBytes)} · ${probe.decoded.detectedFormat}
Decoded SHA-256: ${probe.decoded.sha256}
Decoded header (32 bytes): ${probe.decoded.signatureHex}
Decoded entropy: whole ${Number(probe.decoded.entropyBitsPerByte).toFixed(3)} · first 256 ${Number(probe.decoded.header256EntropyBitsPerByte).toFixed(3)} · remainder ${Number(probe.decoded.bodyEntropyAfter256BitsPerByte).toFixed(3)}
Decoded signatures: ${(probe.decoded.embeddedSignatures || []).join(", ")}\n${describeSqlite(probe.decoded.sqliteDatabase)}`
              : "";
            return `Zstandard @ 0x${Number(probe.offset).toString(16).toUpperCase()}: ${probe.status}
Frame size: ${frameSize} · declared output: ${declared} · observed output: ${observed} · trailing bytes: ${trailing}
${probe.note}
${decoded}`;
          }).join("\n\n") || "No Zstandard candidates found";
          return `${file.name}: ${file.detectedFormat} · vault payload SHA-256 matches stored metadata
Size: ${Number(file.sizeBytes).toLocaleString()} bytes · mod 16: ${file.sizeMod16} · mod 512: ${file.sizeMod512} · mod 4096: ${file.sizeMod4096}
${blockSummary}
${xorSummary}
${repeatingSummary}
Entropy (whole): ${Number(file.entropyBitsPerByte).toFixed(3)} bits/byte · ${file.entropyAssessment}
Entropy (first 256): ${Number(file.header256EntropyBitsPerByte).toFixed(3)} · remainder: ${Number(file.bodyEntropyAfter256BitsPerByte).toFixed(3)} · tail 256: ${Number(file.tail256EntropyBitsPerByte).toFixed(3)}
Printable ASCII: ${Number(file.printableAsciiPercent).toFixed(1)}% · zero bytes: ${Number(file.zeroBytePercent).toFixed(1)}% · unique byte values: ${file.uniqueByteValues}/256
Header (first 32 bytes): ${file.signatureHex}
Tail (last 32 bytes): ${file.tailHex}
Embedded signatures (whole file):
  ${embedded || "No signature hits"}
PLXE little-endian words:
  ${headerWords}
PLXE words matching decoded sizes:
  ${decodedSizeMatches}
Zstandard candidates: ${file.zstdCandidatesAttempted} attempted / ${file.zstdCandidatesTotal} signatures · ${file.zstdCandidatesSkipped} skipped by 32-attempt cap · ${file.zstdCandidatesOverlappingSkipped} nested/overlapping signatures skipped
${zstd}`;
        }).join("\n\n");
        const baseline = previousInspection;
        const comparison = baseline && baseline.fileName !== fileName
          ? `Compared with last inspected backup (${baseline.fileName})\n${summarizeFileChanges(baseline.files, report.files)}\n\n`
          : "Inspect a different backup to compare its captured files with this one.\n\n";
        previousInspection = {
          fileName,
          files: report.files.map(({ name, sizeBytes, sha256 }) => ({ name, sizeBytes, sha256 })),
        };
        status.textContent = `${comparison}${captureIntegritySummary}${missingOptionalSummary ? `\n${missingOptionalSummary}` : ""}\n\n${details}${report.identicalFiles ? " · All captured files are byte-for-byte identical." : ""}`;
        status.className = "vault-row-status success";
        if (inspectPassphraseInput) inspectPassphraseInput.value = "";
      } catch (error) { status.textContent = String(error); status.className = "vault-row-status error"; }
      finally { button.disabled = false; }
    });
  }
  for (const button of vaultList.querySelectorAll(".restore-vault")) {
    const fileName = button.dataset.fileName;
    const status = button.closest(".vault-row").querySelector(".vault-row-status");
    armConfirm(button, "Confirm restore", async () => {
      const serial = deviceSelect.value;
      const passphrase = inspectPassphraseInput?.value || "";
      const problem = passphraseProblem(passphrase);
      if (!serial) { status.textContent = "Select a connected LDPlayer device first."; status.className = "vault-row-status error"; return; }
      if (problem) { status.textContent = problem; status.className = "vault-row-status error"; inspectPassphraseInput?.focus(); return; }
      button.disabled = true;
      status.textContent = "Backing up the current game state, then restoring. Keep the game closed…";
      status.className = "vault-row-status";
      try {
        const result = await invoke("restore_profile", { serial, fileName, passphrase });
        const names = result.restoredFiles.map(file => file.name).join(", ");
        const walNote = result.removedStaleWal ? " The old WAL file was removed." : "";
        const message = `Restored ${names}.${walNote} Previous state saved to ${result.safetyBackupPath}`;
        status.textContent = message;
        status.className = "vault-row-status success";
        setStatus(message, "success");
        if (inspectPassphraseInput) inspectPassphraseInput.value = "";
        await refreshVaults();
      } catch (error) {
        status.textContent = String(error);
        status.className = "vault-row-status error";
      } finally {
        button.disabled = false;
      }
    });
  }
  for (const button of vaultList.querySelectorAll(".delete-vault")) {
    const fileName = button.dataset.fileName;
    const status = button.closest(".vault-row").querySelector(".vault-row-status");
    armConfirm(button, "Confirm delete", async () => {
      button.disabled = true;
      try {
        await invoke("delete_vault", { fileName });
        await refreshVaults();
      } catch (error) {
        status.textContent = String(error);
        status.className = "vault-row-status error";
        button.disabled = false;
      }
    });
  }
  for (const button of vaultList.querySelectorAll(".export-vault")) {
    button.addEventListener("click", async () => {
      const fileName = button.dataset.fileName;
      const status = button.closest(".vault-row").querySelector(".vault-row-status");
      button.disabled = true;
      status.textContent = "Choose export location…";
      status.className = "vault-row-status";
      try {
        const exportedPath = await invoke("export_vault", { fileName });
        status.textContent = exportedPath ? `Exported to ${exportedPath}` : "Export cancelled.";
        status.className = exportedPath ? "vault-row-status success" : "vault-row-status";
      } catch (error) {
        status.textContent = String(error);
        status.className = "vault-row-status error";
      } finally {
        button.disabled = false;
      }
    });
  }
}
async function refreshVaults() {
  if (!invoke || !vaultList) return;
  refreshVaultsButton.disabled = true;
  vaultList.innerHTML = '<div class="vault-empty">Loading encrypted backups…</div>';
  try {
    const vaults = await invoke("list_vaults");
    renderVaults(vaults);
  } catch (error) {
    vaultList.innerHTML = `<div class="vault-empty error">${escapeHtml(error)}</div>`;
  } finally {
    refreshVaultsButton.disabled = false;
  }
}
function renderResult(result) {
  const cards = result.files.map(file => `<div class="file-card"><small>CAPTURED FILE</small><strong>${escapeHtml(file.name)}</strong><small>${Number(file.sizeBytes).toLocaleString()} bytes</small><code>Device SHA-256 matched: ${escapeHtml(file.sha256)}</code></div>`).join("");
  const missingOptional = (result.missingOptionalFiles || []).length
    ? `<div class="path-line">Not present: ${(result.missingOptionalFiles || []).map(escapeHtml).join(", ")}. No file entry was stored.</div>`
    : "";
  resultPanel.className = "panel result-panel";
  resultPanel.innerHTML = `<div style="width:100%"><div class="section-head result-top"><div><h3>Encrypted snapshot created</h3><p>Device ${escapeHtml(result.deviceSerial)} · ${escapeHtml(result.capturedAt)}</p></div><span class="status-badge ok">ENCRYPTED</span></div><div class="result-grid">${cards}</div><div class="path-line">Device source and temporary copy matched; ADB pull size and SHA-256 matched before encryption.</div>${missingOptional}<div class="path-line">Vault file: <code>${escapeHtml(result.vaultPath)}</code></div></div>`;
}
refreshButton.addEventListener("click", refreshDevices);
deviceSelect.addEventListener("change", refreshReadButton);
readButton.addEventListener("click", async () => {
  const serial = deviceSelect.value;
  const passphrase = passphraseInput.value;
  if (!serial) { setStatus("Select a connected LDPlayer device.", "error"); return; }
  const problem = passphraseProblem(passphrase);
  if (problem) { setStatus(problem, "error"); passphraseInput.focus(); return; }
  readButton.disabled = true;
  refreshButton.disabled = true;
  setStatus("Verifying game state and encrypting snapshot…");
  try {
    const result = await invoke("read_profile", { serial, passphrase });
    renderResult(result);
    passphraseInput.value = "";
    setStatus("Profile captured and encrypted locally.", "success");
    await refreshVaults();
  } catch (error) {
    setStatus(String(error), "error");
  } finally {
    refreshButton.disabled = false;
    refreshReadButton();
  }
});
const adbStatus = document.querySelector("#adbStatus");
const adbPathInput = document.querySelector("#adbPath");
const adbMessage = document.querySelector("#adbMessage");
function setAdbMessage(message, kind = "") {
  adbMessage.textContent = message;
  adbMessage.className = `adb-status ${kind}`.trim();
}
async function refreshAdbSettings() {
  if (!invoke || !adbStatus) return;
  try {
    const settings = await invoke("get_adb_settings");
    adbStatus.textContent = `Using ${settings.resolvedPath} (${settings.source}).`;
    if (settings.configuredPath && !adbPathInput.value) adbPathInput.value = settings.configuredPath;
  } catch (error) {
    adbStatus.textContent = String(error);
  }
}
async function saveAdbPath(path) {
  setAdbMessage("Checking that this is Android Debug Bridge…");
  try {
    await invoke("set_adb_path", { path });
    if (!path) adbPathInput.value = "";
    setAdbMessage(path ? "ADB path saved." : "Using auto-detected ADB.", "success");
    await refreshAdbSettings();
    await refreshDevices();
  } catch (error) {
    setAdbMessage(String(error), "error");
  }
}
document.querySelector("#adbSave")?.addEventListener("click", () => {
  const value = adbPathInput.value.trim();
  if (!value) { setAdbMessage("Enter the full path to adb.exe, or choose Use auto-detect.", "error"); return; }
  saveAdbPath(value);
});
document.querySelector("#adbReset")?.addEventListener("click", () => saveAdbPath(null));
document.querySelector("#adbTest")?.addEventListener("click", async () => {
  setAdbMessage("Running adb version…");
  try { setAdbMessage(await invoke("test_adb"), "success"); }
  catch (error) { setAdbMessage(String(error), "error"); }
});
document.querySelector("#adbBrowse")?.addEventListener("click", async () => {
  try {
    const chosen = await invoke("browse_adb");
    if (chosen) { adbPathInput.value = chosen; setAdbMessage("Selected. Choose Save to use it.", ""); }
  } catch (error) { setAdbMessage(String(error), "error"); }
});
refreshVaultsButton?.addEventListener("click", refreshVaults);
document.querySelector("#copyDiagnostics")?.addEventListener("click", async () => {
  const devices = (window.gardenVaultDevices || []).map(d => `${d.serial} gameInstalled=${d.gameInstalled} rootAvailable=${d.rootAvailable}`);
  const text = [
    document.querySelector(".version")?.textContent || "GardenVault",
    `Time: ${new Date().toISOString()}`,
    `Connection: ${connectionBadge.textContent}`,
    `Summary: ${deviceSummary.textContent}`,
    `Devices: ${devices.length ? devices.join("; ") : "none"}`,
    `Last status: ${readStatus.textContent}`
  ].join("\n");
  try {
    await navigator.clipboard.writeText(text);
    setStatus("Diagnostics copied. They contain no passphrases or save data.", "success");
  } catch {
    setStatus("Could not access the clipboard.", "error");
  }
});
document.querySelector("#backupsNav")?.addEventListener("click", () => vaultList?.scrollIntoView({ behavior: "smooth", block: "center" }));
window.addEventListener("DOMContentLoaded", () => {
  refreshDevices();
  refreshVaults();
  refreshAdbSettings();
});
