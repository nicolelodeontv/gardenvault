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
      deviceSummary.textContent = "Start LDPlayer 14 and enable ADB debugging.";
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
    const ready = devices.some(d => d.gameInstalled && d.rootAvailable);
    deviceSummary.textContent = `${devices.length} supported emulator(s) detected.`;
    connectionBadge.textContent = ready ? "DEVICE READY" : "CHECK SETUP";
    connectionBadge.className = ready ? "status-badge ok" : "status-badge warn";
    refreshReadButton();
  } catch (error) {
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
      <div class="vault-row-actions"><button class="button secondary inspect-vault" type="button" data-file-name="${fileName}">Inspect</button><button class="button secondary export-vault" type="button" data-file-name="${fileName}">Export</button><span class="vault-row-status" aria-live="polite"></span></div>
    </article>`;
  }).join("")}</div>`;
  for (const button of vaultList.querySelectorAll(".inspect-vault")) {
    button.addEventListener("click", async () => {
      const fileName = button.dataset.fileName;
      const status = button.closest(".vault-row").querySelector(".vault-row-status");
      const passphrase = inspectPassphraseInput?.value || "";
      if (passphrase.length < 12) { status.textContent = "Enter the vault passphrase above."; status.className = "vault-row-status error"; inspectPassphraseInput?.focus(); return; }
      button.disabled = true; status.textContent = "Decrypting in memory and analyzing binary structure…"; status.className = "vault-row-status";
      try {
        const report = await invoke("inspect_vault", { fileName, passphrase });
        const details = report.files.map(file => {
          const embedded = (file.embeddedSignatures || []).join("\n  ");
          const headerWords = (file.plxeHeaderWords || []).join("\n  ") || "No PLXE header fields found";
          const zstd = (file.zstdProbes || []).map(probe => {
            const frameSize = probe.compressedFrameSizeBytes == null ? "unknown" : formatBytes(probe.compressedFrameSizeBytes);
            const declared = probe.frameContentSizeBytes == null ? "not declared" : formatBytes(probe.frameContentSizeBytes);
            const trailing = probe.trailingBytesAfterFrame == null ? "unknown" : formatBytes(probe.trailingBytesAfterFrame);
            const decoded = probe.decoded
              ? `Decoded output: ${formatBytes(probe.decoded.sizeBytes)} · ${probe.decoded.detectedFormat}
Decoded SHA-256: ${probe.decoded.sha256}
Decoded header (32 bytes): ${probe.decoded.signatureHex}
Decoded entropy: whole ${Number(probe.decoded.entropyBitsPerByte).toFixed(3)} · first 256 ${Number(probe.decoded.header256EntropyBitsPerByte).toFixed(3)} · remainder ${Number(probe.decoded.bodyEntropyAfter256BitsPerByte).toFixed(3)}
Decoded signatures: ${(probe.decoded.embeddedSignatures || []).join(", ")}`
              : "";
            return `Zstandard @ 0x${Number(probe.offset).toString(16).toUpperCase()}: ${probe.status}
Frame size: ${frameSize} · declared output: ${declared} · trailing bytes: ${trailing}
${probe.note}
${decoded}`;
          }).join("\n\n") || "No Zstandard candidates found";
          return `${file.name}: ${file.detectedFormat} · SHA-256 verified
Size: ${Number(file.sizeBytes).toLocaleString()} bytes · mod 16: ${file.sizeMod16} · mod 512: ${file.sizeMod512} · mod 4096: ${file.sizeMod4096}
Entropy (whole): ${Number(file.entropyBitsPerByte).toFixed(3)} bits/byte · ${file.entropyAssessment}
Entropy (first 256): ${Number(file.header256EntropyBitsPerByte).toFixed(3)} · remainder: ${Number(file.bodyEntropyAfter256BitsPerByte).toFixed(3)} · tail 256: ${Number(file.tail256EntropyBitsPerByte).toFixed(3)}
Printable ASCII: ${Number(file.printableAsciiPercent).toFixed(1)}% · zero bytes: ${Number(file.zeroBytePercent).toFixed(1)}% · unique byte values: ${file.uniqueByteValues}/256
Header (first 32 bytes): ${file.signatureHex}
Tail (last 32 bytes): ${file.tailHex}
Embedded signatures (whole file):
  ${embedded || "No signature hits"}
PLXE little-endian words:
  ${headerWords}
Zstandard probes: ${file.zstdCandidatesAttempted}/${file.zstdCandidatesTotal} attempted · ${file.zstdCandidatesSkipped} skipped by safety cap
${zstd}`;
        }).join("\n\n");        status.textContent = `${details}${report.identicalFiles ? " · Both captured files are identical." : ""}`;
        status.className = "vault-row-status success";
      } catch (error) { status.textContent = String(error); status.className = "vault-row-status error"; }
      finally { button.disabled = false; if (inspectPassphraseInput) inspectPassphraseInput.value = ""; }
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
  const cards = result.files.map(file => `<div class="file-card"><small>CAPTURED FILE</small><strong>${escapeHtml(file.name)}</strong><small>${Number(file.sizeBytes).toLocaleString()} bytes</small><code>SHA-256: ${escapeHtml(file.sha256)}</code></div>`).join("");
  resultPanel.className = "panel result-panel";
  resultPanel.innerHTML = `<div style="width:100%"><div class="section-head result-top"><div><h3>Encrypted snapshot created</h3><p>Device ${escapeHtml(result.deviceSerial)} · ${escapeHtml(result.capturedAt)}</p></div><span class="status-badge ok">ENCRYPTED</span></div><div class="result-grid">${cards}</div><div class="path-line">Vault file: <code>${escapeHtml(result.vaultPath)}</code></div></div>`;
}
refreshButton.addEventListener("click", refreshDevices);
deviceSelect.addEventListener("change", refreshReadButton);
readButton.addEventListener("click", async () => {
  const serial = deviceSelect.value;
  const passphrase = passphraseInput.value;
  if (!serial) { setStatus("Select a connected LDPlayer device.", "error"); return; }
  if (passphrase.length < 12) { setStatus("Enter a vault passphrase of at least 12 characters.", "error"); passphraseInput.focus(); return; }
  readButton.disabled = true;
  refreshButton.disabled = true;
  setStatus("Verifying game state and encrypting snapshot…");
  try {
    const result = await invoke("read_profile", { serial, passphrase });
    renderResult(result);
    setStatus("Profile captured and encrypted locally.", "success");
    await refreshVaults();
  } catch (error) {
    setStatus(String(error), "error");
  } finally {
    passphraseInput.value = "";
    refreshButton.disabled = false;
    refreshReadButton();
  }
});
refreshVaultsButton?.addEventListener("click", refreshVaults);
document.querySelector("#backupsNav")?.addEventListener("click", () => vaultList?.scrollIntoView({ behavior: "smooth", block: "center" }));
window.addEventListener("DOMContentLoaded", () => {
  refreshDevices();
  refreshVaults();
});
