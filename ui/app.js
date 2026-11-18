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
      <div class="vault-row-actions"><button class="button secondary export-vault" type="button" data-file-name="${fileName}">Export</button><span class="vault-row-status" aria-live="polite"></span></div>
    </article>`;
  }).join("")}</div>`;
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
