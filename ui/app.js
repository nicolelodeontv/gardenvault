const invoke = window.__TAURI__?.core?.invoke;
const deviceSelect = document.querySelector("#deviceSelect");
const deviceSummary = document.querySelector("#deviceSummary");
const connectionBadge = document.querySelector("#connectionBadge");
const refreshButton = document.querySelector("#refreshDevices");
const readButton = document.querySelector("#readProfile");
const passphraseInput = document.querySelector("#vaultPassphrase");
const readStatus = document.querySelector("#readStatus");
const resultPanel = document.querySelector("#resultPanel");

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
  } catch (error) {
    setStatus(String(error), "error");
  } finally {
    passphraseInput.value = "";
    refreshButton.disabled = false;
    refreshReadButton();
  }
});
window.addEventListener("DOMContentLoaded", refreshDevices);
