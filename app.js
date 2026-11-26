import {
  decryptNote,
  encryptNote,
  packFragment,
  parseExport,
  serializeExport,
  unpackFragment,
} from "./crypto.js";

const createForm = document.querySelector("#create-form");
const createStatus = document.querySelector("#create-status");
const sharePanel = document.querySelector("#share-panel");
const shareLink = document.querySelector("#share-link");
const copyLinkButton = document.querySelector("#copy-link");
const downloadButton = document.querySelector("#download-export");

const openForm = document.querySelector("#open-form");
const openStatus = document.querySelector("#open-status");
const payloadStatus = document.querySelector("#payload-status");
const importFile = document.querySelector("#import-file");
const openedPanel = document.querySelector("#opened-panel");
const openedMeta = document.querySelector("#opened-meta");
const openedNote = document.querySelector("#opened-note");

let currentPayload = null;
let createdPayload = null;

function setStatus(element, message, success = false) {
  element.textContent = message;
  element.classList.toggle("success", success);
}

function setPayloadStatus(message, ready = false) {
  payloadStatus.textContent = message;
  payloadStatus.classList.toggle("ready", ready);
}

function buildShareUrl(payload) {
  const base = window.location.href.split("#")[0];
  return `${base}${packFragment(payload)}`;
}

function loadFragmentPayload() {
  if (!window.location.hash.startsWith("#s=")) return;
  try {
    currentPayload = unpackFragment(window.location.hash);
    setPayloadStatus("Encrypted note loaded from this link. Enter the passphrase to open it.", true);
  } catch {
    currentPayload = null;
    setPayloadStatus("This link does not contain a valid crypt-share payload.");
  }
}

createForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = createForm.querySelector("button[type='submit']");
  const text = document.querySelector("#note-text").value;
  const passphrase = document.querySelector("#create-passphrase").value;
  const confirmation = document.querySelector("#confirm-passphrase").value;
  const expiryValue = document.querySelector("#expiry").value;
  const burnAfterReading = document.querySelector("#burn-after-reading").checked;

  sharePanel.hidden = true;
  createdPayload = null;

  if (!text.trim()) {
    setStatus(createStatus, "Write a note before encrypting it.");
    return;
  }
  if (!passphrase) {
    setStatus(createStatus, "Choose a passphrase.");
    return;
  }
  if (passphrase !== confirmation) {
    setStatus(createStatus, "The passphrases do not match.");
    return;
  }
  if (expiryValue && new Date(expiryValue).getTime() <= Date.now()) {
    setStatus(createStatus, "Choose an expiry time in the future.");
    return;
  }

  submitButton.disabled = true;
  setStatus(createStatus, "Encrypting locally…");

  try {
    createdPayload = await encryptNote({
      text,
      passphrase,
      expiresAt: expiryValue ? new Date(expiryValue).toISOString() : null,
      burnAfterReading,
    });
    shareLink.value = buildShareUrl(createdPayload);
    sharePanel.hidden = false;
    setStatus(createStatus, "Encrypted. Share the link and passphrase separately.", true);
    document.querySelector("#create-passphrase").value = "";
    document.querySelector("#confirm-passphrase").value = "";
  } catch (error) {
    setStatus(createStatus, error instanceof Error ? error.message : "Encryption failed.");
  } finally {
    submitButton.disabled = false;
  }
});

copyLinkButton.addEventListener("click", async () => {
  if (!shareLink.value) return;
  try {
    await navigator.clipboard.writeText(shareLink.value);
    setStatus(createStatus, "Share link copied.", true);
  } catch {
    shareLink.select();
    document.execCommand("copy");
    setStatus(createStatus, "Share link selected for copying.", true);
  }
});

downloadButton.addEventListener("click", () => {
  if (!createdPayload) return;
  const blob = new Blob([serializeExport(createdPayload)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "crypt-share-note.cryptshare.json";
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
});

importFile.addEventListener("change", async () => {
  const [file] = importFile.files;
  if (!file) return;

  openedPanel.hidden = true;
  try {
    currentPayload = parseExport(await file.text());
    setPayloadStatus(`Encrypted note imported from ${file.name}. Enter the passphrase to open it.`, true);
    setStatus(openStatus, "");
  } catch (error) {
    currentPayload = null;
    setPayloadStatus("That file is not a valid crypt-share export.");
    setStatus(openStatus, error instanceof Error ? error.message : "Import failed.");
  }
});

openForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = openForm.querySelector("button[type='submit']");
  const passphrase = document.querySelector("#open-passphrase").value;

  openedPanel.hidden = true;
  if (!currentPayload) {
    setStatus(openStatus, "Open a crypt-share link or import an encrypted file first.");
    return;
  }
  if (!passphrase) {
    setStatus(openStatus, "Enter the passphrase.");
    return;
  }

  submitButton.disabled = true;
  setStatus(openStatus, "Decrypting locally…");

  try {
    const decrypted = await decryptNote(currentPayload, passphrase);
    if (decrypted.expiresAt && new Date(decrypted.expiresAt).getTime() <= Date.now()) {
      setStatus(openStatus, "This note has expired according to its client-side expiry metadata.");
      return;
    }

    openedNote.textContent = decrypted.text;
    const expiryText = decrypted.expiresAt
      ? `Expires ${new Date(decrypted.expiresAt).toLocaleString()}.`
      : "No expiry set.";
    const burnText = decrypted.burnAfterReading
      ? "Burn-after-reading was requested; the fragment has been removed from this browser."
      : "Burn-after-reading was not requested.";
    openedMeta.textContent = `Created ${new Date(decrypted.createdAt).toLocaleString()}. ${expiryText} ${burnText}`;
    openedPanel.hidden = false;
    setStatus(openStatus, "Decrypted locally.", true);
    document.querySelector("#open-passphrase").value = "";

    if (decrypted.burnAfterReading) {
      window.history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
      currentPayload = null;
      setPayloadStatus("This note was opened and its link fragment was removed from this browser.");
    }
  } catch (error) {
    setStatus(openStatus, error instanceof Error ? error.message : "Decryption failed.");
  } finally {
    submitButton.disabled = false;
  }
});

loadFragmentPayload();
