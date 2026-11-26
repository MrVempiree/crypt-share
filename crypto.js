// crypt-share pure crypto core.
// This module intentionally has no DOM access so it can run in browsers and Node.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const PAYLOAD_VERSION = 1;
export const DEFAULT_ITERATIONS = 310_000;
export const MIN_ITERATIONS = 100_000;
export const MAX_ITERATIONS = 2_000_000;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const MAX_ENCODED_PAYLOAD_CHARS = 250_000;

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+={0,2}$/;

function getSubtle() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error("WebCrypto is not available in this environment.");
  }
  return subtle;
}

function getRandomValues(bytes) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("Secure random generation is not available in this environment.");
  }
  return globalThis.crypto.getRandomValues(bytes);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

export function bytesToBase64Url(bytes) {
  assert(bytes instanceof Uint8Array, "Expected Uint8Array bytes.");
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64UrlToBytes(value) {
  assert(typeof value === "string" && value.length > 0, "Expected a non-empty base64url string.");
  assert(BASE64URL_PATTERN.test(value), "Invalid base64url data.");

  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("Invalid base64url data.");
  }
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function normalizeExpiry(expiresAt) {
  if (expiresAt === null || expiresAt === undefined || expiresAt === "") return null;
  const date = expiresAt instanceof Date ? expiresAt : new Date(expiresAt);
  assert(!Number.isNaN(date.getTime()), "Expiry must be a valid date.");
  return date.toISOString();
}

function normalizeCreatedAt(createdAt) {
  const date = createdAt === undefined ? new Date() : new Date(createdAt);
  assert(!Number.isNaN(date.getTime()), "Creation time must be a valid date.");
  return date.toISOString();
}

function validateIterations(iterations) {
  assert(Number.isSafeInteger(iterations), "PBKDF2 iterations must be an integer.");
  assert(
    iterations >= MIN_ITERATIONS && iterations <= MAX_ITERATIONS,
    `PBKDF2 iterations must be between ${MIN_ITERATIONS} and ${MAX_ITERATIONS}.`,
  );
  return iterations;
}

export async function deriveKey(passphrase, salt, iterations = DEFAULT_ITERATIONS) {
  assert(typeof passphrase === "string" && passphrase.length > 0, "Passphrase is required.");
  assert(salt instanceof Uint8Array && salt.length === SALT_BYTES, `Salt must be ${SALT_BYTES} bytes.`);
  validateIterations(iterations);

  const subtle = getSubtle();
  const keyMaterial = await subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function additionalData(payload) {
  return encoder.encode(
    `crypt-share:v${payload.v}:PBKDF2-SHA-256:${payload.iterations}:${payload.salt}:${payload.iv}`,
  );
}

export function validatePayload(payload) {
  assert(payload !== null && typeof payload === "object" && !Array.isArray(payload), "Payload must be an object.");
  assert(payload.v === PAYLOAD_VERSION, "Unsupported crypt-share payload version.");
  assert(payload.kdf === "PBKDF2-SHA-256", "Unsupported key derivation function.");
  validateIterations(payload.iterations);

  const salt = base64UrlToBytes(payload.salt);
  const iv = base64UrlToBytes(payload.iv);
  const data = base64UrlToBytes(payload.data);
  assert(salt.length === SALT_BYTES, "Payload salt has an invalid length.");
  assert(iv.length === IV_BYTES, "Payload IV has an invalid length.");
  assert(data.length >= 16, "Payload ciphertext is too short.");

  return {
    v: PAYLOAD_VERSION,
    kdf: "PBKDF2-SHA-256",
    iterations: payload.iterations,
    salt: payload.salt,
    iv: payload.iv,
    data: payload.data,
  };
}

export async function encryptNote({
  text,
  passphrase,
  expiresAt = null,
  burnAfterReading = false,
  createdAt,
  iterations = DEFAULT_ITERATIONS,
} = {}) {
  assert(typeof text === "string", "Note text must be a string.");
  assert(typeof passphrase === "string" && passphrase.length > 0, "Passphrase is required.");
  assert(typeof burnAfterReading === "boolean", "burnAfterReading must be a boolean.");
  validateIterations(iterations);

  const plaintext = {
    text,
    createdAt: normalizeCreatedAt(createdAt),
    expiresAt: normalizeExpiry(expiresAt),
    burnAfterReading,
  };

  const salt = getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = getRandomValues(new Uint8Array(IV_BYTES));
  const payloadWithoutData = {
    v: PAYLOAD_VERSION,
    kdf: "PBKDF2-SHA-256",
    iterations,
    salt: bytesToBase64Url(salt),
    iv: bytesToBase64Url(iv),
  };

  const key = await deriveKey(passphrase, salt, iterations);
  const ciphertext = await getSubtle().encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: additionalData(payloadWithoutData),
    },
    key,
    encoder.encode(JSON.stringify(plaintext)),
  );

  return validatePayload({
    ...payloadWithoutData,
    data: bytesToBase64Url(new Uint8Array(ciphertext)),
  });
}

export async function decryptNote(payload, passphrase) {
  const validPayload = validatePayload(payload);
  assert(typeof passphrase === "string" && passphrase.length > 0, "Passphrase is required.");

  const salt = base64UrlToBytes(validPayload.salt);
  const iv = base64UrlToBytes(validPayload.iv);
  const data = base64UrlToBytes(validPayload.data);
  const key = await deriveKey(passphrase, salt, validPayload.iterations);

  let plaintextBytes;
  try {
    plaintextBytes = await getSubtle().decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: additionalData(validPayload),
      },
      key,
      data,
    );
  } catch {
    throw new Error("Unable to decrypt. Check the passphrase and link.");
  }

  let plaintext;
  try {
    plaintext = JSON.parse(decoder.decode(plaintextBytes));
  } catch {
    throw new Error("Decrypted payload is malformed.");
  }

  assert(typeof plaintext.text === "string", "Decrypted payload is missing note text.");
  assert(typeof plaintext.burnAfterReading === "boolean", "Decrypted payload has invalid metadata.");

  return {
    text: plaintext.text,
    createdAt: normalizeCreatedAt(plaintext.createdAt),
    expiresAt: normalizeExpiry(plaintext.expiresAt),
    burnAfterReading: plaintext.burnAfterReading,
  };
}

export function encodePayload(payload) {
  const validPayload = validatePayload(payload);
  const encoded = bytesToBase64Url(encoder.encode(JSON.stringify(validPayload)));
  assert(encoded.length <= MAX_ENCODED_PAYLOAD_CHARS, "Encrypted payload is too large for a share link.");
  return encoded;
}

export function decodePayload(encoded) {
  assert(typeof encoded === "string" && encoded.length > 0, "Encoded payload is required.");
  assert(encoded.length <= MAX_ENCODED_PAYLOAD_CHARS, "Encoded payload is too large.");

  let payload;
  try {
    payload = JSON.parse(decoder.decode(base64UrlToBytes(encoded.trim())));
  } catch {
    throw new Error("Invalid crypt-share payload.");
  }
  return validatePayload(payload);
}

export function packFragment(payload) {
  return `#s=${encodePayload(payload)}`;
}

export function unpackFragment(input) {
  assert(typeof input === "string" && input.length > 0, "A share link or fragment is required.");

  let fragment = input.trim();
  try {
    const url = new URL(fragment);
    fragment = url.hash;
  } catch {
    // Input may already be a fragment or bare encoded payload.
  }

  const match = fragment.match(/(?:^#|[#&])s=([^&#\s]+)/u);
  const encoded = match ? decodeURIComponent(match[1]) : fragment.replace(/^#/u, "");
  return decodePayload(encoded);
}

export function serializeExport(payload) {
  return `${JSON.stringify(
    {
      format: "crypt-share",
      version: PAYLOAD_VERSION,
      payload: validatePayload(payload),
    },
    null,
    2,
  )}\n`;
}

export function parseExport(text) {
  assert(typeof text === "string" && text.trim().length > 0, "Export file is empty.");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("Export file is not valid JSON.");
  }

  if (parsed?.format === "crypt-share") {
    assert(parsed.version === PAYLOAD_VERSION, "Unsupported crypt-share export version.");
    return validatePayload(parsed.payload);
  }
  return validatePayload(parsed);
}
