import assert from "node:assert/strict";
import test from "node:test";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  decryptNote,
  encodePayload,
  encryptNote,
  packFragment,
  parseExport,
  serializeExport,
  unpackFragment,
} from "../crypto.js";

const TEST_ITERATIONS = 100_000;

test("encrypts and decrypts a note with metadata", async () => {
  const payload = await encryptNote({
    text: "Meet at the old gate after dark.",
    passphrase: "correct horse battery staple",
    expiresAt: "2030-01-02T03:04:05.000Z",
    burnAfterReading: true,
    createdAt: "2026-11-26T00:00:00.000Z",
    iterations: TEST_ITERATIONS,
  });

  const decrypted = await decryptNote(payload, "correct horse battery staple");

  assert.deepEqual(decrypted, {
    text: "Meet at the old gate after dark.",
    createdAt: "2026-11-26T00:00:00.000Z",
    expiresAt: "2030-01-02T03:04:05.000Z",
    burnAfterReading: true,
  });
});

test("rejects an incorrect passphrase", async () => {
  const payload = await encryptNote({
    text: "Secret note",
    passphrase: "right passphrase",
    iterations: TEST_ITERATIONS,
  });

  await assert.rejects(
    () => decryptNote(payload, "wrong passphrase"),
    /Unable to decrypt/u,
  );
});

test("packs and unpacks a payload in a URL fragment", async () => {
  const payload = await encryptNote({
    text: "Fragment-safe secret",
    passphrase: "fragment passphrase",
    iterations: TEST_ITERATIONS,
  });

  const fragment = packFragment(payload);
  const fromFragment = unpackFragment(fragment);
  const fromUrl = unpackFragment(`https://example.invalid/crypt-share/${fragment}`);

  assert.match(fragment, /^#s=[A-Za-z0-9_-]+$/u);
  assert.deepEqual(fromFragment, payload);
  assert.deepEqual(fromUrl, payload);
  assert.equal(encodePayload(fromFragment), encodePayload(payload));
});

test("detects tampered ciphertext", async () => {
  const payload = await encryptNote({
    text: "Do not alter this note",
    passphrase: "tamper passphrase",
    iterations: TEST_ITERATIONS,
  });

  const ciphertext = base64UrlToBytes(payload.data);
  ciphertext[0] ^= 0xff;
  const tampered = { ...payload, data: bytesToBase64Url(ciphertext) };

  await assert.rejects(
    () => decryptNote(tampered, "tamper passphrase"),
    /Unable to decrypt/u,
  );
});

test("exports and imports an encrypted payload", async () => {
  const payload = await encryptNote({
    text: "Exported secret",
    passphrase: "export passphrase",
    iterations: TEST_ITERATIONS,
  });

  const imported = parseExport(serializeExport(payload));
  const decrypted = await decryptNote(imported, "export passphrase");

  assert.deepEqual(imported, payload);
  assert.equal(decrypted.text, "Exported secret");
});
