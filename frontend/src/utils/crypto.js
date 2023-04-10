const PASSWORD_CHARS =
  "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const PBKDF2_SALT_LENGTH = 16;
const AES_GCM_IV_LENGTH = 12;

function clientPasswordHash(str) {
  // Get the string as arraybuffer.
  var buffer = new TextEncoder("utf-8").encode(str);
  return crypto.subtle.digest("SHA-256", buffer).then(function (hashBuffer) {
    const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""); // convert bytes to hex string
    return hashHex;
  });
}

function generateRandomPassword(length) {
  let i32Max = Math.pow(2, 32);
  let randomMax = i32Max - (i32Max & PASSWORD_CHARS.length);
  let r = new Uint32Array(1);

  let randPassword = new Array(length)
    .fill(0)
    .map((x) => {
      do {
        crypto.getRandomValues(r);
      } while (r[0] > randomMax);
      return PASSWORD_CHARS[r[0] % PASSWORD_CHARS.length];
    })
    .join("");

  return randPassword;
}

function getKeyMaterial(password) {
  return window.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
}

function deriveKey(keyMaterial, salt, usage) {
  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    usage
  );
}

async function encryptPassword(masterPassword, plaintext) {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH));
  const keyMaterial = await getKeyMaterial(masterPassword);
  const key = await deriveKey(keyMaterial, salt, ["encrypt"]);

  const aesEncrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext)
  );

  const aesEncryptedArr = new Uint8Array(aesEncrypted);

  let buff = new Uint8Array(
    salt.byteLength + iv.byteLength + aesEncryptedArr.byteLength
  );
  buff.set(salt, 0);
  buff.set(iv, salt.byteLength);
  buff.set(aesEncryptedArr, salt.byteLength + iv.byteLength);

  const base64 = btoa(String.fromCharCode.apply(null, buff));
  return base64;
}

async function decryptPassword(masterPassword, ciphertext) {
  const aseEncryptedArr = Uint8Array.from(atob(ciphertext), (c) =>
    c.charCodeAt(null)
  );
  const salt = aseEncryptedArr.slice(0, PBKDF2_SALT_LENGTH);
  const iv = aseEncryptedArr.slice(
    PBKDF2_SALT_LENGTH,
    PBKDF2_SALT_LENGTH + AES_GCM_IV_LENGTH
  );
  const data = aseEncryptedArr.slice(
    PBKDF2_SALT_LENGTH + AES_GCM_IV_LENGTH,
    aseEncryptedArr.byteLength
  );
  const keyMaterial = await getKeyMaterial(masterPassword);
  const aesKey = await deriveKey(keyMaterial, salt, ["decrypt"]);
  const decryptedContent = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    aesKey,
    data
  );
  return new TextDecoder().decode(decryptedContent);
}

export {
  clientPasswordHash,
  generateRandomPassword,
  encryptPassword,
  decryptPassword,
};
