// Offline opId forgery using the repo's own stable-encryptor algorithm
// (platform/wab/src/wab/server/util/crypt.ts) with the DEFAULT key "fake"
// (server/secrets.ts: getOpEncryptionKey() ?? "fake" when secrets.json absent).
import crypto from "node:crypto";

const stableSalt =
  "82dfa5d0e69f74709499686119a46db3420ffc9e8703e1d2c0dc0b6e4049bd6aa55b84e393f8100e8754f76a2eabf718c58a7c06b4a5774130197dffc593aa1e";
const stableIv = "7b40ddbfd7b334bd9628a2ab624717f6";

export function stableEncrypt(key, value) {
  const stableKey = crypto.pbkdf2Sync(key, stableSalt, 100000, 32, "sha512");
  const cipher = crypto.createCipheriv("aes-256-gcm", stableKey, stableIv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([tag, encrypted]).toString("hex");
}

if (process.argv[1].endsWith("forge_opid.mjs")) {
  const key = process.argv[2];
  const templateJson = process.argv[3];
  console.log(stableEncrypt(key, templateJson));
}
