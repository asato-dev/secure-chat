/**
 * crypto.js - ブラウザ側ハイブリッド暗号モジュール
 *
 * Web Crypto API（ブラウザ標準）を使用して以下を実装:
 *   - RSA-OAEP鍵ペア生成・保存・読み込み
 *   - AES-CBC暗号化・復号
 *   - RSA-OAEPによるAES鍵の暗号化・復号
 *
 * 設計方針:
 *   - 秘密鍵はlocalStorageのみに保存（サーバーには送らない）
 *   - 公開鍵はサーバーに登録し、誰でも取得可能
 *   - メッセージの暗号化・復号は全てこのファイルで完結
 */

// ================================================================
// RSA鍵ペアの生成・保存・読み込み
// ================================================================

/**
 * RSA-OAEP鍵ペアを生成する。
 * 登録時に一度だけ呼ばれる。
 *
 * @returns {{ publicKeyPem: string, privateKeyJwk: object }}
 */
async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,           // 鍵長2048bit
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true,  // エクスポート可能にする（保存のため）
    ["encrypt", "decrypt"]
  );

  // 公開鍵をPEM形式に変換（サーバーに登録する）
  const publicKeyDer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const publicKeyPem = derToPem(publicKeyDer, "PUBLIC KEY");

  // 秘密鍵をJWK形式に変換（localStorageに保存する）
  const privateKeyJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  return { publicKeyPem, privateKeyJwk };
}

/**
 * 秘密鍵をlocalStorageに保存する。
 * サーバーには送らない。
 */
function savePrivateKey(privateKeyJwk) {
  localStorage.setItem("privateKey", JSON.stringify(privateKeyJwk));
}

/**
 * localStorageから秘密鍵を読み込む。
 */
async function loadPrivateKey() {
  const jwk = JSON.parse(localStorage.getItem("privateKey"));
  if (!jwk) throw new Error("秘密鍵が見つかりません。再登録してください。");

  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"]
  );
}

/**
 * PEM形式の公開鍵文字列をWeb Crypto APIのKeyオブジェクトに変換する。
 * サーバーから取得した相手の公開鍵を使うときに呼ぶ。
 */
async function importPublicKey(publicKeyPem) {
  const der = pemToDer(publicKeyPem);
  return await crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}


// ================================================================
// AES-CBC 暗号化・復号
// ================================================================

/**
 * メッセージをAES-256-CBCで暗号化する。
 *
 * @param {string} plaintext - 平文メッセージ
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @returns {string} Base64( IV[16byte] + 暗号文 )
 */
async function aesEncrypt(plaintext, aesKey) {
  const iv  = crypto.getRandomValues(new Uint8Array(16)); // ランダムIV
  const key = await crypto.subtle.importKey(
    "raw", aesKey,
    { name: "AES-CBC" },
    false,
    ["encrypt"]
  );

  const encoded   = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-CBC", iv },
    key,
    encoded
  );

  // IV + 暗号文 を結合してBase64に変換
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);

  return uint8ToBase64(combined);
}

/**
 * AES-256-CBCで暗号文を復号する。
 *
 * @param {string} encryptedBase64 - Base64( IV[16byte] + 暗号文 )
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @returns {string} 復号された平文
 */
async function aesDecrypt(encryptedBase64, aesKey) {
  const combined = base64ToUint8(encryptedBase64);
  const iv        = combined.slice(0, 16);
  const ciphertext = combined.slice(16);

  const key = await crypto.subtle.importKey(
    "raw", aesKey,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-CBC", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}


// ================================================================
// RSA-OAEP による AES鍵の暗号化・復号
// ================================================================

/**
 * AES鍵を受信者のRSA公開鍵で暗号化する。
 *
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @param {CryptoKey} publicKey - 受信者のRSA公開鍵
 * @returns {string} Base64エンコードされた暗号化AES鍵
 */
async function encryptAESKey(aesKey, publicKey) {
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    aesKey
  );
  return uint8ToBase64(new Uint8Array(encrypted));
}

/**
 * 暗号化されたAES鍵を自分の秘密鍵で復号する。
 *
 * @param {string} encryptedKeyBase64 - Base64エンコードされた暗号化AES鍵
 * @param {CryptoKey} privateKey - 自分のRSA秘密鍵
 * @returns {Uint8Array} 復号されたAES鍵
 */
async function decryptAESKey(encryptedKeyBase64, privateKey) {
  const encrypted = base64ToUint8(encryptedKeyBase64);
  const decrypted = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    encrypted
  );
  return new Uint8Array(decrypted);
}


// ================================================================
// ハイブリッド暗号: メッセージの暗号化・復号
// ================================================================

/**
 * メッセージをハイブリッド暗号化する。
 *
 * 流れ:
 *   ① AES鍵（32byte）をランダム生成
 *   ② メッセージをAES-CBCで暗号化
 *   ③ AES鍵を受信者のRSA公開鍵で暗号化
 *   ④ 暗号化メッセージと暗号化AES鍵を返す
 *
 * @param {string} plaintext - 平文メッセージ
 * @param {string} receiverPublicKeyPem - 受信者のRSA公開鍵（PEM形式）
 * @returns {{ content: string, encrypted_key: string }}
 */
async function hybridEncrypt(plaintext, receiverPublicKeyPem) {
  // ① メッセージごとにランダムなAES鍵を生成
  const aesKey = crypto.getRandomValues(new Uint8Array(32));

  // ② AES-CBCでメッセージを暗号化
  const content = await aesEncrypt(plaintext, aesKey);

  // ③ 受信者の公開鍵でAES鍵を暗号化
  const publicKey     = await importPublicKey(receiverPublicKeyPem);
  const encrypted_key = await encryptAESKey(aesKey, publicKey);

  return { content, encrypted_key };
}

/**
 * 暗号化されたメッセージを復号する。
 *
 * 流れ:
 *   ① localStorageの秘密鍵でAES鍵を復号
 *   ② AES鍵でメッセージを復号
 *
 * @param {string} content - 暗号化されたメッセージ本文
 * @param {string} encrypted_key - 暗号化されたAES鍵
 * @returns {string} 復号された平文
 */
async function hybridDecrypt(content, encrypted_key) {
  const privateKey = await loadPrivateKey();
  const aesKey     = await decryptAESKey(encrypted_key, privateKey);
  return await aesDecrypt(content, aesKey);
}


// ================================================================
// ユーティリティ: PEM ↔ DER 変換 / Base64変換
// ================================================================

function derToPem(der, label) {
  const base64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const lines   = base64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToDer(pem) {
  const base64 = pem
    .replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "")
    .replace(/\s/g, "");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0)).buffer;
}

function uint8ToBase64(uint8) {
  return btoa(String.fromCharCode(...uint8));
}

function base64ToUint8(base64) {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}
