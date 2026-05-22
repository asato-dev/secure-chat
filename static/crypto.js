/**
 * crypto.js - ブラウザ側ハイブリッド暗号モジュール
 *
 * Web Crypto API（ブラウザ標準）を使用して以下を実装:
 *   - RSA-OAEP鍵ペア生成・保存・読み込み
 *   - AES-GCM暗号化・復号（v2: CBC→GCMに変更。改ざん検知付き）
 *   - RSA-OAEPによるAES鍵の暗号化・復号
 *   - PBKDF2によるRSA秘密鍵のバックアップ・復元（v2新機能）
 *
 * 設計方針:
 *   - 秘密鍵はlocalStorageに保存し、さらにPBKDF2でバックアップ
 *   - 公開鍵はサーバーに登録し、誰でも取得可能
 *   - メッセージの暗号化・復号は全てこのファイルで完結
 *
 * v1からの変更点:
 *   - AES-CBC → AES-GCM（IVが16byte→12byte、改ざん検知が追加）
 *   - PBKDF2によるRSA秘密鍵の暗号化バックアップ機能を追加
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
// AES-GCM 暗号化・復号
// v1のAES-CBCから変更:
//   - IVサイズ: 16byte → 12byte（GCMの最適サイズ）
//   - 改ざん検知タグが自動で付与されるためデータ改ざんを検知できる
//   - TLS 1.3でも採用されている現代の標準
// ================================================================

/**
 * メッセージをAES-256-GCMで暗号化する。
 *
 * @param {string} plaintext - 平文メッセージ
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @returns {string} Base64( IV[12byte] + 暗号文+認証タグ )
 */
async function aesEncrypt(plaintext, aesKey) {
  const iv  = crypto.getRandomValues(new Uint8Array(12)); // GCMは12byteが最適
  const key = await crypto.subtle.importKey(
    "raw", aesKey,
    { name: "AES-GCM" },  // v1: AES-CBC → v2: AES-GCM
    false,
    ["encrypt"]
  );

  const encoded   = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, // GCMは認証タグ(16byte)を暗号文末尾に自動付与
    key,
    encoded
  );

  // IV + 暗号文（+認証タグ） を結合してBase64に変換
  const combined = new Uint8Array(iv.byteLength + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.byteLength);

  return uint8ToBase64(combined);
}

/**
 * AES-256-GCMで暗号文を復号する。
 *
 * @param {string} encryptedBase64 - Base64( IV[12byte] + 暗号文+認証タグ )
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @returns {string} 復号された平文
 */
async function aesDecrypt(encryptedBase64, aesKey) {
  const combined   = base64ToUint8(encryptedBase64);
  const iv         = combined.slice(0, 12);  // v1: 16byte → v2: 12byte
  const ciphertext = combined.slice(12);

  const key = await crypto.subtle.importKey(
    "raw", aesKey,
    { name: "AES-GCM" },  // v1: AES-CBC → v2: AES-GCM
    false,
    ["decrypt"]
  );

  // GCMは復号時に認証タグを自動検証する。改ざんされていれば例外を投げる
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}


// ================================================================
// RSA-OAEP による AES鍵の暗号化・復号
// ================================================================

/**
 * AES鍵をRSA公開鍵で暗号化する。
 *
 * @param {Uint8Array} aesKey - 32byteのAES鍵
 * @param {CryptoKey} publicKey - RSA公開鍵
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
 * メッセージをハイブリッド暗号化する（送信者・受信者の両方に対応）。
 *
 * 【重要】AES鍵は1つだけ生成し、受信者用と送信者用の両方の公開鍵で
 * 同じAES鍵を暗号化する。こうすることで：
 *   - 受信者は encrypted_key         を自分の秘密鍵で復号して本文を読める
 *   - 送信者は encrypted_key_for_sender を自分の秘密鍵で復号して本文を読める
 *
 * 流れ:
 *   ① AES鍵（32byte）をランダム生成
 *   ② メッセージをAES-GCMで暗号化（content）
 *   ③ 同じAES鍵を受信者の公開鍵で暗号化（encrypted_key）
 *   ④ 同じAES鍵を送信者自身の公開鍵でも暗号化（encrypted_key_for_sender）
 *   ⑤ content / encrypted_key / encrypted_key_for_sender を返す
 *
 * @param {string} plaintext              - 平文メッセージ
 * @param {string} receiverPublicKeyPem   - 受信者のRSA公開鍵（PEM形式）
 * @param {string} senderPublicKeyPem     - 送信者自身のRSA公開鍵（PEM形式）
 * @returns {{ content: string, encrypted_key: string, encrypted_key_for_sender: string }}
 */
async function hybridEncrypt(plaintext, receiverPublicKeyPem, senderPublicKeyPem) {
  // ① メッセージごとにランダムなAES鍵を1つだけ生成
  const aesKey = crypto.getRandomValues(new Uint8Array(32));

  // ② 同じAES鍵でメッセージを暗号化（contentは1つ）
  const content = await aesEncrypt(plaintext, aesKey);

  // ③ 受信者の公開鍵で同じAES鍵を暗号化
  const receiverPublicKey = await importPublicKey(receiverPublicKeyPem);
  const encrypted_key     = await encryptAESKey(aesKey, receiverPublicKey);

  // ④ 送信者自身の公開鍵でも同じAES鍵を暗号化
  const senderPublicKey          = await importPublicKey(senderPublicKeyPem);
  const encrypted_key_for_sender = await encryptAESKey(aesKey, senderPublicKey);

  return { content, encrypted_key, encrypted_key_for_sender };
}

/**
 * 暗号化されたメッセージを復号する。
 *
 * 流れ:
 *   ① localStorageの秘密鍵でAES鍵を復号
 *   ② AES鍵でメッセージを復号
 *
 * @param {string} content       - 暗号化されたメッセージ本文
 * @param {string} encrypted_key - 暗号化されたAES鍵（自分宛のもの）
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


// ================================================================
// PBKDF2 による RSA秘密鍵のバックアップ・復元（v2新機能）
//
// 目的: 機種変更・キャッシュ削除後も秘密鍵を復元できるようにする
// 仕組み: ログインパスワードからAES鍵を派生させ、RSA秘密鍵を暗号化して
//         サーバーに保存。サーバーはパスワードも派生鍵も知らない。
// ================================================================

/**
 * ログインパスワードからRSA秘密鍵保護用のAES鍵を派生させる。
 *
 * @param {string} password    - ユーザーのログインパスワード
 * @param {Uint8Array} salt    - ランダムなSalt（16byte）
 * @returns {CryptoKey} AES-GCM用の鍵オブジェクト
 */
async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();

  // パスワード文字列をPBKDF2用のKeyオブジェクトに変換
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  // PBKDF2で10万回ハッシュ化し256bitのAES-GCM鍵を生成
  // 10万回繰り返すことで総当たり攻撃を現実的でなくする
  return await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * RSA秘密鍵をログインパスワードから派生した鍵で暗号化する。
 * 登録時に呼ばれ、暗号化済み秘密鍵をサーバーにバックアップする。
 *
 * @param {object} privateKeyJwk - JWK形式のRSA秘密鍵
 * @param {string} password      - ユーザーのログインパスワード
 * @returns {string} Base64( Salt[16byte] + IV[12byte] + 暗号文 )
 */
async function encryptPrivateKeyWithPassword(privateKeyJwk, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // ランダムSalt
  const iv   = crypto.getRandomValues(new Uint8Array(12)); // ランダムIV

  const key     = await deriveKeyFromPassword(password, salt);
  const encoded = new TextEncoder().encode(JSON.stringify(privateKeyJwk));

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  // Salt + IV + 暗号文 を1つのBase64文字列にまとめて返す
  // 復号時にSaltとIVが必要なため、暗号文と一緒に保存する
  const combined = new Uint8Array(
    salt.byteLength + iv.byteLength + encrypted.byteLength
  );
  combined.set(salt, 0);
  combined.set(iv,   salt.byteLength);
  combined.set(new Uint8Array(encrypted), salt.byteLength + iv.byteLength);

  return uint8ToBase64(combined);
}

/**
 * 暗号化されたRSA秘密鍵をログインパスワードで復号する。
 * 機種変更後のログイン時に呼ばれ、秘密鍵を復元する。
 *
 * @param {string} encryptedBase64 - encryptPrivateKeyWithPasswordの戻り値
 * @param {string} password        - ユーザーのログインパスワード
 * @returns {object} JWK形式のRSA秘密鍵
 */
async function decryptPrivateKeyWithPassword(encryptedBase64, password) {
  const combined = base64ToUint8(encryptedBase64);

  // 先頭から順にSalt・IV・暗号文を切り出す
  const salt       = combined.slice(0, 16);
  const iv         = combined.slice(16, 28);
  const ciphertext = combined.slice(28);

  // 同じパスワード + 同じSalt → 必ず同じAES鍵が再現される
  const key = await deriveKeyFromPassword(password, salt);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return JSON.parse(new TextDecoder().decode(decrypted));
}
