/**
 * Supported cryptographic profile versions.
 * V1: baseline (PBKDF2-HMAC-SHA256, AES-256-GCM, 12-byte nonce, 16-byte tag).
 * Append new members sequentially; never change existing values.
 */
export enum CryptoVersion {

    /** Version 1 — initial profile. */
    V1 = 1,
}