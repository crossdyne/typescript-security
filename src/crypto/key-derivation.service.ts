import { SecurityUtils } from "../utils/security.utils.js";
import { KdfOptions, SecurityConstants } from "./crypto-options.js";

export class KeyDerivationService{
  readonly ITERATIONS = 600_000;
  readonly KEY_SIZE = 32;

  async deriveKeysFromPassword(identity: string, password: string, salt: Uint8Array, options?: KdfOptions): Promise<{ kek: Uint8Array; authHash: string }> {

    const opts = options ?? KdfOptions.default;
    opts.validate();

    const safeSalt = new Uint8Array(salt);
    const encoder = new TextEncoder();

    const normalizedLogin = identity.trim().toLocaleLowerCase();
    const combinedPassword = `${normalizedLogin}:${password}`;
    const passwordBytes = encoder.encode(combinedPassword);
    const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

    const masterKeyBits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: safeSalt, 
        iterations: opts.pbkdf2Iterations,
        hash: 'SHA-256'
    }, baseKey, SecurityConstants.KeySizeBytes * 8);

    const masterKey = await crypto.subtle.importKey('raw', masterKeyBits, 'HKDF', false, ['deriveBits']);

    const kek = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode('AES-GCM-KEK-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    const authBytes = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode('SERVER-AUTH-HASH-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    return {
      kek: new Uint8Array(kek),
      authHash: SecurityUtils.toBase64(new Uint8Array(authBytes)),
    };
  }
}