import { SecurityConstants } from "../configurations/security-constants.js";
import { SecurityUtils } from "../utils/security.utils.js";
import { HashAlgorithm } from "./hash-algorithm.js";
import { KdfOptions } from "./kdf-options.js";


export class KeyDerivationService {

  async deriveKeysFromPassword(identity: string, password: string, salt: Uint8Array, options?: KdfOptions): Promise<{ kek: Uint8Array; authHash: string }> {
    const opts = options ?? KdfOptions.default;
    opts.validate();

    const safeSalt = new Uint8Array(salt);
    const encoder = new TextEncoder();

    const normalizedLogin = identity.trim().toLowerCase();
    const combinedPassword = `${normalizedLogin}:${password}`;
    const passwordBytes = encoder.encode(combinedPassword);
    const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

    const masterKeyBits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: safeSalt,
      iterations: opts.pbkdf2Iterations,
      hash: opts.hashAlgorithm
    }, baseKey, SecurityConstants.KeySizeBytes * 8);

    const masterKey = await crypto.subtle.importKey('raw', masterKeyBits, 'HKDF', false, ['deriveBits']);

    const kek = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: opts.hashAlgorithm, salt: new Uint8Array(0), info: encoder.encode('AES-GCM-KEK-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    const authBytes = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: opts.hashAlgorithm, salt: new Uint8Array(0), info: encoder.encode('SERVER-AUTH-HASH-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    return {
      kek: new Uint8Array(kek),
      authHash: SecurityUtils.toBase64(new Uint8Array(authBytes)),
    };
  }

  async deriveAuthHashForSrp(identity: string, password: string, salt: Uint8Array, srpHashAlgorithm: HashAlgorithm, options?: KdfOptions): Promise<Uint8Array> {
    const opts = options ?? KdfOptions.default;
    opts.validate();

    const srpHashSize = srpHashAlgorithm === 'SHA-256' ? 32 : srpHashAlgorithm === 'SHA-384' ? 48 : 64;

    const normalizedLogin = identity.trim().toLowerCase();
    const combinedPassword = `${normalizedLogin}:${password}`;
    const passwordBytes = new TextEncoder().encode(combinedPassword);

    const baseKey = await crypto.subtle.importKey(
      'raw', 
      passwordBytes as BufferSource, 
      'PBKDF2', 
      false, 
      ['deriveBits']
    );

    const masterKeyBits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: opts.pbkdf2Iterations,
      hash: srpHashAlgorithm
    }, baseKey, SecurityConstants.KeySizeBytes * 8);

    const masterKey = await crypto.subtle.importKey(
      'raw', 
      masterKeyBits, 
      'HKDF', 
      false, 
      ['deriveBits']
    );

    const info = new TextEncoder().encode('SRP-AUTH-HASH-v1');
    const authBytes = await crypto.subtle.deriveBits(
      { 
        name: 'HKDF', 
        hash: srpHashAlgorithm, 
        salt: new Uint8Array(0) as BufferSource, 
        info: info as BufferSource 
      },
      masterKey,
      srpHashSize * 8
    );

    return new Uint8Array(authBytes);
  }
}