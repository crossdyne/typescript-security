import { SecurityUtils } from '../utils/security.utils.js';
import { AesGcmOptions } from './aes-gcm-options.js';

export class CryptoService {

  async encryptData<T>(dataModel: T, key: Uint8Array, options?: AesGcmOptions): Promise<string> {
    const opts = options ?? AesGcmOptions.default;
    opts.validate();

    const encoder = new TextEncoder();
    let jsonString: string;
    if (dataModel instanceof Uint8Array) {
      jsonString = `"${SecurityUtils.toBase64(dataModel)}"`;
    } else {
      jsonString = JSON.stringify(dataModel);
    }

    const plainBytes = encoder.encode(jsonString);
    const nonce = crypto.getRandomValues(new Uint8Array(opts.nonceSize));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as BufferSource, 
      'AES-GCM',
      false,
      ['encrypt']
    );

    let associatedData: BufferSource = new Uint8Array(0);

    if (opts.associatedData != null){
      associatedData = opts.associatedData as BufferSource;
    }

    const encryptedContent = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: opts.tagSize * 8,
        additionalData: associatedData
      },
      cryptoKey,
      plainBytes
    );

    const result = new Uint8Array(opts.nonceSize + encryptedContent.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(encryptedContent), opts.nonceSize);
    return SecurityUtils.toBase64(result);
  }

  async decryptData<T>(encryptedBase64: string, key: Uint8Array, options?: AesGcmOptions): Promise<T | null> {
    if (!encryptedBase64)
      return null;

    const opts = options ?? AesGcmOptions.default;
    opts.validate();

    const encryptedBytes = SecurityUtils.fromBase64(encryptedBase64);

    if (encryptedBytes.length < opts.nonceSize + opts.tagSize)
      throw new Error(`Invalid format: minimum expected ${opts.nonceSize + opts.tagSize} byte.`);

    const nonce = encryptedBytes.slice(0, opts.nonceSize);
    const ciphertextWithTag = encryptedBytes.slice(opts.nonceSize);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as BufferSource,
      'AES-GCM',
      false,
      ['decrypt']
    );

    try {

      let associatedData: BufferSource = new Uint8Array(0);

      if (opts.associatedData != null){
        associatedData = opts.associatedData as BufferSource;
      }

      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          tagLength: opts.tagSize * 8,
          additionalData: associatedData
        },
        cryptoKey,
        ciphertextWithTag
      );

      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedBuffer);

      return JSON.parse(jsonString) as T;
    } catch (e) {
      console.error('Decryption error:', e);
      throw new Error("Decryption failed: authentication tag mismatch or corrupted data.");
    }
  }

  generateRandomBytes = (length = 32): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
}