import { SecurityUtils } from '../utils/security.utils.js';
import { AesGcmOptions } from './crypto-options.js';

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
      ['encrypt']);

    const encryptedContent = await crypto.subtle.encrypt({ 
        name: 'AES-GCM',
        iv: nonce, 
        tagLength: opts.tagSize * 8},
        cryptoKey,
        plainBytes
    );

    const result = new Uint8Array(opts.nonceSize + encryptedContent.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(encryptedContent), opts.nonceSize);
    
    return SecurityUtils.toBase64(result);
  }

  async decryptedData<T>(encryptedBase64: string, key: Uint8Array, options?: AesGcmOptions): Promise<T | null>{
    if (!encryptedBase64) 
        return null;

    const opts = options ?? AesGcmOptions.default;
    opts.validate();

    const encryptedBytes = SecurityUtils.fromBase64(encryptedBase64);

    if (encryptedBytes.length < opts.nonceSize + opts.tagSize)
        throw new Error(`Недопустимый формат: ожидалось минимум ${opts.nonceSize + opts.tagSize} байт.`);

    const nonce = encryptedBytes.slice(0, opts.nonceSize);
    const ciphertextWithTag = encryptedBytes.slice(opts.nonceSize);

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
         key as BufferSource, 
         'AES-GCM', 
         false,
          ['decrypt']);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt({ 
        name: 'AES-GCM',
        iv: nonce,
        tagLength: opts.tagSize * 8
     },
      cryptoKey,
      ciphertextWithTag);

      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedBuffer);

      return JSON.parse(jsonString) as T;
    } catch (e) {
      console.error('Ошибка дешифрования:', e);
      return null;
    }
  }

  generateRandomBytes = (length = 32): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
}