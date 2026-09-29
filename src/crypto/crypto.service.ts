import { SecurityUtils } from '../utils/security.utils.js';
import { AesGcmOptions } from './aes-gcm-options.js';
import { CryptoProfileRegistry } from './crypto-profile-registry.js';
import { CryptoProfile } from './crypto-profile.js';
import { CryptoVersion } from './crypto-version.js';

/**
 * AES-GCM encryption/decryption service with JSON serialization.
 * Encrypted output format (Base64): [Nonce][Ciphertext+Tag].
 */
export class CryptoService {

    /**
    * Encrypts a serializable object to a Base64 string.
    * @param dataModel - Object or Uint8Array to encrypt.
    * @param key - A non-extractable CryptoKey obtained via {@link CryptoService.importKey}.
    * @returns Base64-encoded ciphertext with prepended nonce.
    */
    async encryptData<T>(dataModel: T, key: CryptoKey, version: CryptoVersion = CryptoVersion.V1): Promise<string> {
        const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
        const opts: AesGcmOptions = profile.aesGcmOptions;
        opts.validate();

        const encoder = new TextEncoder();
        let jsonString: string;

        if (ArrayBuffer.isView(dataModel) && dataModel.constructor === Uint8Array) {
            jsonString = `"${SecurityUtils.toBase64(dataModel)}"`;
        } else {
            jsonString = JSON.stringify(dataModel);
        }

        const plainBytes = encoder.encode(jsonString);
        const nonce = crypto.getRandomValues(new Uint8Array(opts.nonceSize));

        const encryptedContent = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: opts.tagSize * 8,
            },
            key,
            plainBytes
        );

        const result = new Uint8Array(1 + opts.nonceSize + encryptedContent.byteLength);
        result[0] = version;
        result.set(nonce, 1);
        result.set(new Uint8Array(encryptedContent), 1 + opts.nonceSize);
        return SecurityUtils.toBase64(result);
    }

    /**
    * Decrypts a Base64-encoded ciphertext back to the original object.
    * @param encryptedBase64 - The encrypted data.
    * @param key - A non-extractable CryptoKey obtained via {@link CryptoService.importKey}.
    * @returns Deserialized object, or null if input is empty.
    * @throws If authentication tag mismatch or corrupted data.
    */
    async decryptData<T>(encryptedBase64: string, key: CryptoKey, isBytes: boolean = false): Promise<T | null> {
        if (!encryptedBase64)
            return null;

        const encryptedBytes: Uint8Array<ArrayBufferLike> = SecurityUtils.fromBase64(encryptedBase64);

        const version: CryptoVersion = encryptedBytes[0] as CryptoVersion;
        const payload: Uint8Array<ArrayBuffer> = encryptedBytes.slice(1);

        const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
        const opts: AesGcmOptions = profile.aesGcmOptions;
        opts.validate();

        if (payload.length < opts.nonceSize + opts.tagSize)
            throw new Error(`Invalid format: minimum expected ${opts.nonceSize + opts.tagSize} byte.`);

        const nonce = payload.slice(0, opts.nonceSize);
        const ciphertextWithTag = payload.slice(opts.nonceSize);

        try {

            const decryptedBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: nonce,
                    tagLength: opts.tagSize * 8,
                },
                key,
                ciphertextWithTag
            );

            const decoder = new TextDecoder();
            const jsonString = decoder.decode(decryptedBuffer);
            const parsed = JSON.parse(jsonString);

            if (isBytes && typeof parsed === 'string') {
                return SecurityUtils.fromBase64(parsed) as unknown as T;
            }

            return parsed as T;
        } catch (e) {
            console.error('Decryption error:', e);
            throw new Error("Decryption failed: authentication tag mismatch or corrupted data.");
        }
    }

    /**
    * Generates cryptographically secure random bytes.
    * @param length - Number of bytes (default 32).
    * @returns Uint8Array of random bytes.
    */
    generateRandomBytes = (length = 32): Uint8Array => crypto.getRandomValues(new Uint8Array(length));

    /**
     * Imports raw key bytes into a non-extractable CryptoKey based on the crypto profile version.
     *
     * The resulting key cannot be exported back to raw bytes (extractable: false),
     * ensuring that sensitive key material does not persist in JavaScript-accessible memory.
     * Callers should securely wipe the original raw key buffer immediately after import.
     *
     * @param rawKey - Raw key bytes (e.g. a Data Encryption Key).
     * @param version - Crypto profile version that determines the algorithm and parameters.
     * @param usages - Allowed key operations (e.g. ['encrypt', 'decrypt']).
     * @returns A non-extractable CryptoKey bound to the algorithm defined by the profile.
     */
    async importKey(rawKey: Uint8Array, version: CryptoVersion, usages: KeyUsage[]): Promise<CryptoKey> {
        const profile = CryptoProfileRegistry.getProfile(version);
    
        return await crypto.subtle.importKey(
            'raw',
            rawKey as BufferSource,
            profile.algorithmName, 
            false,
            usages
        );
    }
}