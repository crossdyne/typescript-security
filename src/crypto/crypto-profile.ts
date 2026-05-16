import { AesGcmOptions } from "./aes-gcm-options.js";
import { CryptoVersion } from "./crypto-version.js";
import { KdfOptions } from "./kdf-options.js";

/**
 * Immutable cryptographic profile bundling version, KDF, and AES-GCM settings.
 * Thread-safe after construction.
 */
export class CryptoProfile {

    /** Protocol version, influencing KDF defaults, cipher modes, and serialization. */
    readonly version: CryptoVersion;

    /** Key derivation parameters (iterations, hash algorithm). */
    readonly kdfOptions: KdfOptions;

    /** AES-GCM encryption parameters (nonce size, tag size, AAD). */
    readonly aesGcmOptions: AesGcmOptions;

    /**
     * Creates a new CryptoProfile.
     * @param params - Object containing version, kdfOptions, aesGcmOptions.
     */
    constructor(params: {
        version: CryptoVersion;
        kdfOptions: KdfOptions;
        aesGcmOptions: AesGcmOptions;
    }) {
        this.version = params.version;
        this.kdfOptions = params.kdfOptions;
        this.aesGcmOptions = params.aesGcmOptions;
    }
}