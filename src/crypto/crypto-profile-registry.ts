import { AesGcmOptions } from "./aes-gcm-options.js";
import { CryptoProfile } from "./crypto-profile.js";
import { CryptoVersion } from "./crypto-version.js";
import { KdfOptions } from "./kdf-options.js";

/**
 * Registry of predefined {@link CryptoProfile} instances by version.
 * Returns a fresh profile per call.
 */
export class CryptoProfileRegistry {

    private static readonly V1_PROFILE = new CryptoProfile({
        version: CryptoVersion.V1,
        algorithmName: 'AES-GCM',
        kdfOptions: KdfOptions.V1,
        aesGcmOptions: AesGcmOptions.V1,
    });

    static getProfile(version: CryptoVersion): CryptoProfile {
        switch (version) {
            case CryptoVersion.V1:
                return this.V1_PROFILE;
            default:
                throw new Error(`Unsupported crypto version: ${version}`);
        }
    }
}