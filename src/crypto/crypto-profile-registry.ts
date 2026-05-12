import { AesGcmOptions, KdfOptions } from "./crypto-options.js";
import { CryptoProfile, CryptoVersion } from "./crypto-profile.js";

export class CryptoProfileRegistry {
    static getProfile(version: CryptoVersion): CryptoProfile {
        switch (version) {
            case CryptoVersion.V1:
                return new CryptoProfile({
                    version: CryptoVersion.V1,
                    kdfOptions: KdfOptions.default,
                    aesGcmOptions: AesGcmOptions.default,
                });
            default:
                throw new Error(`Unsupported crypto version: ${version}`);
        }
    }

    static get latest(): CryptoProfile {
        return this.getProfile(CryptoVersion.V1);
    }
}