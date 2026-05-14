import { AesGcmOptions } from "./aes-gcm-options.js";
import { CryptoVersion } from "./crypto-version.js";
import { KdfOptions } from "./kdf-options.js";

export class CryptoProfile {
    readonly version: CryptoVersion;
    readonly kdfOptions: KdfOptions;
    readonly aesGcmOptions: AesGcmOptions;

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