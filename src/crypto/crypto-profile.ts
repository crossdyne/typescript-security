import { AesGcmOptions, KdfOptions } from "./crypto-options.js";

export enum CryptoVersion {
    V1 = 1,
}

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