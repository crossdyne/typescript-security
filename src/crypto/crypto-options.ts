export const HashAlgorithms = {
    SHA256: 'SHA-256' as const,
    SHA384: 'SHA-384' as const,
    SHA512: 'SHA-512' as const,
} as const;

export type HashAlgorithm = typeof HashAlgorithms[keyof typeof HashAlgorithms];

export const SupportedHashAlgorithms = [
    HashAlgorithms.SHA256,
    HashAlgorithms.SHA384,
    HashAlgorithms.SHA512,
] as const;

export const DefaultHashAlgorithm = HashAlgorithms.SHA256;

export const SecurityConstants = {
    Pbkdf2IterationsDefault: 600_000,
    Pbkdf2IterationsMinimum: 100_000,
    AesGcmNonceSize: 12,
    AesGcmTagSizeMin: 12,
    AesGcmTagSizeMax: 16,
    KeySizeBytes: 32, // 256 bits
} as const;

export class KdfOptions {

    //#region Iterations

    private _pbkdf2Iterations: number = SecurityConstants.Pbkdf2IterationsDefault;

    get pbkdf2Iterations(): number {
        return this._pbkdf2Iterations;
    }

    set pbkdf2Iterations(value: number) {
        if (value < SecurityConstants.Pbkdf2IterationsMinimum) {
            throw new Error(`PBKDF2 iterations must be at least ${SecurityConstants.Pbkdf2IterationsMinimum}`);
        }

        this._pbkdf2Iterations = value;
    }

    //#endregion

    //#region HashAlgorithm

    private _hashAlgorithm: HashAlgorithm = DefaultHashAlgorithm;

    get hashAlgorithm(): HashAlgorithm {
        return this._hashAlgorithm;
    }

    set hashAlgorithm(value: HashAlgorithm) {
        if (!SupportedHashAlgorithms.includes(value)) {
            throw new Error(`Unsupported hash algorithm: ${value}`);
        }
        this._hashAlgorithm = value;
    }

    //#endregion

    validate(): void {
        if (this.pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum) {
            throw new Error(`PBKDF2 iterations (${this.pbkdf2Iterations}) is below safe minimum.`);
        }
        if (!SupportedHashAlgorithms.includes(this.hashAlgorithm)) {
            throw new Error(`Invalid hash algorithm: ${this.hashAlgorithm}`);
        }
    }

    static get default(): KdfOptions {
        return new KdfOptions();
    }

    withPbkdf2Iterations(iterations: number): this {
        this.pbkdf2Iterations = iterations;
        return this;
    }

    withHashAlgorithm(hash: HashAlgorithm): this {
        this.hashAlgorithm = hash;
        return this;
    }

    build(): KdfOptions {
        this.validate();
        return this;
    }
}

export class AesGcmOptions {
    private _nonceSize: number = SecurityConstants.AesGcmNonceSize; // 12 bytes by default
    private _tagSize: number = SecurityConstants.AesGcmTagSizeMax; // 16 bytes by default
    public associatedData?: Uint8Array;

    get nonceSize(): number {
        return this._nonceSize;
    }

    set nonceSize(value: number) {
        if (value !== SecurityConstants.AesGcmNonceSize) {
            throw new Error(`AES-GCM requires a ${SecurityConstants.AesGcmNonceSize}-byte nonce.`);
        }
        this._nonceSize = value;
    }

    get tagSize(): number {
        return this._tagSize;
    }

    set tagSize(value: number) {
        if (value < SecurityConstants.AesGcmTagSizeMin || value > SecurityConstants.AesGcmTagSizeMax) {
            throw new Error(`Tag size must be between ${SecurityConstants.AesGcmTagSizeMin} and ${SecurityConstants.AesGcmTagSizeMax} bytes.`);
        }
        this._tagSize = value;
    }

    validate(): void {
        if (this.tagSize < SecurityConstants.AesGcmTagSizeMin || this.tagSize > SecurityConstants.AesGcmTagSizeMax) {
            throw new Error(`Invalid Tag Size: ${this.tagSize}`);
        }
    }

    static get default(): AesGcmOptions {
        return new AesGcmOptions();
    }
}