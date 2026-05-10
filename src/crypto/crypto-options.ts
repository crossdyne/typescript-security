export const SecurityConstants = {
    Pbkdf2IterationsDefault: 600_000,
    Pbkdf2IterationsMinimum: 100_000,
    Pbkdf2IterationsRecommended: 1_000_000,
    AesGcmNonceSize: 12,
    AesGcmTagSizeMin: 12,
    AesGcmTagSizeMax: 16,
    KeySizeBytes: 32 // 256 bits
} as const;

export class KdfOptions {
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

    validate(): void {
        if (this.pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum) {
            throw new Error(`PBKDF2 iterations (${this.pbkdf2Iterations}) is below safe minimum.`);
        }
    }

    static get default(): KdfOptions {
        return new KdfOptions();
    }

    static get highSecurity(): KdfOptions {
        const opts = new KdfOptions();
        opts.pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended;
        return opts;
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