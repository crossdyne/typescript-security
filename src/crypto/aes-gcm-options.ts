import { SecurityConstants } from "../configurations/security-constants.js";

export class AesGcmOptions {
  private _nonceSize: number = SecurityConstants.AesGcmNonceSize;
  private _tagSize: number = SecurityConstants.AesGcmTagSize;
  public associatedData?: Uint8Array;

  get nonceSize(): number { return this._nonceSize; }
  set nonceSize(v: number) {
    if (v !== SecurityConstants.AesGcmNonceSize) throw new RangeError(`AES-GCM requires ${SecurityConstants.AesGcmNonceSize}-byte nonce`);
    this._nonceSize = v;
  }

  get tagSize(): number { return this._tagSize; }
  set tagSize(v: number) {
    if (v < SecurityConstants.AesGcmTagSizeMin || v > SecurityConstants.AesGcmTagSizeMax) throw new RangeError(`Tag size must be between ${SecurityConstants.AesGcmTagSizeMin} and ${SecurityConstants.AesGcmTagSizeMax}`);
    this._tagSize = v;
  }

  validate(): void {
    if (this.tagSize < SecurityConstants.AesGcmTagSizeMin || this.tagSize > SecurityConstants.AesGcmTagSizeMax) throw new Error(`Invalid Tag Size: ${this.tagSize}`);
  }

  static get default(): AesGcmOptions { return new AesGcmOptions(); }
  withTagSize(s: number): this { this.tagSize = s; return this; }
  withAssociatedData(aad: Uint8Array | string | undefined): this {
    this.associatedData = typeof aad === 'string' ? new TextEncoder().encode(aad) : aad;
    return this;
  }
  build(): AesGcmOptions { this.validate(); return this; }
}