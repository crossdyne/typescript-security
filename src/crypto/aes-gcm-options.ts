import { SecurityConstants } from "../configurations/security-constants.js";

/**
 * AES-GCM encryption options: nonce size, tag size, and optional AAD.
 * Mutable builder-style; call {@link build} to validate.
 */
export class AesGcmOptions {
  private _nonceSize: number = SecurityConstants.AesGcmNonceSize;
  private _tagSize: number = SecurityConstants.AesGcmTagSize;

   /** Optional Additional Authenticated Data (not encrypted). */
  public associatedData?: Uint8Array;

  /** Nonce size in bytes (must be 12). */
  get nonceSize(): number { return this._nonceSize; }
  set nonceSize(v: number) {
    if (v !== SecurityConstants.AesGcmNonceSize) throw new RangeError(`AES-GCM requires ${SecurityConstants.AesGcmNonceSize}-byte nonce`);
    this._nonceSize = v;
  }

  /** Tag size in bytes (12–16, default 16). */
  get tagSize(): number { return this._tagSize; }
  set tagSize(v: number) {
    if (v < SecurityConstants.AesGcmTagSizeMin || v > SecurityConstants.AesGcmTagSizeMax) throw new RangeError(`Tag size must be between ${SecurityConstants.AesGcmTagSizeMin} and ${SecurityConstants.AesGcmTagSizeMax}`);
    this._tagSize = v;
  }

  /** Validates that {@link tagSize} is in the allowed range. */
  validate(): void {
    if (this.tagSize < SecurityConstants.AesGcmTagSizeMin || this.tagSize > SecurityConstants.AesGcmTagSizeMax) throw new Error(`Invalid Tag Size: ${this.tagSize}`);
  }

  /** Default preset: nonce=12, tag=16, no AAD. */
  static get default(): AesGcmOptions { return new AesGcmOptions(); }

  /** Fluent setter for {@link tagSize}. */
  withTagSize(s: number): this { this.tagSize = s; return this; }

  /**
   * Fluent setter for {@link associatedData}.
   * Accepts a byte array or a UTF-8 string (encoded internally).
   */
  withAssociatedData(aad: Uint8Array | string | undefined): this {
    this.associatedData = typeof aad === 'string' ? new TextEncoder().encode(aad) : aad;
    return this;
  }

   /** Validates and returns this instance. */
  build(): AesGcmOptions { this.validate(); return this; }
}