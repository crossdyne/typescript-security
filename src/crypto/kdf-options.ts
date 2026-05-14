import { SecurityConstants } from "../configurations/security-constants.js";
import { SupportedHashAlgorithms } from "../configurations/supported-hash-algorithms.js";
import { HashAlgorithm } from "./hash-algorithm.js";

export class KdfOptions {
  private _pbkdf2Iterations: number = SecurityConstants.Pbkdf2IterationsDefault;
  private _hashAlgorithm: HashAlgorithm = 'SHA-256';

  get pbkdf2Iterations(): number { return this._pbkdf2Iterations; }
  set pbkdf2Iterations(v: number) {
    if (v < SecurityConstants.Pbkdf2IterationsMinimum) throw new RangeError(`PBKDF2 iterations must be ≥ ${SecurityConstants.Pbkdf2IterationsMinimum}`);
    this._pbkdf2Iterations = v;
  }

  get hashAlgorithm(): HashAlgorithm { return this._hashAlgorithm; }
  set hashAlgorithm(v: HashAlgorithm) {
    if (!SupportedHashAlgorithms.includes(v)) throw new RangeError(`Unsupported hash: ${v}`);
    this._hashAlgorithm = v;
  }

  validate(): void {
    if (this.pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum) throw new Error(`Pbkdf2Iterations (${this.pbkdf2Iterations}) below minimum`);
    if (!SupportedHashAlgorithms.includes(this.hashAlgorithm)) throw new Error(`Invalid hash algorithm: ${this.hashAlgorithm}`);
  }

  static get default(): KdfOptions { return new KdfOptions(); }
  withPbkdf2Iterations(i: number): this { this.pbkdf2Iterations = i; return this; }
  withHashAlgorithm(h: HashAlgorithm): this { this.hashAlgorithm = h; return this; }
  build(): KdfOptions { this.validate(); return this; }
}