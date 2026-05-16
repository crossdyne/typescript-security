import { HashAlgorithm } from "../crypto/hash-algorithm.js";
import { SecurityUtils } from "../utils/security.utils.js";
import { SrpGroupParams } from "./srp-group-params.js";
import { SrpGroup } from "./srp-group.js";

/**
 * Immutable-style SRP-6a configuration. Parameters aligned with RFC 5054.
 * Compute `k` via {@link computeK}.
 */
export class SrpOptions {

   /** Diffie-Hellman group. Default Rfc5054_3072 (g=5). */
  group: SrpGroup = SrpGroup.Rfc5054_3072;

  /** Hash algorithm for SRP computations. Default SHA-256. */
  hashAlgorithmName: HashAlgorithm = 'SHA-256';

  /** Salt size in bytes. Default 32. */
  saltSize: number = 32;

  /** Prime modulus N for the selected group. */
  get N(): bigint { 
    return SrpGroupParams.getN(this.group); 
}

  /** Generator g for the selected group (2, 5, or 19). */
  get g(): bigint { 
    return SrpGroupParams.getG(this.group);
 }

  /** Byte length of N (ceil(bitLength / 8)). */
  get modulusSize(): number { 
    return Math.floor((this.N.toString(2).length + 7) / 8); 
}

  /**
   * Computes the multiplier parameter k = H(PAD(N) || PAD(g)) (RFC 5054, 2.5.3).
   * @returns k as a bigint.
   */
  async computeK(): Promise<bigint> {
    const nBytes = SecurityUtils.bigIntToFixedBytes(this.N, this.modulusSize);
    const gBytes = SecurityUtils.bigIntToFixedBytes(this.g, this.modulusSize);
    const combined = new Uint8Array(nBytes.length + gBytes.length);
    combined.set(nBytes, 0);
    combined.set(gBytes, nBytes.length);
    const hash = await crypto.subtle.digest(this.hashAlgorithmName, combined);
    return SecurityUtils.bytesToBigInt(new Uint8Array(hash));
  }
}