import { HashAlgorithm } from "../crypto/hash-algorithm.js";

/**
 * Immutable SRP cryptographic context: modulus, generator, multiplier k, hash algorithm, and sizes.
 */
export interface SrpContext {

    /** Prime modulus N. */
    readonly N: bigint;

    /** Generator g. */
    readonly g: bigint;

     /** Multiplier k = H(PAD(N) || PAD(g)) (RFC 5054, 2.5.3) */
    readonly k: bigint;

     /** Modulus size in bytes (ceil(bit length / 8)). */
    readonly modulusSize: number;

    /** Hash algorithm used for SRP computations. */
    readonly hashAlgorithmName: HashAlgorithm;

    /** Hash output size in bytes (e.g., 32 for SHA-256). */
    readonly hashSize: number;
}