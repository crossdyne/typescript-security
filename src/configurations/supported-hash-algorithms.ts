import { HashAlgorithm } from "../crypto/hash-algorithm.js";

export const SupportedHashAlgorithms: ReadonlyArray<HashAlgorithm> = ['SHA-256', 'SHA-384', 'SHA-512'] as const;