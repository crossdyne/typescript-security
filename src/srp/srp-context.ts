import { HashAlgorithm } from "../crypto/hash-algorithm.js";

export interface SrpContext {
    readonly N: bigint;
    readonly g: bigint;
    readonly k: bigint;
    readonly modulusSize: number;
    readonly hashAlgorithmName: HashAlgorithm;
    readonly hashSize: number;
}