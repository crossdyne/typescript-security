import { HashAlgorithm } from "../crypto/hash-algorithm.js";
import { SrpContext } from "../srp/srp-context.js";
import { SecurityUtils } from "./security.utils.js";

export class SrpEncoding {
  static toModulusBytes(ctx: SrpContext, value: bigint): Uint8Array {
    return SecurityUtils.bigIntToFixedBytes(value, ctx.modulusSize);
  }
  
  static toHashBytes(ctx: SrpContext, value: bigint): Uint8Array {
    return SecurityUtils.bigIntToFixedBytes(value, ctx.hashSize);
  }

  static async hashModuli(ctx: SrpContext, ...values: bigint[]): Promise<bigint> {
    const buffers = values.map(v => this.toModulusBytes(ctx, v));
    return this.hash(ctx.hashAlgorithmName, ...buffers);
  }

  static async computeM1(ctx: SrpContext, A: bigint, B: bigint, sessionKeyK: Uint8Array): Promise<bigint> {
    return this.hash(ctx.hashAlgorithmName, this.toModulusBytes(ctx, A), this.toModulusBytes(ctx, B), sessionKeyK);
  }
  
  static async computeM2(ctx: SrpContext, A: bigint, M1: bigint, sessionKeyK: Uint8Array): Promise<bigint> {
    return this.hash(ctx.hashAlgorithmName, this.toModulusBytes(ctx, A), this.toHashBytes(ctx, M1), sessionKeyK);
  }
  
  static async computeSessionKey(ctx: SrpContext, S: bigint): Promise<Uint8Array> {
    const sBytes = this.toModulusBytes(ctx, S);
    const hashBuffer = await crypto.subtle.digest(
        ctx.hashAlgorithmName, 
        sBytes as BufferSource
    );
    return new Uint8Array(hashBuffer);
}

  private static async hash(algo: HashAlgorithm, ...buffers: Uint8Array[]): Promise<bigint> {
    const totalLen = buffers.reduce((sum, b) => sum + b.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const buf of buffers) { combined.set(buf, offset); offset += buf.length; }
    const hashBuffer = await crypto.subtle.digest(algo, combined);
    return SecurityUtils.bytesToBigInt(new Uint8Array(hashBuffer));
  }
}