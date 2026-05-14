import { KeyDerivationService } from "../crypto/key-derivation.service.js";
import { SecurityUtils, SrpEncoding } from "../utils/security.utils.js";
import { SrpContext } from "./srp-configuration.js";

export class SrpService {
  private readonly keyDerivation = new KeyDerivationService(); // Ваш сервис

  async generateSrpVerifier(authHash: string, ctx: SrpContext): Promise<string> {
    const x = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(authHash));
    const v = SecurityUtils.expMod(ctx.g, x, ctx.N);
    return SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, v));
  }

  async generateSrpProof(login: string, password: string, saltBase64: string, B_base64: string, ctx: SrpContext): Promise<{ A: string; M1: string; S: string }> {
    const salt = SecurityUtils.fromBase64(saltBase64);

    const { authHash } = await this.keyDerivation.deriveKeysFromPassword(login, password, salt);
    const x = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(authHash));

    const aBytes = crypto.getRandomValues(new Uint8Array(32));
    const a = SecurityUtils.bytesToBigInt(aBytes);

    const A = SecurityUtils.expMod(ctx.g, a, ctx.N);
    if (A % ctx.N === 0n)
        throw new Error('Критическая ошибка: A % N === 0');

    const B = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(B_base64));
    if (B % ctx.N === 0n)
        throw new Error('Критическая ошибка: B % N === 0');

    const u = await SrpEncoding.hashModuli(ctx, A, B);
    if (u === 0n)
        throw new Error('Недопустимое значение u');

    const gX = SecurityUtils.expMod(ctx.g, x, ctx.N);
    const term = (ctx.k * gX) % ctx.N;
    const base = (B - term + ctx.N) % ctx.N;
    const exponent = a + (u * x);
    const S = SecurityUtils.expMod(base, exponent, ctx.N);

    if (S === 0n)
        throw new Error('Критическая ошибка: S === 0');

    const M1 = await SrpEncoding.computeM1(ctx, A, B, S);

    return {
      A: SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, A)),
      M1: SecurityUtils.toBase64(SrpEncoding.toHashBytes(ctx, M1)),
      S: SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, S)),
    };
  }

  async verifyServerM2(A_b64: string, M1_b64: string, S_b64: string, serverM2_b64: string, ctx: SrpContext): Promise<boolean> {
    const A = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(A_b64));
    const M1 = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(M1_b64));
    const S = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(S_b64));

    const computedM2 = await SrpEncoding.computeM2(ctx, A, M1, S);
    const computedM2_b64 = SecurityUtils.toBase64(SrpEncoding.toHashBytes(ctx, computedM2));

    return serverM2_b64 === computedM2_b64;
  }
}