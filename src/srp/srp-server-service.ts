import { SecurityUtils } from "../utils/security.utils.js";
import { SrpEncoding } from "../utils/srp-encoding.js";
import { SrpContext } from "./srp-context.js";

export interface SrpSessionState {
  login: string;
  privateKeyB: string;
  verifier: string;
  publicKeyB: string;
}

export class SrpServerService {

  async getSrpChallenge(login: string, verifierBytes: Uint8Array, ctx: SrpContext): Promise<SrpSessionState> {
    const v = SecurityUtils.bytesToBigInt(verifierBytes);

    const bBytes = crypto.getRandomValues(new Uint8Array(32));
    const b = SecurityUtils.bytesToBigInt(bBytes);

    const gB = SecurityUtils.expMod(ctx.g, b, ctx.N);
    const B = (ctx.k * v + gB) % ctx.N;

    return {
      login,
      privateKeyB: SecurityUtils.toBase64(bBytes),
      verifier: SecurityUtils.toBase64(verifierBytes),
      publicKeyB: SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, B))
    };
  }

  async verifySrpProof(sessionState: SrpSessionState, a: string, m1: string, ctx: SrpContext): Promise<string> {
    const A = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(a));
    const M1_client = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(m1));
    const b = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(sessionState.privateKeyB));
    const v = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(sessionState.verifier));
    const B = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(sessionState.publicKeyB));

    if (v <= 0n)
      throw new Error("The verifier is corrupted");

    if (A % ctx.N === 0n)
      throw new Error("Incorrect value of A");

    if (A <= 0n || A >= ctx.N)
      throw new Error("Invalid A (out of range)");

    const u = await SrpEncoding.hashModuli(ctx, A, B);

    if (u === 0n)
      throw new Error("Error in calculating the parameter u");

    const vU = SecurityUtils.expMod(v, u, ctx.N);
    const S = SecurityUtils.expMod((A * vU) % ctx.N, b, ctx.N);

    const sessionKeyK = await SrpEncoding.computeSessionKey(ctx, S);
    const M1_server = await SrpEncoding.computeM1(ctx, A, B, sessionKeyK);

    const m1ServerBytes = SrpEncoding.toHashBytes(ctx, M1_server);
    const m1ClientBytes = SrpEncoding.toHashBytes(ctx, M1_client);

    if (!SecurityUtils.fixedTimeEquals(m1ServerBytes, m1ClientBytes))
      throw new Error("Invalid password");

    const M2_server = await SrpEncoding.computeM2(ctx, A, M1_client, sessionKeyK);

    return SecurityUtils.toBase64(SrpEncoding.toHashBytes(ctx, M2_server));
  }
}