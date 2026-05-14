import { HashAlgorithmName, SrpContext } from "../srp/srp-configuration.js";

export class SecurityUtils {
    static toBase64(bytes: Uint8Array): string {
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++)
            binary += String.fromCharCode(bytes[i]);
        return window.btoa(binary);
    }

    static fromBase64(base64: string): Uint8Array {
        const cleaned = base64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        const binary = window.atob(cleaned);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
             bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    static bytesToBigInt(bytes: Uint8Array): bigint {
        if (bytes.length === 0) return BigInt(0);
        return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
    }

    static bigIntToFixedBytes(bn: bigint, length: number): Uint8Array {
        let hex = bn.toString(16);
        if (hex.length % 2 !== 0) hex = '0' + hex;

        if (hex.length > length * 2) {
            hex = hex.substring(hex.length - length * 2);
        } else {
            hex = hex.padStart(length * 2, '0');
        }

        return this.fromHex(hex);
    }

    static fromHex(hex: string): Uint8Array {
        const matches = hex.match(/.{1,2}/g);
        return new Uint8Array(matches ? matches.map(byte => parseInt(byte, 16)) : []);
    }  

    static expMod(base: bigint, exp: bigint, mod: bigint): bigint {
        let res = BigInt(1);
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n)
                 res = (res * base) % mod;
                
            base = (base * base) % mod;
            exp = exp / 2n;
        }
        return res;
    }

    static async hash(algo: HashAlgorithmName, ...buffers: Uint8Array[]): Promise<bigint> {
        const totalLen = buffers.reduce((sum, buf) => sum + buf.length, 0);
        const combined = new Uint8Array(totalLen);
        let offset = 0;
        for (const buf of buffers) {
            combined.set(buf, offset);
            offset += buf.length;
        }
        const hashBuffer = await crypto.subtle.digest(algo, combined);
        return this.bytesToBigInt(new Uint8Array(hashBuffer));
    }
}

export class SrpEncoding {
    static toModulusBytes(ctx: SrpContext, value: bigint): Uint8Array {
        return SecurityUtils.bigIntToFixedBytes(value, ctx.modulusSize);
    }

    static toHashBytes(ctx: SrpContext, value: bigint): Uint8Array {
        return SecurityUtils.bigIntToFixedBytes(value, ctx.hashSize);
    }

    static async hashModuli(ctx: SrpContext, ...values: bigint[]): Promise<bigint> {
        const buffers = values.map(v => this.toModulusBytes(ctx, v));
        return SecurityUtils.hash(ctx.hashAlgorithmName, ...buffers);
    }

    static async computeM1(ctx: SrpContext, A: bigint, B: bigint, S: bigint): Promise<bigint> {
        return SecurityUtils.hash(
            ctx.hashAlgorithmName,
            this.toModulusBytes(ctx, A),
            this.toModulusBytes(ctx, B),
            this.toModulusBytes(ctx, S)
        );
    }

    static async computeM2(ctx: SrpContext, A: bigint, M1: bigint, S: bigint): Promise<bigint> {
        return SecurityUtils.hash(
            ctx.hashAlgorithmName,
            this.toModulusBytes(ctx, A),
            this.toHashBytes(ctx, M1),
            this.toModulusBytes(ctx, S)
        );
    }
}