import { HashAlgorithm } from "../crypto/hash-algorithm.js";
import { SecurityUtils } from "../utils/security.utils.js";
import { SrpGroupParams } from "./srp-group-params.js";
import { SrpGroup } from "./srp-group.js";

export class SrpOptions {
  group: SrpGroup = SrpGroup.Rfc5054_3072;
  hashAlgorithmName: HashAlgorithm = 'SHA-256';
  saltSize: number = 32;

  get N(): bigint { 
    return SrpGroupParams.getN(this.group); 
}

  get g(): bigint { 
    return SrpGroupParams.getG(this.group);
 }

  get modulusSize(): number { 
    return Math.floor((this.N.toString(2).length + 7) / 8); 
}

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