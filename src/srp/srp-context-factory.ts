import { SrpContext } from "./srp-context.js";
import { SrpGroup } from "./srp-group.js";
import { SrpOptions } from "./srp-options.js";

export class SrpContextFactory {
  static async create(group: SrpGroup = SrpGroup.Rfc5054_3072): Promise<SrpContext> {
    const opts = new SrpOptions();
    opts.group = group;
    opts.hashAlgorithmName = group === SrpGroup.Rfc5054_4096 || group === SrpGroup.Rfc5054_6144 || group === SrpGroup.Rfc5054_8192 ? 'SHA-384' : 'SHA-256';
    
    return {
      N: opts.N,
      g: opts.g,
      k: await opts.computeK(),
      modulusSize: opts.modulusSize,
      hashAlgorithmName: opts.hashAlgorithmName,
      hashSize: opts.hashAlgorithmName === 'SHA-256' ? 32 : opts.hashAlgorithmName === 'SHA-384' ? 48 : 64
    };
  }
}