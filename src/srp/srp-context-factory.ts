import { SrpContext } from "./srp-context.js";
import { SrpGroup } from "./srp-group.js";
import { SrpOptions } from "./srp-options.js";

/**
 * Factory for creating an {@link SrpContext} from an SRP group.
 * Automatically selects the hash algorithm (SHA-256 for ≤3072-bit, SHA-384 for 4096+).
 */
export class SrpContextFactory {

  /**
   * Creates an SRP context with the specified group.
   * @param group - SRP group (default Rfc5054_3072).
   * @returns A ready-to-use SrpContext.
   */
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