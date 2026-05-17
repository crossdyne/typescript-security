/**
 * SRP-6a Diffie-Hellman groups (RFC 5054).
 * 1024 (~80) deprecated, 1536 (~90) legacy, 2048 (~112) baseline,
 * 3072+ (≥128) preferred. g=2 for ≤2048, g=5 for 3072-6144, g=19 for 8192.
 * Always use {@link SrpGroupParams} to get N and g.
 */
export enum SrpGroup {
    /** 1024-bit, g=2, ~80-bit security. Deprecated, legacy only. */
    Rfc5054_1024 = 1,

    /** 1536-bit, g=2, ~90-bit security. Minimum for legacy systems. */
    Rfc5054_1536 = 2,

    /** 2048-bit, g=2, ~112-bit security. Recommended baseline. */
    Rfc5054_2048 = 3,

    /** 3072-bit, g=5, ~128-bit security. Preferred for long-term. */
    Rfc5054_3072 = 4,

    /** 4096-bit, g=5, ~156-bit security. High-security environments. */
    Rfc5054_4096 = 5,

    /** 6144-bit, g=5, ~192-bit security. Specialized high-assurance. */
    Rfc5054_6144 = 6,

    /** 8192-bit, g=19, ~256-bit security. Experimental, extremely slow. */
    Rfc5054_8192 = 7,

    /** User-supplied N and g. Validate safe prime and generator. */
    Custom = 99
}