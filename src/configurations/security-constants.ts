export const SecurityConstants = {
  AesGcmNonceSize: 12,
  AesGcmTagSize: 16,
  AesGcmTagSizeMin: 12,
  AesGcmTagSizeMax: 16,
  KeySizeBytes: 32, // 256 bits
  Pbkdf2IterationsDefault: 600_000,
  Pbkdf2IterationsMinimum: 100_000
} as const;