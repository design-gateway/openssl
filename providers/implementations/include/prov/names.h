/*
 * Copyright 2021-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Macros for use as names and descriptions in our providers' OSSL_ALGORITHM.
 *
 * All the strings are formatted the same way:
 *
 *     Our primary name[:other names][:numeric OID]
 *
 * 'other names' include historical OpenSSL names, NIST names, ASN.1 OBJECT
 * IDENTIFIER names, and commonly known aliases.
 *
 * Where it matters, our primary names follow this format:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 */

/*-
 * Symmetric ciphers
 * -----------------
 */
#define PROV_NAMES_AES_256_ECB "AES-256-ECB:2.16.840.1.101.3.4.1.41"
#define PROV_NAMES_AES_192_ECB "AES-192-ECB:2.16.840.1.101.3.4.1.21"
#define PROV_NAMES_AES_128_ECB "AES-128-ECB:2.16.840.1.101.3.4.1.1"
#define PROV_NAMES_AES_256_CBC "AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42"
#define PROV_NAMES_AES_192_CBC "AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22"
#define PROV_NAMES_AES_128_CBC "AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2"
#define PROV_NAMES_AES_256_CBC_CTS "AES-256-CBC-CTS"
#define PROV_NAMES_AES_192_CBC_CTS "AES-192-CBC-CTS"
#define PROV_NAMES_AES_128_CBC_CTS "AES-128-CBC-CTS"
#define PROV_NAMES_AES_256_OFB "AES-256-OFB:2.16.840.1.101.3.4.1.43"
#define PROV_NAMES_AES_192_OFB "AES-192-OFB:2.16.840.1.101.3.4.1.23"
#define PROV_NAMES_AES_128_OFB "AES-128-OFB:2.16.840.1.101.3.4.1.3"
#define PROV_NAMES_AES_256_CFB "AES-256-CFB:2.16.840.1.101.3.4.1.44"
#define PROV_NAMES_AES_192_CFB "AES-192-CFB:2.16.840.1.101.3.4.1.24"
#define PROV_NAMES_AES_128_CFB "AES-128-CFB:2.16.840.1.101.3.4.1.4"
#define PROV_NAMES_AES_256_CFB1 "AES-256-CFB1"
#define PROV_NAMES_AES_192_CFB1 "AES-192-CFB1"
#define PROV_NAMES_AES_128_CFB1 "AES-128-CFB1"
#define PROV_NAMES_AES_256_CFB8 "AES-256-CFB8"
#define PROV_NAMES_AES_192_CFB8 "AES-192-CFB8"
#define PROV_NAMES_AES_128_CFB8 "AES-128-CFB8"
#define PROV_NAMES_AES_256_CTR "AES-256-CTR"
#define PROV_NAMES_AES_192_CTR "AES-192-CTR"
#define PROV_NAMES_AES_128_CTR "AES-128-CTR"
#define PROV_NAMES_AES_256_XTS "AES-256-XTS:1.3.111.2.1619.0.1.2"
#define PROV_NAMES_AES_128_XTS "AES-128-XTS:1.3.111.2.1619.0.1.1"
#define PROV_NAMES_AES_256_GCM "AES-256-GCM:id-aes256-GCM:2.16.840.1.101.3.4.1.46"
#define PROV_NAMES_AES_192_GCM "AES-192-GCM:id-aes192-GCM:2.16.840.1.101.3.4.1.26"
#define PROV_NAMES_AES_128_GCM "AES-128-GCM:id-aes128-GCM:2.16.840.1.101.3.4.1.6"
#define PROV_NAMES_AES_256_CCM "AES-256-CCM:id-aes256-CCM:2.16.840.1.101.3.4.1.47"
#define PROV_NAMES_AES_192_CCM "AES-192-CCM:id-aes192-CCM:2.16.840.1.101.3.4.1.27"
#define PROV_NAMES_AES_128_CCM "AES-128-CCM:id-aes128-CCM:2.16.840.1.101.3.4.1.7"
#define PROV_NAMES_AES_256_WRAP "AES-256-WRAP:id-aes256-wrap:AES256-WRAP:2.16.840.1.101.3.4.1.45"
#define PROV_NAMES_AES_192_WRAP "AES-192-WRAP:id-aes192-wrap:AES192-WRAP:2.16.840.1.101.3.4.1.25"
#define PROV_NAMES_AES_128_WRAP "AES-128-WRAP:id-aes128-wrap:AES128-WRAP:2.16.840.1.101.3.4.1.5"
#define PROV_NAMES_AES_256_WRAP_PAD "AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD:2.16.840.1.101.3.4.1.48"
#define PROV_NAMES_AES_192_WRAP_PAD "AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD:2.16.840.1.101.3.4.1.28"
#define PROV_NAMES_AES_128_WRAP_PAD "AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD:2.16.840.1.101.3.4.1.8"
#define PROV_NAMES_AES_256_WRAP_INV "AES-256-WRAP-INV:AES256-WRAP-INV"
#define PROV_NAMES_AES_192_WRAP_INV "AES-192-WRAP-INV:AES192-WRAP-INV"
#define PROV_NAMES_AES_128_WRAP_INV "AES-128-WRAP-INV:AES128-WRAP-INV"
#define PROV_NAMES_AES_256_WRAP_PAD_INV "AES-256-WRAP-PAD-INV:AES256-WRAP-PAD-INV"
#define PROV_NAMES_AES_192_WRAP_PAD_INV "AES-192-WRAP-PAD-INV:AES192-WRAP-PAD-INV"
#define PROV_NAMES_AES_128_WRAP_PAD_INV "AES-128-WRAP-PAD-INV:AES128-WRAP-PAD-INV"
#define PROV_NAMES_AES_128_CBC_HMAC_SHA1 "AES-128-CBC-HMAC-SHA1"
#define PROV_NAMES_AES_256_CBC_HMAC_SHA1 "AES-256-CBC-HMAC-SHA1"
#define PROV_NAMES_AES_128_CBC_HMAC_SHA256 "AES-128-CBC-HMAC-SHA256"
#define PROV_NAMES_AES_256_CBC_HMAC_SHA256 "AES-256-CBC-HMAC-SHA256"
#define PROV_NAMES_DES_EDE3_ECB "DES-EDE3-ECB:DES-EDE3"
#define PROV_NAMES_DES_EDE3_CBC "DES-EDE3-CBC:DES3:1.2.840.113549.3.7"
#define PROV_NAMES_NULL "NULL"
#define PROV_NAMES_AES_256_OCB "AES-256-OCB"
#define PROV_NAMES_AES_192_OCB "AES-192-OCB"
#define PROV_NAMES_AES_128_OCB "AES-128-OCB"
#define PROV_NAMES_AES_128_SIV "AES-128-SIV"
#define PROV_NAMES_AES_192_SIV "AES-192-SIV"
#define PROV_NAMES_AES_256_SIV "AES-256-SIV"
#define PROV_NAMES_AES_128_GCM_SIV "AES-128-GCM-SIV"
#define PROV_NAMES_AES_192_GCM_SIV "AES-192-GCM-SIV"
#define PROV_NAMES_AES_256_GCM_SIV "AES-256-GCM-SIV"
#define PROV_NAMES_ARIA_256_GCM "ARIA-256-GCM:1.2.410.200046.1.1.36"
#define PROV_NAMES_ARIA_192_GCM "ARIA-192-GCM:1.2.410.200046.1.1.35"
#define PROV_NAMES_ARIA_128_GCM "ARIA-128-GCM:1.2.410.200046.1.1.34"
#define PROV_NAMES_ARIA_256_CCM "ARIA-256-CCM:1.2.410.200046.1.1.39"
#define PROV_NAMES_ARIA_192_CCM "ARIA-192-CCM:1.2.410.200046.1.1.38"
#define PROV_NAMES_ARIA_128_CCM "ARIA-128-CCM:1.2.410.200046.1.1.37"
#define PROV_NAMES_ARIA_256_ECB "ARIA-256-ECB:1.2.410.200046.1.1.11"
#define PROV_NAMES_ARIA_192_ECB "ARIA-192-ECB:1.2.410.200046.1.1.6"
#define PROV_NAMES_ARIA_128_ECB "ARIA-128-ECB:1.2.410.200046.1.1.1"
#define PROV_NAMES_ARIA_256_CBC "ARIA-256-CBC:ARIA256:1.2.410.200046.1.1.12"
#define PROV_NAMES_ARIA_192_CBC "ARIA-192-CBC:ARIA192:1.2.410.200046.1.1.7"
#define PROV_NAMES_ARIA_128_CBC "ARIA-128-CBC:ARIA128:1.2.410.200046.1.1.2"
#define PROV_NAMES_ARIA_256_OFB "ARIA-256-OFB:1.2.410.200046.1.1.14"
#define PROV_NAMES_ARIA_192_OFB "ARIA-192-OFB:1.2.410.200046.1.1.9"
#define PROV_NAMES_ARIA_128_OFB "ARIA-128-OFB:1.2.410.200046.1.1.4"
#define PROV_NAMES_ARIA_256_CFB "ARIA-256-CFB:1.2.410.200046.1.1.13"
#define PROV_NAMES_ARIA_192_CFB "ARIA-192-CFB:1.2.410.200046.1.1.8"
#define PROV_NAMES_ARIA_128_CFB "ARIA-128-CFB:1.2.410.200046.1.1.3"
#define PROV_NAMES_ARIA_256_CFB1 "ARIA-256-CFB1"
#define PROV_NAMES_ARIA_192_CFB1 "ARIA-192-CFB1"
#define PROV_NAMES_ARIA_128_CFB1 "ARIA-128-CFB1"
#define PROV_NAMES_ARIA_256_CFB8 "ARIA-256-CFB8"
#define PROV_NAMES_ARIA_192_CFB8 "ARIA-192-CFB8"
#define PROV_NAMES_ARIA_128_CFB8 "ARIA-128-CFB8"
#define PROV_NAMES_ARIA_256_CTR "ARIA-256-CTR:1.2.410.200046.1.1.15"
#define PROV_NAMES_ARIA_192_CTR "ARIA-192-CTR:1.2.410.200046.1.1.10"
#define PROV_NAMES_ARIA_128_CTR "ARIA-128-CTR:1.2.410.200046.1.1.5"
#define PROV_NAMES_CAMELLIA_256_ECB "CAMELLIA-256-ECB:0.3.4401.5.3.1.9.41"
#define PROV_NAMES_CAMELLIA_192_ECB "CAMELLIA-192-ECB:0.3.4401.5.3.1.9.21"
#define PROV_NAMES_CAMELLIA_128_ECB "CAMELLIA-128-ECB:0.3.4401.5.3.1.9.1"
#define PROV_NAMES_CAMELLIA_256_CBC "CAMELLIA-256-CBC:CAMELLIA256:1.2.392.200011.61.1.1.1.4"
#define PROV_NAMES_CAMELLIA_192_CBC "CAMELLIA-192-CBC:CAMELLIA192:1.2.392.200011.61.1.1.1.3"
#define PROV_NAMES_CAMELLIA_128_CBC "CAMELLIA-128-CBC:CAMELLIA128:1.2.392.200011.61.1.1.1.2"
#define PROV_NAMES_CAMELLIA_256_CBC_CTS "CAMELLIA-256-CBC-CTS"
#define PROV_NAMES_CAMELLIA_192_CBC_CTS "CAMELLIA-192-CBC-CTS"
#define PROV_NAMES_CAMELLIA_128_CBC_CTS "CAMELLIA-128-CBC-CTS"
#define PROV_NAMES_CAMELLIA_256_OFB "CAMELLIA-256-OFB:0.3.4401.5.3.1.9.43"
#define PROV_NAMES_CAMELLIA_192_OFB "CAMELLIA-192-OFB:0.3.4401.5.3.1.9.23"
#define PROV_NAMES_CAMELLIA_128_OFB "CAMELLIA-128-OFB:0.3.4401.5.3.1.9.3"
#define PROV_NAMES_CAMELLIA_256_CFB "CAMELLIA-256-CFB:0.3.4401.5.3.1.9.44"
#define PROV_NAMES_CAMELLIA_192_CFB "CAMELLIA-192-CFB:0.3.4401.5.3.1.9.24"
#define PROV_NAMES_CAMELLIA_128_CFB "CAMELLIA-128-CFB:0.3.4401.5.3.1.9.4"
#define PROV_NAMES_CAMELLIA_256_CFB1 "CAMELLIA-256-CFB1"
#define PROV_NAMES_CAMELLIA_192_CFB1 "CAMELLIA-192-CFB1"
#define PROV_NAMES_CAMELLIA_128_CFB1 "CAMELLIA-128-CFB1"
#define PROV_NAMES_CAMELLIA_256_CFB8 "CAMELLIA-256-CFB8"
#define PROV_NAMES_CAMELLIA_192_CFB8 "CAMELLIA-192-CFB8"
#define PROV_NAMES_CAMELLIA_128_CFB8 "CAMELLIA-128-CFB8"
#define PROV_NAMES_CAMELLIA_256_CTR "CAMELLIA-256-CTR:0.3.4401.5.3.1.9.49"
#define PROV_NAMES_CAMELLIA_192_CTR "CAMELLIA-192-CTR:0.3.4401.5.3.1.9.29"
#define PROV_NAMES_CAMELLIA_128_CTR "CAMELLIA-128-CTR:0.3.4401.5.3.1.9.9"
#define PROV_NAMES_DES_EDE3_OFB "DES-EDE3-OFB"
#define PROV_NAMES_DES_EDE3_CFB "DES-EDE3-CFB"
#define PROV_NAMES_DES_EDE3_CFB8 "DES-EDE3-CFB8"
#define PROV_NAMES_DES_EDE3_CFB1 "DES-EDE3-CFB1"
#define PROV_NAMES_DES3_WRAP "DES3-WRAP:id-smime-alg-CMS3DESwrap:1.2.840.113549.1.9.16.3.6"
#define PROV_NAMES_DES_EDE_ECB "DES-EDE-ECB:DES-EDE:1.3.14.3.2.17"
#define PROV_NAMES_DES_EDE_CBC "DES-EDE-CBC"
#define PROV_NAMES_DES_EDE_OFB "DES-EDE-OFB"
#define PROV_NAMES_DES_EDE_CFB "DES-EDE-CFB"
#define PROV_NAMES_SM4_ECB "SM4-ECB:1.2.156.10197.1.104.1"
#define PROV_NAMES_SM4_CBC "SM4-CBC:SM4:1.2.156.10197.1.104.2"
#define PROV_NAMES_SM4_CTR "SM4-CTR:1.2.156.10197.1.104.7"
#define PROV_NAMES_SM4_OFB "SM4-OFB:SM4-OFB128:1.2.156.10197.1.104.3"
#define PROV_NAMES_SM4_CFB "SM4-CFB:SM4-CFB128:1.2.156.10197.1.104.4"
#define PROV_NAMES_SM4_GCM "SM4-GCM:1.2.156.10197.1.104.8"
#define PROV_NAMES_SM4_CCM "SM4-CCM:1.2.156.10197.1.104.9"
#define PROV_NAMES_SM4_XTS "SM4-XTS:1.2.156.10197.1.104.10"
#define PROV_NAMES_ChaCha20 "ChaCha20"
#define PROV_NAMES_ChaCha20_Poly1305 "ChaCha20-Poly1305"
#define PROV_NAMES_CAST5_ECB "CAST5-ECB"
#define PROV_NAMES_CAST5_CBC "CAST5-CBC:CAST-CBC:CAST:1.2.840.113533.7.66.10"
#define PROV_NAMES_CAST5_OFB "CAST5-OFB"
#define PROV_NAMES_CAST5_CFB "CAST5-CFB"
#define PROV_NAMES_BF_ECB "BF-ECB"
#define PROV_NAMES_BF_CBC "BF-CBC:BF:BLOWFISH:1.3.6.1.4.1.3029.1.2"
#define PROV_NAMES_BF_OFB "BF-OFB"
#define PROV_NAMES_BF_CFB "BF-CFB"
#define PROV_NAMES_IDEA_ECB "IDEA-ECB"
#define PROV_NAMES_IDEA_CBC "IDEA-CBC:IDEA:1.3.6.1.4.1.188.7.1.1.2"
#define PROV_NAMES_IDEA_OFB "IDEA-OFB:IDEA-OFB64"
#define PROV_NAMES_IDEA_CFB "IDEA-CFB:IDEA-CFB64"
#define PROV_NAMES_SEED_ECB "SEED-ECB:1.2.410.200004.1.3"
#define PROV_NAMES_SEED_CBC "SEED-CBC:SEED:1.2.410.200004.1.4"
#define PROV_NAMES_SEED_OFB "SEED-OFB:SEED-OFB128:1.2.410.200004.1.6"
#define PROV_NAMES_SEED_CFB "SEED-CFB:SEED-CFB128:1.2.410.200004.1.5"
#define PROV_NAMES_RC2_ECB "RC2-ECB"
#define PROV_NAMES_RC2_CBC "RC2-CBC:RC2:RC2-128:1.2.840.113549.3.2"
#define PROV_NAMES_RC2_40_CBC "RC2-40-CBC:RC2-40"
#define PROV_NAMES_RC2_64_CBC "RC2-64-CBC:RC2-64"
#define PROV_NAMES_RC2_CFB "RC2-CFB"
#define PROV_NAMES_RC2_OFB "RC2-OFB"
#define PROV_NAMES_RC4 "RC4:1.2.840.113549.3.4"
#define PROV_NAMES_RC4_40 "RC4-40"
#define PROV_NAMES_RC4_HMAC_MD5 "RC4-HMAC-MD5"
#define PROV_NAMES_RC5_ECB "RC5-ECB"
#define PROV_NAMES_RC5_CBC "RC5-CBC:RC5:1.2.840.113549.3.8"
#define PROV_NAMES_RC5_OFB "RC5-OFB"
#define PROV_NAMES_RC5_CFB "RC5-CFB"
#define PROV_NAMES_DESX_CBC "DESX-CBC:DESX"
#define PROV_NAMES_DES_ECB "DES-ECB:1.3.14.3.2.6"
#define PROV_NAMES_DES_CBC "DES-CBC:DES:1.3.14.3.2.7"
#define PROV_NAMES_DES_OFB "DES-OFB:1.3.14.3.2.8"
#define PROV_NAMES_DES_CFB "DES-CFB:1.3.14.3.2.9"
#define PROV_NAMES_DES_CFB1 "DES-CFB1"
#define PROV_NAMES_DES_CFB8 "DES-CFB8"

/*-
 * Digests
 * -------
 */
#define PROV_NAMES_SHA1 "SHA1:SHA-1:SSL3-SHA1:1.3.14.3.2.26"
#define PROV_NAMES_SHA2_224 "SHA2-224:SHA-224:SHA224:2.16.840.1.101.3.4.2.4"
#define PROV_NAMES_SHA2_256 "SHA2-256:SHA-256:SHA256:2.16.840.1.101.3.4.2.1"
#define PROV_NAMES_SHA2_256_192 "SHA2-256/192:SHA-256/192:SHA256-192"
#define PROV_NAMES_SHA2_384 "SHA2-384:SHA-384:SHA384:2.16.840.1.101.3.4.2.2"
#define PROV_NAMES_SHA2_512 "SHA2-512:SHA-512:SHA512:2.16.840.1.101.3.4.2.3"
#define PROV_NAMES_SHA2_512_224 "SHA2-512/224:SHA-512/224:SHA512-224:2.16.840.1.101.3.4.2.5"
#define PROV_NAMES_SHA2_512_256 "SHA2-512/256:SHA-512/256:SHA512-256:2.16.840.1.101.3.4.2.6"

/* We agree with NIST here, so one name only */
#define PROV_NAMES_SHA3_224 "SHA3-224:2.16.840.1.101.3.4.2.7"
#define PROV_NAMES_SHA3_256 "SHA3-256:2.16.840.1.101.3.4.2.8"
#define PROV_NAMES_SHA3_384 "SHA3-384:2.16.840.1.101.3.4.2.9"
#define PROV_NAMES_SHA3_512 "SHA3-512:2.16.840.1.101.3.4.2.10"

#define PROV_NAMES_KECCAK_224 "KECCAK-224"
#define PROV_NAMES_KECCAK_256 "KECCAK-256"
#define PROV_NAMES_KECCAK_384 "KECCAK-384"
#define PROV_NAMES_KECCAK_512 "KECCAK-512"

#define PROV_NAMES_SHAKE_128 "SHAKE-128:SHAKE128:2.16.840.1.101.3.4.2.11"
#define PROV_NAMES_SHAKE_256 "SHAKE-256:SHAKE256:2.16.840.1.101.3.4.2.12"

/*
 * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
 * KMAC128 and KMAC256.
 */
#define PROV_NAMES_KECCAK_KMAC_128 "KECCAK-KMAC-128:KECCAK-KMAC128"
#define PROV_NAMES_KECCAK_KMAC_256 "KECCAK-KMAC-256:KECCAK-KMAC256"
/*
 * https://blake2.net/ doesn't specify size variants, but mentions that
 * Bouncy Castle uses the names BLAKE2b-160, BLAKE2b-256, BLAKE2b-384, and
 * BLAKE2b-512
 * If we assume that "2b" and "2s" are versions, that pattern fits with ours.
 *  We also add our historical names.
 */
#define PROV_NAMES_BLAKE2S_256 "BLAKE2S-256:BLAKE2s256:1.3.6.1.4.1.1722.12.2.2.8"
#define PROV_NAMES_BLAKE2B_512 "BLAKE2B-512:BLAKE2b512:1.3.6.1.4.1.1722.12.2.1.16"
#define PROV_NAMES_SM3 "SM3:1.2.156.10197.1.401"
#define PROV_NAMES_MD5 "MD5:SSL3-MD5:1.2.840.113549.2.5"
#define PROV_NAMES_MD5_SHA1 "MD5-SHA1"
#define PROV_NAMES_MD2 "MD2:1.2.840.113549.2.2"
#define PROV_NAMES_MD4 "MD4:1.2.840.113549.2.4"
#define PROV_NAMES_MDC2 "MDC2:2.5.8.3.101"
#define PROV_NAMES_WHIRLPOOL "WHIRLPOOL:1.0.10118.3.0.55"
#define PROV_NAMES_RIPEMD_160 "RIPEMD-160:RIPEMD160:RIPEMD:RMD160:1.3.36.3.2.1"

/*-
 * KDFs / PRFs
 * -----------
 */
#define PROV_NAMES_HKDF "HKDF"
#define PROV_DESCS_HKDF_SIGN "OpenSSL HKDF via EVP_PKEY implementation"
#define PROV_NAMES_TLS1_3_KDF "TLS13-KDF"
#define PROV_NAMES_SSKDF "SSKDF"
#define PROV_NAMES_PBKDF1 "PBKDF1"
#define PROV_NAMES_PBKDF2 "PBKDF2:1.2.840.113549.1.5.12"
#define PROV_NAMES_PVKKDF "PVKKDF"
#define PROV_NAMES_SSHKDF "SSHKDF"
#define PROV_NAMES_X963KDF "X963KDF:X942KDF-CONCAT"
#define PROV_NAMES_X942KDF_ASN1 "X942KDF-ASN1:X942KDF"
#define PROV_NAMES_TLS1_PRF "TLS1-PRF"
#define PROV_DESCS_TLS1_PRF_SIGN "OpenSSL TLS1_PRF via EVP_PKEY implementation"
#define PROV_NAMES_KBKDF "KBKDF"
#define PROV_NAMES_PKCS12KDF "PKCS12KDF"
#define PROV_NAMES_SCRYPT "SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11"
#define PROV_DESCS_SCRYPT_SIGN "OpenSSL SCRYPT via EVP_PKEY implementation"
#define PROV_NAMES_KRB5KDF "KRB5KDF"
#define PROV_NAMES_HMAC_DRBG_KDF "HMAC-DRBG-KDF"
#define PROV_NAMES_ARGON2I "ARGON2I"
#define PROV_NAMES_ARGON2D "ARGON2D"
#define PROV_NAMES_ARGON2ID "ARGON2ID"

/*-
 * MACs
 * ----
 */
#define PROV_NAMES_HMAC "HMAC"
#define PROV_DESCS_HMAC_SIGN "OpenSSL HMAC via EVP_PKEY implementation"
#define PROV_NAMES_CMAC "CMAC"
#define PROV_DESCS_CMAC_SIGN "OpenSSL CMAC via EVP_PKEY implementation"
#define PROV_NAMES_SIPHASH "SIPHASH"
#define PROV_DESCS_SIPHASH_SIGN "OpenSSL SIPHASH via EVP_PKEY implementation"
#define PROV_NAMES_POLY1305 "POLY1305"
#define PROV_DESCS_POLY1305_SIGN "OpenSSL POLY1305 via EVP_PKEY implementation"
#define PROV_NAMES_GMAC "GMAC:1.0.9797.3.4"
#define PROV_NAMES_KMAC_128 "KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19"
#define PROV_NAMES_KMAC_256 "KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20"
#define PROV_NAMES_BLAKE2BMAC "BLAKE2BMAC:1.3.6.1.4.1.1722.12.2.1"
#define PROV_NAMES_BLAKE2SMAC "BLAKE2SMAC:1.3.6.1.4.1.1722.12.2.2"

/*-
 * RANDs
 * -----
 */
#define PROV_NAMES_CRNG_TEST "CRNG-TEST"
#define PROV_NAMES_CTR_DRBG "CTR-DRBG"
#define PROV_NAMES_HASH_DRBG "HASH-DRBG"
#define PROV_NAMES_HMAC_DRBG "HMAC-DRBG"
#define PROV_NAMES_TEST_RAND "TEST-RAND"
#define PROV_NAMES_SEED_SRC "SEED-SRC"
#define PROV_NAMES_JITTER "JITTER"

/*-
 * Asymmetric algos
 * ----------------
 */
#define PROV_NAMES_EC "EC:id-ecPublicKey:1.2.840.10045.2.1"
#define PROV_DESCS_EC "OpenSSL EC implementation"
#define PROV_NAMES_ECDH "ECDH"
#define PROV_DESCS_ECDH "OpenSSL ECDH implementation"
#define PROV_NAMES_ECDSA "ECDSA"
#define PROV_NAMES_ECDSA_SHA1 "ECDSA-SHA1:ECDSA-SHA-1:ecdsa-with-SHA1:1.2.840.10045.4.1"
#define PROV_NAMES_ECDSA_SHA224 "ECDSA-SHA2-224:ECDSA-SHA224:ecdsa-with-SHA224:1.2.840.10045.4.3.1"
#define PROV_NAMES_ECDSA_SHA256 "ECDSA-SHA2-256:ECDSA-SHA256:ecdsa-with-SHA256:1.2.840.10045.4.3.2"
#define PROV_NAMES_ECDSA_SHA384 "ECDSA-SHA2-384:ECDSA-SHA384:ecdsa-with-SHA384:1.2.840.10045.4.3.3"
#define PROV_NAMES_ECDSA_SHA512 "ECDSA-SHA2-512:ECDSA-SHA512:ecdsa-with-SHA512:1.2.840.10045.4.3.4"
#define PROV_NAMES_ECDSA_SHA3_224 "ECDSA-SHA3-224:ecdsa_with_SHA3-224:id-ecdsa-with-sha3-224:2.16.840.1.101.3.4.3.9"
#define PROV_NAMES_ECDSA_SHA3_256 "ECDSA-SHA3-256:ecdsa_with_SHA3-256:id-ecdsa-with-sha3-256:2.16.840.1.101.3.4.3.10"
#define PROV_NAMES_ECDSA_SHA3_384 "ECDSA-SHA3-384:ecdsa_with_SHA3-384:id-ecdsa-with-sha3-384:2.16.840.1.101.3.4.3.11"
#define PROV_NAMES_ECDSA_SHA3_512 "ECDSA-SHA3-512:ecdsa_with_SHA3-512:id-ecdsa-with-sha3-512:2.16.840.1.101.3.4.3.12"
#define PROV_DESCS_ECDSA "OpenSSL ECDSA implementation"
#define PROV_NAMES_X25519 "X25519:1.3.101.110"
#define PROV_DESCS_X25519 "OpenSSL X25519 implementation"
#define PROV_NAMES_X448 "X448:1.3.101.111"
#define PROV_DESCS_X448 "OpenSSL X448 implementation"
#define PROV_NAMES_ED25519 "ED25519:1.3.101.112"
#define PROV_DESCS_ED25519 "OpenSSL ED25519 implementation"
#define PROV_NAMES_ED25519ph "ED25519ph"
#define PROV_DESCS_ED25519ph "OpenSSL ED25519ph implementation"
#define PROV_NAMES_ED25519ctx "ED25519ctx"
#define PROV_DESCS_ED25519ctx "OpenSSL ED25519ctx implementation"
#define PROV_NAMES_ED448 "ED448:1.3.101.113"
#define PROV_DESCS_ED448 "OpenSSL ED448 implementation"
#define PROV_NAMES_ED448ph "ED448ph"
#define PROV_DESCS_ED448ph "OpenSSL ED448ph implementation"
#define PROV_NAMES_DH "DH:dhKeyAgreement:1.2.840.113549.1.3.1"
#define PROV_DESCS_DH "OpenSSL PKCS#3 DH implementation"
#define PROV_NAMES_DHX "DHX:X9.42 DH:dhpublicnumber:1.2.840.10046.2.1"
#define PROV_DESCS_DHX "OpenSSL X9.42 DH implementation"
#define PROV_NAMES_DSA "DSA:dsaEncryption:1.2.840.10040.4.1"
#define PROV_NAMES_DSA_SHA1 "DSA-SHA1:DSA-SHA-1:dsaWithSHA1:1.2.840.10040.4.3"
#define PROV_NAMES_DSA_SHA224 "DSA-SHA2-224:DSA-SHA224:dsa_with_SHA224:2.16.840.1.101.3.4.3.1"
#define PROV_NAMES_DSA_SHA256 "DSA-SHA2-256:DSA-SHA256:dsa_with_SHA256:2.16.840.1.101.3.4.3.2"
#define PROV_NAMES_DSA_SHA384 "DSA-SHA2-384:DSA-SHA384:dsa_with_SHA384:id-dsa-with-sha384:1.2.840.1.101.3.4.3.3"
#define PROV_NAMES_DSA_SHA512 "DSA-SHA2-512:DSA-SHA512:dsa_with_SHA512:id-dsa-with-sha512:1.2.840.1.101.3.4.3.4"
#define PROV_NAMES_DSA_SHA3_224 "DSA-SHA3-224:dsa_with_SHA3-224:id-dsa-with-sha3-224:2.16.840.1.101.3.4.3.5"
#define PROV_NAMES_DSA_SHA3_256 "DSA-SHA3-256:dsa_with_SHA3-256:id-dsa-with-sha3-256:2.16.840.1.101.3.4.3.6"
#define PROV_NAMES_DSA_SHA3_384 "DSA-SHA3-384:dsa_with_SHA3-384:id-dsa-with-sha3-384:2.16.840.1.101.3.4.3.7"
#define PROV_NAMES_DSA_SHA3_512 "DSA-SHA3-512:dsa_with_SHA3-512:id-dsa-with-sha3-512:2.16.840.1.101.3.4.3.8"
#define PROV_DESCS_DSA "OpenSSL DSA implementation"
#define PROV_NAMES_RSA "RSA:rsaEncryption:1.2.840.113549.1.1.1"
#define PROV_NAMES_RSA_MD2 "RSA-MD2:md2WithRSAEncryption:1.2.840.113549.1.1.2"
#define PROV_NAMES_RSA_MD4 "RSA-MD4:md4WithEncryption:1.2.840.113549.1.1.3"
#define PROV_NAMES_RSA_MD5 "RSA-MD5:md5WithRSAEncryption:1.2.840.113549.1.1.4"
#define PROV_NAMES_RSA_RIPEMD160 "RSA-RIPEMD160:ripemd160WithRSA:1.3.36.3.3.1.2"
#define PROV_NAMES_RSA_SHA1 "RSA-SHA1:RSA-SHA-1:sha1WithRSAEncryption:1.2.840.113549.1.1.5"
#define PROV_NAMES_RSA_SHA256 "RSA-SHA2-256:RSA-SHA256:sha256WithRSAEncryption:1.2.840.113549.1.1.11"
#define PROV_NAMES_RSA_SHA384 "RSA-SHA2-384:RSA-SHA384:sha384WithRSAEncryption:1.2.840.113549.1.1.12"
#define PROV_NAMES_RSA_SHA512 "RSA-SHA2-512:RSA-SHA512:sha512WithRSAEncryption:1.2.840.113549.1.1.13"
#define PROV_NAMES_RSA_SHA224 "RSA-SHA2-224:RSA-SHA224:sha224WithRSAEncryption:1.2.840.113549.1.1.14"
#define PROV_NAMES_RSA_SHA512_224 "RSA-SHA2-512/224:RSA-SHA512-224:sha512-224WithRSAEncryption:1.2.840.113549.1.1.15"
#define PROV_NAMES_RSA_SHA512_256 "RSA-SHA2-512/256:RSA-SHA512-256:sha512-256WithRSAEncryption:1.2.840.113549.1.1.16"
#define PROV_NAMES_RSA_SM3 "RSA-SM3:sm3WithRSAEncryption:1.2.156.10197.1.504"
#define PROV_NAMES_RSA_SHA3_224 "RSA-SHA3-224:id-rsassa-pkcs1-v1_5-with-sha3-224:2.16.840.1.101.3.4.3.13"
#define PROV_NAMES_RSA_SHA3_256 "RSA-SHA3-256:id-rsassa-pkcs1-v1_5-with-sha3-256:2.16.840.1.101.3.4.3.14"
#define PROV_NAMES_RSA_SHA3_384 "RSA-SHA3-384:id-rsassa-pkcs1-v1_5-with-sha3-384:2.16.840.1.101.3.4.3.15"
#define PROV_NAMES_RSA_SHA3_512 "RSA-SHA3-512:id-rsassa-pkcs1-v1_5-with-sha3-512:2.16.840.1.101.3.4.3.16"
#define PROV_DESCS_RSA "OpenSSL RSA implementation"
#define PROV_NAMES_RSA_PSS "RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10"
#define PROV_DESCS_RSA_PSS "OpenSSL RSA-PSS implementation"
#define PROV_NAMES_SM2 "SM2:1.2.156.10197.1.301"
#define PROV_DESCS_SM2 "OpenSSL SM2 implementation"

/*
 * SLH_DSA OIDS are defined in
 * https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#DSA
 */
#define PROV_NAMES_SLH_DSA_SHA2_128S "SLH-DSA-SHA2-128s:2.16.840.1.101.3.4.3.20"
#define PROV_DESCS_SLH_DSA_SHA2_128S "OpenSSL SLH-DSA-SHA2-128s implementation"
