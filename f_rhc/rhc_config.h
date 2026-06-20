/*
 * RHC Protocol Core - Configuration File
 *
 * This file contains all the tunable parameters for the RHC Protocol.
 * Adjust these values based on your security and memory requirements.
 */

#ifndef RHC_CONFIG_H
#define RHC_CONFIG_H

/* ─────────────────────────────────────────────
   BUFFER SIZES & LIMITS
   ───────────────────────────────────────────── */

/* Maximum number of headers allowed in a single request (Real + Decoys) */
#define RHC_MAX_HEADERS       24

/* Maximum string length for a header name (e.g. "X-Random-Auth") */
#define RHC_MAX_HEADER_NAME   32

/* Maximum string length for a token (128 hex chars + 1 null terminator) */
#define RHC_MAX_TOKEN_LEN     129

/* Maximum string length for a nonce (32 hex chars + 1 null terminator) */
#define RHC_MAX_NONCE_LEN     33


/* ─────────────────────────────────────────────
   REPLAY PROTECTION SETTINGS
   ───────────────────────────────────────────── */

/* Number of nonces to keep in memory to detect replay attacks.
 * Higher = safer, but uses more memory per session. */
#define RHC_NONCE_CACHE       64

/* Maximum age of a request in seconds before it is rejected as expired. */
#define RHC_TIMESTAMP_WINDOW  30


/* ─────────────────────────────────────────────
   ENTROPY SETTINGS (TOKEN LENGTHS)
   ───────────────────────────────────────────── */

/* Token lengths in bytes (Note: hex output will be twice this length) */
#define TOKEN_LEN_8           8
#define TOKEN_LEN_16          16
#define TOKEN_LEN_32          32
#define TOKEN_LEN_64          64

#endif /* RHC_CONFIG_H */
