/*
 * RHC Protocol Core - C Implementation
 * Randomized Header Channel for Communication Integrity
 *
 * Author (Original Concept): Fernando Flores Alvarado
 * C PoC Implementation: Contribution / Testing
 *
 * Levels:
 *   Level 1 - Basic:    1 token, 1 of 3 random headers
 *   Level 2 - Medium:   Random header + dynamic token assignment
 *   Level 3 - Advanced: Variable token lengths (8/16/32/64 bytes)
 *   Level 4 - Dynamic:  Decoy headers + adaptive entropy + full rotation
 *
 * Replay Protection: Nonce + Timestamp validation (added contribution)
 */

#ifndef RHC_H
#define RHC_H

#include <stdint.h>
#include <time.h>

#include "rhc_config.h"

/* ─────────────────────────────────────────────
   ENUMS
   ───────────────────────────────────────────── */

typedef enum {
    RHC_LEVEL_1 = 1,   /* Basic rotation */
    RHC_LEVEL_2 = 2,   /* Header + token randomization */
    RHC_LEVEL_3 = 3,   /* Variable token lengths */
    RHC_LEVEL_4 = 4    /* Full: decoys + adaptive entropy */
} RhcLevel;

typedef enum {
    RHC_MODE_A = 0,    /* Fixed assignment */
    RHC_MODE_B = 1     /* Random assignment */
} RhcMode;

typedef enum {
    RHC_OK              = 0,
    RHC_ERR_BAD_TOKEN   = 1,
    RHC_ERR_BAD_HEADER  = 2,
    RHC_ERR_REPLAY      = 3,
    RHC_ERR_EXPIRED     = 4,
    RHC_ERR_NO_TOKEN    = 5,
    RHC_ERR_DECOY_SENT  = 6    /* attacker sent a decoy header as real */
} RhcStatus;

/* ─────────────────────────────────────────────
   STRUCTS
   ───────────────────────────────────────────── */

/* A single HTTP-like header: name + value */
typedef struct {
    char name[RHC_MAX_HEADER_NAME];
    char value[RHC_MAX_TOKEN_LEN];
    int  is_decoy;   /* 1 = fake/decoy, 0 = potentially real */
} RhcHeader;

/* A simulated HTTP request with RHC headers */
typedef struct {
    RhcHeader headers[RHC_MAX_HEADERS];
    int        header_count;
    char       nonce[RHC_MAX_NONCE_LEN];
    time_t     timestamp;
} RhcRequest;

/* Server-side session state */
typedef struct {
    RhcLevel level;
    RhcMode  mode;

    /* The ONE valid header name server expects */
    char     expected_header[RHC_MAX_HEADER_NAME];

    /* The ONE valid token server expects */
    char     expected_token[RHC_MAX_TOKEN_LEN];

    /* Token byte length (for Level 3/4) */
    int      token_byte_len;

    /* Nonce cache for replay protection */
    char     nonce_cache[RHC_NONCE_CACHE][RHC_MAX_NONCE_LEN];
    int      nonce_cache_idx;
    int      nonce_cache_count;

    /* Session ID */
    uint32_t session_id;
} RhcSession;

/* Validation result with detail */
typedef struct {
    RhcStatus status;
    const char *message;
    char found_header[RHC_MAX_HEADER_NAME];
    char found_token[RHC_MAX_TOKEN_LEN];
} RhcResult;

/* ─────────────────────────────────────────────
   PUBLIC API
   ───────────────────────────────────────────── */

/* Initialize a new RHC session */
void rhc_session_init(RhcSession *session, RhcLevel level, RhcMode mode);

/* Generate secure random bytes → hex string */
void rhc_gen_token(char *out, int byte_len);

/* Generate a nonce for replay protection */
void rhc_gen_nonce(char *out);

/* Build a client request at given level */
RhcRequest rhc_build_request(RhcSession *session);

/* Server validates an incoming request */
RhcResult rhc_validate(RhcSession *session, const RhcRequest *req);

/* Rotate session state (call after each valid request) */
void rhc_rotate(RhcSession *session);

/* Print a request (for debugging/demo) */
void rhc_print_request(const RhcRequest *req);

/* Print validation result */
void rhc_print_result(const RhcResult *result);

/* Print session state */
void rhc_print_session(const RhcSession *session);

#endif /* RHC_H */
