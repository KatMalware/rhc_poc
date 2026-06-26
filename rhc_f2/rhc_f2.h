/*
 * RHC Protocol Core - F2 Extension
 *
 * Builds upon the Advanced Implementation with 3 new features:
 * 1. Multi-Header Conjoint Validation (Level 0+ from Fernando's roadmap)
 * 2. Per-Token TTL (Time-To-Live) — individual token expiry
 * 3. Audit & Forensics Logger — structured JSON logging
 *
 * Plus all existing Advanced features:
 * - HMAC-SHA256 Token Binding
 * - IP & User-Agent Session Locking
 * - Honeypot Active Defense
 * - Exponential Rate Limiting
 * - Constant-Time Comparison
 * - Flat Frequency Distribution
 * - Nonce/Timestamp Replay Protection
 */

#ifndef RHC_F2_H
#define RHC_F2_H

#include <stdint.h>
#include <time.h>
#include <stdio.h>
#include "../rhc_config.h"

/* ── F2 Extension Constants ── */
#define RHC_F2_MAX_IP_LEN         46
#define RHC_F2_MAX_UA_LEN         256
#define RHC_F2_MAX_BANS           128
#define RHC_F2_MAX_CONJOINT       3       /* Max simultaneous valid headers */
#define RHC_F2_DEFAULT_TOKEN_TTL  10      /* Per-token TTL in seconds */
#define RHC_F2_AUDIT_FILE         "rhc_audit.jsonl"
#define RHC_F2_MAX_LOG_LINE       1024

/* ── Enums ── */

typedef enum {
    RHC_F2_LEVEL_1 = 1,
    RHC_F2_LEVEL_2 = 2,
    RHC_F2_LEVEL_3 = 3,
    RHC_F2_LEVEL_4 = 4
} RhcF2Level;

typedef enum {
    RHC_F2_MODE_A = 0,
    RHC_F2_MODE_B = 1
} RhcF2Mode;

typedef enum {
    RHC_F2_OK                = 0,
    RHC_F2_ERR_BAD_TOKEN     = 1,
    RHC_F2_ERR_BAD_HEADER    = 2,
    RHC_F2_ERR_REPLAY        = 3,
    RHC_F2_ERR_EXPIRED       = 4,
    RHC_F2_ERR_NO_TOKEN      = 5,
    RHC_F2_ERR_DECOY_SENT    = 6,
    RHC_F2_ERR_IP_MISMATCH   = 7,
    RHC_F2_ERR_BANNED        = 8,
    RHC_F2_ERR_RATE_LIMITED  = 9,
    RHC_F2_ERR_TOKEN_TTL     = 10,   /* NEW: Individual token expired */
    RHC_F2_ERR_CONJOINT_MISS = 11    /* NEW: Missing conjoint header */
} RhcF2Status;

/* ── Structs ── */

typedef struct {
    char name[RHC_MAX_HEADER_NAME];
    char value[RHC_MAX_TOKEN_LEN];
    int  is_decoy;
} RhcF2Header;

typedef struct {
    RhcF2Header headers[RHC_MAX_HEADERS];
    int         header_count;
    char        nonce[RHC_MAX_NONCE_LEN];
    time_t      timestamp;

    /* Request Metadata */
    char        client_ip[RHC_F2_MAX_IP_LEN];
    char        user_agent[RHC_F2_MAX_UA_LEN];
} RhcF2Request;

typedef struct {
    RhcF2Level level;
    RhcF2Mode  mode;

    /* ── Conjoint Validation State ── */
    int      num_active_valid;                                    /* 1-3 valid headers this cycle */
    char     expected_headers[RHC_F2_MAX_CONJOINT][RHC_MAX_HEADER_NAME];
    char     expected_tokens[RHC_F2_MAX_CONJOINT][RHC_MAX_TOKEN_LEN];
    int      token_byte_len;

    /* ── Nonce Cache ── */
    char     nonce_cache[RHC_NONCE_CACHE][RHC_MAX_NONCE_LEN];
    int      nonce_cache_idx;
    int      nonce_cache_count;

    uint32_t session_id;

    /* ── HMAC Secret Key ── */
    uint8_t  hmac_secret[32];

    /* ── Client Binding ── */
    char     bound_ip[RHC_F2_MAX_IP_LEN];
    char     bound_ua[RHC_F2_MAX_UA_LEN];

    /* ── Honeypot Bans ── */
    int      is_banned;
    char     banned_ips[RHC_F2_MAX_BANS][RHC_F2_MAX_IP_LEN];
    int      ban_count;

    /* ── Rate Limiting ── */
    int      failed_attempts;
    time_t   lockout_until;

    /* ── Token TTL ── */
    time_t   token_created_at;          /* When current tokens were generated */
    int      token_ttl;                 /* Per-token TTL in seconds */

    /* ── Audit Logger ── */
    int      audit_enabled;             /* 1 = logging on, 0 = off */
    char     audit_filepath[256];       /* Path to the JSONL log file */

} RhcF2Session;

typedef struct {
    RhcF2Status status;
    const char *message;
    char        found_header[RHC_MAX_HEADER_NAME];
    char        found_token[RHC_MAX_TOKEN_LEN];
    int         delay_applied_ms;
    int         conjoint_matched;       /* How many conjoint headers matched */
    int         conjoint_required;      /* How many were required */
} RhcF2Result;

/* ── Audit Log Entry ── */
typedef struct {
    time_t       timestamp;
    uint32_t     session_id;
    char         client_ip[RHC_F2_MAX_IP_LEN];
    const char  *action;         /* "VALIDATE", "HONEYPOT_BAN", "RATE_LIMIT" */
    const char  *result;         /* "ACCEPT", "REJECT" */
    const char  *reason;         /* Detailed reason string */
    int          conjoint_matched;
    int          conjoint_required;
} RhcF2AuditEntry;

/* ── Public API ── */

void        rhc_f2_session_init(RhcF2Session *session, RhcF2Level level, RhcF2Mode mode,
                                const char *client_ip, const char *user_agent);
RhcF2Request rhc_f2_build_request(RhcF2Session *session);
RhcF2Result  rhc_f2_validate(RhcF2Session *session, const RhcF2Request *req);
void         rhc_f2_rotate(RhcF2Session *session);

/* Display helpers */
void rhc_f2_print_request(const RhcF2Request *req);
void rhc_f2_print_result(const RhcF2Result *result);
void rhc_f2_print_session(const RhcF2Session *session);

/* Audit API */
void rhc_f2_audit_enable(RhcF2Session *session, const char *filepath);
void rhc_f2_audit_disable(RhcF2Session *session);

/* TTL API */
void rhc_f2_set_token_ttl(RhcF2Session *session, int ttl_seconds);

#endif /* RHC_F2_H */
