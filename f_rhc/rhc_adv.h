/*
 * RHC Protocol Core - ADVANCED Implementation
 *
 * This standalone version implements 4 military-grade security features:
 * 1. HMAC-SHA256 Token Binding
 * 2. IP & User-Agent Binding
 * 3. Honeypot Bans (Active Defense)
 * 4. Exponential Rate Limiting
 */

#ifndef RHC_ADV_H
#define RHC_ADV_H

#include <stdint.h>
#include <time.h>
#include "rhc_config.h"

#define RHC_ADV_MAX_IP_LEN 46
#define RHC_ADV_MAX_UA_LEN 256
#define RHC_ADV_MAX_BANS   128

typedef enum {
    RHC_ADV_LEVEL_1 = 1,
    RHC_ADV_LEVEL_2 = 2,
    RHC_ADV_LEVEL_3 = 3,
    RHC_ADV_LEVEL_4 = 4
} RhcAdvLevel;

typedef enum {
    RHC_ADV_MODE_A = 0,
    RHC_ADV_MODE_B = 1
} RhcAdvMode;

typedef enum {
    RHC_ADV_OK               = 0,
    RHC_ADV_ERR_BAD_TOKEN    = 1,
    RHC_ADV_ERR_BAD_HEADER   = 2,
    RHC_ADV_ERR_REPLAY       = 3,
    RHC_ADV_ERR_EXPIRED      = 4,
    RHC_ADV_ERR_NO_TOKEN     = 5,
    RHC_ADV_ERR_DECOY_SENT   = 6,
    RHC_ADV_ERR_IP_MISMATCH  = 7,
    RHC_ADV_ERR_BANNED       = 8,
    RHC_ADV_ERR_RATE_LIMITED = 9
} RhcAdvStatus;

typedef struct {
    char name[RHC_MAX_HEADER_NAME];
    char value[RHC_MAX_TOKEN_LEN];
    int  is_decoy;
} RhcAdvHeader;

typedef struct {
    RhcAdvHeader headers[RHC_MAX_HEADERS];
    int          header_count;
    char         nonce[RHC_MAX_NONCE_LEN];
    time_t       timestamp;
    
    /* Request Metadata (Simulated as coming from HTTP stack) */
    char         client_ip[RHC_ADV_MAX_IP_LEN];
    char         user_agent[RHC_ADV_MAX_UA_LEN];
} RhcAdvRequest;

typedef struct {
    RhcAdvLevel level;
    RhcAdvMode  mode;

    char     expected_header[RHC_MAX_HEADER_NAME];
    char     expected_token[RHC_MAX_TOKEN_LEN];
    int      token_byte_len;

    char     nonce_cache[RHC_NONCE_CACHE][RHC_MAX_NONCE_LEN];
    int      nonce_cache_idx;
    int      nonce_cache_count;

    uint32_t session_id;
    
    /* ── Advanced Features State ── */
    
    /* 1. HMAC Secret Key */
    uint8_t  hmac_secret[32];
    
    /* 2. Client Binding */
    char     bound_ip[RHC_ADV_MAX_IP_LEN];
    char     bound_ua[RHC_ADV_MAX_UA_LEN];
    
    /* 3. Honeypot Bans */
    int      is_banned;
    char     banned_ips[RHC_ADV_MAX_BANS][RHC_ADV_MAX_IP_LEN];
    int      ban_count;
    
    /* 4. Rate Limiting */
    int      failed_attempts;
    time_t   lockout_until;

} RhcAdvSession;

typedef struct {
    RhcAdvStatus status;
    const char  *message;
    char         found_header[RHC_MAX_HEADER_NAME];
    char         found_token[RHC_MAX_TOKEN_LEN];
    int          delay_applied_ms; /* Rate limiting delay applied */
} RhcAdvResult;

/* API Functions */
void rhc_adv_session_init(RhcAdvSession *session, RhcAdvLevel level, RhcAdvMode mode, const char *client_ip, const char *user_agent);
RhcAdvRequest rhc_adv_build_request(RhcAdvSession *session);
RhcAdvResult rhc_adv_validate(RhcAdvSession *session, const RhcAdvRequest *req);
void rhc_adv_rotate(RhcAdvSession *session);

void rhc_adv_print_request(const RhcAdvRequest *req);
void rhc_adv_print_result(const RhcAdvResult *result);
void rhc_adv_print_session(const RhcAdvSession *session);

#endif /* RHC_ADV_H */
