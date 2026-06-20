/*
 * RHC Protocol Core - ADVANCED Implementation
 *
 * Implements HMAC binding, IP binding, Honeypot Bans, and Rate Limiting.
 */

#define _DEFAULT_SOURCE /* For usleep */
#include "rhc_adv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/hmac.h>

/* Helper: Constant-time memcmp */
static int ct_memcmp(const char *a, const char *b, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= ((unsigned char*)a)[i] ^ ((unsigned char*)b)[i];
    }
    return (result != 0);
}

/* Helper: secure random bytes */
static void read_random_bytes(uint8_t *out, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t read_bytes = fread(out, 1, len, f);
        fclose(f);
        if (read_bytes == len) return;
    }
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(rand() % 256);
}

static void bytes_to_hex(const uint8_t *in, size_t len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(in[i] >> 4) & 0x0F];
        out[i*2+1] = hex[in[i] & 0x0F];
    }
    out[len*2] = '\0';
}

void rhc_adv_gen_nonce(char *out) {
    uint8_t buf[16];
    read_random_bytes(buf, 16);
    bytes_to_hex(buf, 16, out);
}

/* Generate HMAC-SHA256 Token: HMAC(Secret, Nonce || Timestamp || SessionID) */
static void generate_hmac_token(RhcAdvSession *session, const char *nonce, time_t ts, char *out_hex) {
    char data[256];
    snprintf(data, sizeof(data), "%s_%ld_%u", nonce, (long)ts, session->session_id);
    
    unsigned int len = 32;
    unsigned char hash[32];
    HMAC(EVP_sha256(), session->hmac_secret, 32,
         (unsigned char*)data, strlen(data), hash, &len);
         
    bytes_to_hex(hash, len, out_hex);
}

static const char *VALID_HEADERS[] = {
    "X-A1", "X-B3", "X-C7", "X-D2", "X-E8", "X-F5", "X-G4", "X-H6"
};
static const char *DECOY_HEADERS[] = {
    "X-T1", "X-T2", "X-T3", "X-T4", "X-T5",
    "X-M1", "X-M2", "X-M3", "X-N9", "X-P0", "X-Q2", "X-R7"
};

void rhc_adv_session_init(RhcAdvSession *session, RhcAdvLevel level, RhcAdvMode mode, const char *client_ip, const char *user_agent) {
    memset(session, 0, sizeof(RhcAdvSession));
    session->level = level;
    session->mode = mode;
    
    uint8_t sid[4];
    read_random_bytes(sid, 4);
    session->session_id = ((uint32_t)sid[0] << 24) | ((uint32_t)sid[1] << 16) |
                          ((uint32_t)sid[2] <<  8) | ((uint32_t)sid[3]);

    /* Init Advanced State */
    read_random_bytes(session->hmac_secret, 32);
    strncpy(session->bound_ip, client_ip, RHC_ADV_MAX_IP_LEN - 1);
    strncpy(session->bound_ua, user_agent, RHC_ADV_MAX_UA_LEN - 1);
    
    session->token_byte_len = 32; /* HMAC-SHA256 is 32 bytes (64 hex chars) */
    
    rhc_adv_rotate(session);
}

void rhc_adv_rotate(RhcAdvSession *session) {
    /* Pick a random valid header */
    uint8_t r;
    read_random_bytes(&r, 1);
    int idx = r % 8;
    strncpy(session->expected_header, VALID_HEADERS[idx], RHC_MAX_HEADER_NAME - 1);
    
    /* We DO NOT generate expected_token here anymore.
       Because HMAC token depends on the request's Nonce and Timestamp!
       The server will generate the expected HMAC on-the-fly during validation.
    */
}

RhcAdvRequest rhc_adv_build_request(RhcAdvSession *session) {
    RhcAdvRequest req;
    memset(&req, 0, sizeof(RhcAdvRequest));
    
    strncpy(req.client_ip, session->bound_ip, RHC_ADV_MAX_IP_LEN - 1);
    strncpy(req.user_agent, session->bound_ua, RHC_ADV_MAX_UA_LEN - 1);
    
    rhc_adv_gen_nonce(req.nonce);
    req.timestamp = time(NULL);
    
    /* Client generates the HMAC (assuming client knows the secret in this PoC) */
    char valid_token[RHC_MAX_TOKEN_LEN];
    generate_hmac_token(session, req.nonce, req.timestamp, valid_token);
    
    int hcount = 0;
    
    /* Level 4: Add ALL decoys */
    for (int i = 0; i < 12 && hcount < RHC_MAX_HEADERS; i++) {
        strncpy(req.headers[hcount].name, DECOY_HEADERS[i], RHC_MAX_HEADER_NAME - 1);
        
        char dummy_nonce[33];
        rhc_adv_gen_nonce(dummy_nonce);
        generate_hmac_token(session, dummy_nonce, req.timestamp, req.headers[hcount].value);
        req.headers[hcount].is_decoy = 1;
        hcount++;
    }
    
    /* Level 4: Add all unused valid headers as decoys */
    for (int i = 0; i < 8 && hcount < RHC_MAX_HEADERS; i++) {
        if (strcmp(VALID_HEADERS[i], session->expected_header) == 0) continue;
        strncpy(req.headers[hcount].name, VALID_HEADERS[i], RHC_MAX_HEADER_NAME - 1);
        
        char dummy_nonce[33];
        rhc_adv_gen_nonce(dummy_nonce);
        generate_hmac_token(session, dummy_nonce, req.timestamp, req.headers[hcount].value);
        req.headers[hcount].is_decoy = 1;
        hcount++;
    }
    
    /* Insert Real Header */
    int real_pos = rand() % (hcount + 1);
    for (int i = hcount; i > real_pos; i--) req.headers[i] = req.headers[i-1];
    
    strncpy(req.headers[real_pos].name, session->expected_header, RHC_MAX_HEADER_NAME - 1);
    strncpy(req.headers[real_pos].value, valid_token, RHC_MAX_TOKEN_LEN - 1);
    req.headers[real_pos].is_decoy = 0;
    
    hcount++;
    req.header_count = hcount;
    
    return req;
}

RhcAdvResult rhc_adv_validate(RhcAdvSession *session, const RhcAdvRequest *req) {
    RhcAdvResult result;
    memset(&result, 0, sizeof(RhcAdvResult));
    
    /* Apply Rate Limiting Delay */
    if (session->failed_attempts > 0) {
        int delay_ms = session->failed_attempts * 200; /* 200ms per fail */
        if (delay_ms > 5000) delay_ms = 5000;
        usleep(delay_ms * 1000);
        result.delay_applied_ms = delay_ms;
    }
    
    /* 1. Global Ban Check */
    if (session->is_banned) {
        result.status = RHC_ADV_ERR_BANNED;
        result.message = "REJECT: IP is permanently banned (Honeypot Triggered).";
        return result;
    }

    /* 2. IP / UA Binding Check */
    if (strcmp(req->client_ip, session->bound_ip) != 0 || 
        strcmp(req->user_agent, session->bound_ua) != 0) {
        session->failed_attempts++;
        result.status = RHC_ADV_ERR_IP_MISMATCH;
        result.message = "REJECT: Session hijacked! IP or User-Agent mismatch.";
        return result;
    }

    /* 3. Timestamp Check */
    double age = difftime(time(NULL), req->timestamp);
    if (age < 0 || age > RHC_TIMESTAMP_WINDOW) {
        session->failed_attempts++;
        result.status = RHC_ADV_ERR_EXPIRED;
        result.message = "REJECT: Timestamp expired.";
        return result;
    }

    /* 4. Nonce Replay Check */
    for (int i = 0; i < session->nonce_cache_count; i++) {
        if (strcmp(session->nonce_cache[i], req->nonce) == 0) {
            session->failed_attempts++;
            result.status = RHC_ADV_ERR_REPLAY;
            result.message = "REJECT: Nonce replayed.";
            return result;
        }
    }

    /* 5. Token Check (HMAC on the fly) */
    char expected_hmac[RHC_MAX_TOKEN_LEN];
    generate_hmac_token(session, req->nonce, req->timestamp, expected_hmac);

    for (int i = 0; i < req->header_count; i++) {
        const char *hname = req->headers[i].name;
        const char *hval  = req->headers[i].value;

        if (strcmp(hname, session->expected_header) == 0) {
            strncpy(result.found_header, hname, RHC_MAX_HEADER_NAME - 1);
            strncpy(result.found_token, hval, RHC_MAX_TOKEN_LEN - 1);
            
            if (strlen(hval) == 64 && ct_memcmp(hval, expected_hmac, 64) == 0) {
                /* Valid! */
                strncpy(session->nonce_cache[session->nonce_cache_idx], req->nonce, RHC_MAX_NONCE_LEN - 1);
                session->nonce_cache_idx = (session->nonce_cache_idx + 1) % RHC_NONCE_CACHE;
                if (session->nonce_cache_count < RHC_NONCE_CACHE) session->nonce_cache_count++;
                
                session->failed_attempts = 0; /* Reset rate limit */
                result.status = RHC_ADV_OK;
                result.message = "ACCEPT: Valid HMAC Token, Fresh Nonce, Valid IP.";
                return result;
            } else {
                session->failed_attempts++;
                result.status = RHC_ADV_ERR_BAD_TOKEN;
                result.message = "REJECT: Invalid HMAC Token.";
                return result;
            }
        }
        
        /* HONEYPOT CHECK: Did attacker try to use a Decoy Header as Auth? */
        for (int d = 0; d < 12; d++) {
            if (strcmp(hname, DECOY_HEADERS[d]) == 0 && strlen(hval) == 64 && ct_memcmp(hval, expected_hmac, 64) == 0) {
                /* Attacker somehow forged a valid HMAC for a decoy header, or simply tried to brute force a decoy */
                session->is_banned = 1;
                strncpy(session->banned_ips[session->ban_count++], req->client_ip, RHC_ADV_MAX_IP_LEN - 1);
                
                result.status = RHC_ADV_ERR_DECOY_SENT;
                result.message = "CRITICAL: Honeypot Triggered! IP Banned permanently.";
                return result;
            }
        }
    }
    
    session->failed_attempts++;
    result.status = RHC_ADV_ERR_NO_TOKEN;
    result.message = "REJECT: Missing Header.";
    return result;
}

void rhc_adv_print_request(const RhcAdvRequest *req) {
    printf("\n┌─── RHC Advanced Request ────────────────────────\n");
    printf("│ Client IP : %s\n", req->client_ip);
    printf("│ User-Agent: %s\n", req->user_agent);
    printf("│ Timestamp : %ld\n", (long)req->timestamp);
    printf("│ Nonce     : %.12s...\n", req->nonce);
    printf("│ Headers   :\n");
    for (int i = 0; i < req->header_count; i++) {
        printf("│   %-10s : %.20s...\n", req->headers[i].name, req->headers[i].value);
    }
    printf("└────────────────────────────────────────────────\n");
}

void rhc_adv_print_result(const RhcAdvResult *result) {
    printf("\n┌─── Validation Result ───────────────────────────\n");
    if (result->delay_applied_ms > 0) {
        printf("│ [Rate Limit] Delayed response by %d ms\n", result->delay_applied_ms);
    }
    if (result->status == RHC_ADV_OK) {
        printf("│ \033[1;32m%s\033[0m\n", result->message);
    } else {
        printf("│ \033[1;31m%s\033[0m\n", result->message);
    }
    printf("└────────────────────────────────────────────────\n");
}
