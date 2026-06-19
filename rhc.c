/*
 * RHC Protocol Core - C Implementation
 * rhc.c — Core logic
 */

#include "rhc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

/* ─────────────────────────────────────────────
   INTERNAL HELPER: Read random bytes from /dev/urandom
   ───────────────────────────────────────────── */

static void read_random_bytes(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    size_t read_len = 0;
    if (f) {
        read_len = fread(buf, 1, len, f);
        fclose(f);
    }
    
    if (read_len < len) {
        /* Fallback: not cryptographically secure, only for demo */
        srand((unsigned)time(NULL) ^ (unsigned long)buf ^ (unsigned long)read_len);
        for (size_t i = read_len; i < len; i++)
            buf[i] = (uint8_t)(rand() & 0xFF);
    }
}

/* ─────────────────────────────────────────────
   INTERNAL: Convert bytes to hex string
   ───────────────────────────────────────────── */

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]     = hex[(bytes[i] >> 4) & 0xF];
        out[i*2 + 1] = hex[bytes[i] & 0xF];
    }
    out[len * 2] = '\0';
}

/* ─────────────────────────────────────────────
   INTERNAL: Random number in [0, max)
   ───────────────────────────────────────────── */

static int rand_int(int max) {
    uint8_t buf[4];
    read_random_bytes(buf, 4);
    uint32_t val = ((uint32_t)buf[0] << 24) |
                   ((uint32_t)buf[1] << 16) |
                   ((uint32_t)buf[2] <<  8) |
                   ((uint32_t)buf[3]);
    return (int)(val % (uint32_t)max);
}

/* ─────────────────────────────────────────────
   INTERNAL: Valid header pool per level
   ───────────────────────────────────────────── */

/* Level 1-2: 3 fixed valid header names to pick from */
static const char *VALID_HEADERS_L1[] = { "X-A1", "X-B3", "X-C7" };
#define N_VALID_L1 3

/* Level 3-4: Larger pool for more entropy */
static const char *VALID_HEADERS_L3[] = {
    "X-A1", "X-B3", "X-C7",
    "X-D2", "X-E8", "X-F5",
    "X-G4", "X-H6"
};
#define N_VALID_L3 8

/* Level 4 decoy header name pool */
static const char *DECOY_HEADERS[] = {
    "X-T1", "X-T2", "X-T3", "X-T4", "X-T5",
    "X-M1", "X-M2", "X-M3", "X-N9", "X-P0",
    "X-Q2", "X-R7"
};
#define N_DECOY 12

/* ─────────────────────────────────────────────
   PUBLIC: rhc_gen_token
   Generates a cryptographically random hex token.
   byte_len: 8, 16, 32, or 64
   ───────────────────────────────────────────── */

void rhc_gen_token(char *out, int byte_len) {
    if (byte_len > 64) byte_len = 64;
    uint8_t buf[64];
    read_random_bytes(buf, (size_t)byte_len);
    bytes_to_hex(buf, (size_t)byte_len, out);
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_gen_nonce
   16-byte (32 hex char) unique nonce
   ───────────────────────────────────────────── */

void rhc_gen_nonce(char *out) {
    uint8_t buf[16];
    read_random_bytes(buf, 16);
    bytes_to_hex(buf, 16, out);
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_session_init
   ───────────────────────────────────────────── */

void rhc_session_init(RhcSession *session, RhcLevel level, RhcMode mode) {
    memset(session, 0, sizeof(RhcSession));
    session->level = level;
    session->mode  = mode;

    /* Assign a random session ID */
    uint8_t sid[4];
    read_random_bytes(sid, 4);
    session->session_id = ((uint32_t)sid[0] << 24) | ((uint32_t)sid[1] << 16) |
                          ((uint32_t)sid[2] <<  8) | ((uint32_t)sid[3]);

    /* Default token length based on level */
    switch (level) {
        case RHC_LEVEL_1: session->token_byte_len = TOKEN_LEN_8;  break;
        case RHC_LEVEL_2: session->token_byte_len = TOKEN_LEN_16; break;
        case RHC_LEVEL_3: session->token_byte_len = TOKEN_LEN_32; break;
        case RHC_LEVEL_4: session->token_byte_len = TOKEN_LEN_64; break;
    }

    /* Perform initial rotation to set header + token */
    rhc_rotate(session);
}

/* ─────────────────────────────────────────────
   INTERNAL: Choose token byte length for Level 3/4
   Mode B = random length, Mode A = fixed
   ───────────────────────────────────────────── */

static int choose_token_len(RhcMode mode, RhcLevel level) {
    static const int lengths[] = {
        TOKEN_LEN_8, TOKEN_LEN_16, TOKEN_LEN_32, TOKEN_LEN_64
    };
    /* Mode B + Level 3 or 4: fully random length each request */
    if (mode == RHC_MODE_B && level >= RHC_LEVEL_3) {
        return lengths[rand_int(4)];
    }
    /* Mode B + Level 2: random between 8 and 16 */
    if (mode == RHC_MODE_B && level == RHC_LEVEL_2) {
        return lengths[rand_int(2)];
    }
    /* Mode A: fixed length based on level */
    switch (level) {
        case RHC_LEVEL_1: return TOKEN_LEN_8;
        case RHC_LEVEL_2: return TOKEN_LEN_16;
        case RHC_LEVEL_3: return TOKEN_LEN_32;
        case RHC_LEVEL_4: return TOKEN_LEN_64;
        default:          return TOKEN_LEN_16;
    }
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_rotate
   Server picks a new valid header and token for next request.
   ───────────────────────────────────────────── */

void rhc_rotate(RhcSession *session) {
    const char **pool;
    int pool_size;

    if (session->level <= RHC_LEVEL_2) {
        pool      = VALID_HEADERS_L1;
        pool_size = N_VALID_L1;
    } else {
        pool      = VALID_HEADERS_L3;
        pool_size = N_VALID_L3;
    }

    /* Pick random valid header from pool */
    int idx = rand_int(pool_size);
    strncpy(session->expected_header, pool[idx], RHC_MAX_HEADER_NAME - 1);
    session->expected_header[RHC_MAX_HEADER_NAME - 1] = '\0';

    /* Choose token length — always results in a positive value */
    int tlen = choose_token_len(session->mode, session->level);
    if (tlen <= 0) tlen = TOKEN_LEN_16;  /* safety fallback */
    session->token_byte_len = tlen;

    /* Generate new token */
    rhc_gen_token(session->expected_token, session->token_byte_len);
    session->expected_token[RHC_MAX_TOKEN_LEN - 1] = '\0';
}

/* ─────────────────────────────────────────────
   INTERNAL: Constant-time comparison to prevent timing attacks
   ───────────────────────────────────────────── */
static int rhc_ct_memcmp(const char *a, const char *b, size_t len) {
    volatile unsigned char result = 0;
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    for (size_t i = 0; i < len; i++)
        result |= pa[i] ^ pb[i];
    return (result != 0); /* 0 if equal */
}

/* ─────────────────────────────────────────────
   INTERNAL: Check if a nonce was already used
   ───────────────────────────────────────────── */

static int nonce_is_replayed(RhcSession *session, const char *nonce) {
    for (int i = 0; i < session->nonce_cache_count; i++) {
        if (strcmp(session->nonce_cache[i], nonce) == 0)
            return 1; /* replay detected */
    }
    return 0;
}

/* ─────────────────────────────────────────────
   INTERNAL: Record a used nonce
   ───────────────────────────────────────────── */

static void nonce_record(RhcSession *session, const char *nonce) {
    strncpy(session->nonce_cache[session->nonce_cache_idx],
            nonce, RHC_MAX_NONCE_LEN - 1);
    /* FIX: Explicitly null-terminate to prevent off-by-one buffer reads */
    session->nonce_cache[session->nonce_cache_idx][RHC_MAX_NONCE_LEN - 1] = '\0';
    session->nonce_cache_idx = (session->nonce_cache_idx + 1) % RHC_NONCE_CACHE;
    if (session->nonce_cache_count < RHC_NONCE_CACHE)
        session->nonce_cache_count++;
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_build_request
   Client builds the outgoing request.
   Adds the real token in the chosen header.
   Level 4: also injects decoy headers.
   ───────────────────────────────────────────── */

RhcRequest rhc_build_request(RhcSession *session) {
    RhcRequest req;
    memset(&req, 0, sizeof(RhcRequest));

    req.timestamp = time(NULL);
    rhc_gen_nonce(req.nonce);

    int hcount = 0;

    /* ── Level 4: Insert decoy headers BEFORE the real one ── */
    if (session->level == RHC_LEVEL_4) {
        /* FIX: Include ALL decoy headers AND ALL unused valid headers in every request 
           to prevent frequency analysis attacks. This ensures real and decoy headers 
           all have a 100% appearance frequency. */
           
        /* 1. Add all decoy headers */
        for (int d = 0; d < N_DECOY && hcount < RHC_MAX_HEADERS - 1; d++) {
            /* Skip if same name as real header (safety check, though decoys and valid pools shouldn't overlap) */
            if (strcmp(DECOY_HEADERS[d], session->expected_header) == 0)
                continue;

            strncpy(req.headers[hcount].name, DECOY_HEADERS[d],
                    RHC_MAX_HEADER_NAME - 1);

            /* Decoy token: random length, random value */
            int decoy_len = choose_token_len(RHC_MODE_B, RHC_LEVEL_4);
            rhc_gen_token(req.headers[hcount].value, decoy_len);
            req.headers[hcount].is_decoy = 1;
            hcount++;
        }
        
        /* 2. Add all unused valid headers as decoys */
        for (int v = 0; v < N_VALID_L3 && hcount < RHC_MAX_HEADERS - 1; v++) {
            if (strcmp(VALID_HEADERS_L3[v], session->expected_header) == 0)
                continue;

            strncpy(req.headers[hcount].name, VALID_HEADERS_L3[v],
                    RHC_MAX_HEADER_NAME - 1);

            int decoy_len = choose_token_len(RHC_MODE_B, RHC_LEVEL_4);
            rhc_gen_token(req.headers[hcount].value, decoy_len);
            req.headers[hcount].is_decoy = 1;
            hcount++;
        }
    }

    /* ── Insert the REAL header at a random position ── */
    int real_pos;
    if (session->level == RHC_LEVEL_4 && hcount > 0) {
        real_pos = rand_int(hcount + 1); /* random slot among existing */
        /* Shift headers right to make room */
        for (int i = hcount; i > real_pos; i--)
            req.headers[i] = req.headers[i-1];
    } else {
        real_pos = hcount;
    }

    strncpy(req.headers[real_pos].name,  session->expected_header,
            RHC_MAX_HEADER_NAME - 1);
    strncpy(req.headers[real_pos].value, session->expected_token,
            RHC_MAX_TOKEN_LEN - 1);
    req.headers[real_pos].is_decoy = 0;

    hcount++;
    req.header_count = hcount;

    return req;
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_validate
   Server validates the incoming request.
   Checks: timestamp window, nonce replay, correct header+token.
   ───────────────────────────────────────────── */

RhcResult rhc_validate(RhcSession *session, const RhcRequest *req) {
    RhcResult result;
    memset(&result, 0, sizeof(RhcResult));

    /* ── 1. Timestamp check ── */
    time_t now = time(NULL);
    double age = difftime(now, req->timestamp);
    if (age < 0 || age > RHC_TIMESTAMP_WINDOW) {
        result.status  = RHC_ERR_EXPIRED;
        result.message = "REJECT: Request timestamp expired (replay protection)";
        return result;
    }

    /* ── 2. Nonce replay check ── */
    if (nonce_is_replayed(session, req->nonce)) {
        result.status  = RHC_ERR_REPLAY;
        result.message = "REJECT: Nonce already used (replay attack detected!)";
        return result;
    }

    /* ── 3. Search for the expected header ── */
    int found = 0;
    for (int i = 0; i < req->header_count; i++) {
        const char *hname = req->headers[i].name;
        const char *hval  = req->headers[i].value;

        /* Is this the header server is expecting? */
        if (strcmp(hname, session->expected_header) == 0) {

            strncpy(result.found_header, hname,  RHC_MAX_HEADER_NAME - 1);
            strncpy(result.found_token,  hval,   RHC_MAX_TOKEN_LEN   - 1);

            /* Check if token matches (FIX: Constant-time comparison) */
            size_t expected_len = session->token_byte_len * 2; /* byte len to hex char len */
            if (strlen(hval) == expected_len && rhc_ct_memcmp(hval, session->expected_token, expected_len) == 0) {
                /* ── VALID ──
                 * Only record nonce HERE (after all checks pass).
                 * This prevents a second identical request from
                 * succeeding because the nonce was recorded on
                 * first acceptance. */
                nonce_record(session, req->nonce);
                result.status  = RHC_OK;
                result.message = "ACCEPT: Valid RHC token, correct header, fresh nonce";
                found = 1;
            } else {
                result.status  = RHC_ERR_BAD_TOKEN;
                result.message = "REJECT: Correct header found but token mismatch";
                found = 1;
            }
            break;
        }
    }

    if (!found) {
        /* Check if attacker sent a known decoy header as the auth header */
        for (int i = 0; i < req->header_count; i++) {
            for (int d = 0; d < N_DECOY; d++) {
                if (strcmp(req->headers[i].name, DECOY_HEADERS[d]) == 0) {
                    result.status  = RHC_ERR_DECOY_SENT;
                    result.message = "REJECT: Attacker tried a decoy header as auth";
                    return result;
                }
            }
        }
        result.status  = RHC_ERR_NO_TOKEN;
        result.message = "REJECT: Expected header not found in request";
    }

    return result;
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_print_request
   ───────────────────────────────────────────── */

static const char *COLOR_RESET  = "\033[0m";
static const char *COLOR_GREEN  = "\033[1;32m";
static const char *COLOR_RED    = "\033[1;31m";
static const char *COLOR_YELLOW = "\033[1;33m";
static const char *COLOR_CYAN   = "\033[1;36m";
static const char *COLOR_BLUE   = "\033[1;34m";
static const char *COLOR_GRAY   = "\033[0;90m";

void rhc_print_request(const RhcRequest *req) {
    printf("\n%s┌─── RHC Request ─────────────────────────────────%s\n",
           COLOR_BLUE, COLOR_RESET);
    printf("%s│%s Timestamp : %ld\n", COLOR_BLUE, COLOR_RESET, (long)req->timestamp);
    printf("%s│%s Nonce     : %s%.12s...%s\n",
           COLOR_BLUE, COLOR_RESET, COLOR_CYAN, req->nonce, COLOR_RESET);
    printf("%s│%s Headers   :\n", COLOR_BLUE, COLOR_RESET);

    for (int i = 0; i < req->header_count; i++) {
        if (req->headers[i].is_decoy) {
            printf("%s│%s   %s[DECOY]%s %-10s : %.20s...\n",
                   COLOR_BLUE, COLOR_RESET,
                   COLOR_GRAY, COLOR_RESET,
                   req->headers[i].name,
                   req->headers[i].value);
        } else {
            printf("%s│%s   %s[REAL] %s %-10s : %.20s...\n",
                   COLOR_BLUE, COLOR_RESET,
                   COLOR_GREEN, COLOR_RESET,
                   req->headers[i].name,
                   req->headers[i].value);
        }
    }
    printf("%s└────────────────────────────────────────────────%s\n",
           COLOR_BLUE, COLOR_RESET);
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_print_result
   ───────────────────────────────────────────── */

void rhc_print_result(const RhcResult *result) {
    const char *color = (result->status == RHC_OK) ? COLOR_GREEN : COLOR_RED;
    printf("\n%s┌─── Validation Result ───────────────────────────%s\n",
           color, COLOR_RESET);
    printf("%s│%s %s\n", color, COLOR_RESET, result->message);
    if (result->found_header[0]) {
        printf("%s│%s Header: %s  Token: %.16s...\n",
               color, COLOR_RESET,
               result->found_header, result->found_token);
    }
    printf("%s└────────────────────────────────────────────────%s\n\n",
           color, COLOR_RESET);
}

/* ─────────────────────────────────────────────
   PUBLIC: rhc_print_session
   ───────────────────────────────────────────── */

void rhc_print_session(const RhcSession *session) {
    static const char *level_names[] = { "", "Level 1 Basic",
        "Level 2 Medium", "Level 3 Advanced", "Level 4 Dynamic" };
    static const char *mode_names[]  = { "Mode A (Fixed)", "Mode B (Random)" };

    printf("%s╔═══ RHC Session State ════════════════════════════╗%s\n",
           COLOR_YELLOW, COLOR_RESET);
    printf("%s║%s Session ID    : 0x%08X\n",
           COLOR_YELLOW, COLOR_RESET, session->session_id);
    printf("%s║%s Level         : %s%s%s\n",
           COLOR_YELLOW, COLOR_RESET, COLOR_CYAN,
           level_names[session->level], COLOR_RESET);
    printf("%s║%s Mode          : %s\n",
           COLOR_YELLOW, COLOR_RESET, mode_names[session->mode]);
    printf("%s║%s Token Len     : %d bytes (%d hex chars)\n",
           COLOR_YELLOW, COLOR_RESET,
           session->token_byte_len, session->token_byte_len * 2);
    printf("%s║%s Active Header : %s%s%s\n",
           COLOR_YELLOW, COLOR_RESET, COLOR_GREEN,
           session->expected_header, COLOR_RESET);
    printf("%s║%s Token         : %s%.32s...%s\n",
           COLOR_YELLOW, COLOR_RESET, COLOR_GREEN,
           session->expected_token, COLOR_RESET);
    printf("%s║%s Nonce Cache   : %d entries used\n",
           COLOR_YELLOW, COLOR_RESET, session->nonce_cache_count);
    printf("%s╚══════════════════════════════════════════════════╝%s\n",
           COLOR_YELLOW, COLOR_RESET);
}
