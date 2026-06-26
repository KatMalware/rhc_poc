/*
 * RHC Protocol Core - F2 Extension Implementation
 *
 * New Features:
 * 1. Multi-Header Conjoint Validation
 * 2. Per-Token TTL (Time-To-Live)
 * 3. Audit & Forensics Logger (JSONL)
 *
 * Inherited from Advanced:
 * - HMAC-SHA256 Token Binding
 * - IP & User-Agent Session Locking
 * - Honeypot Active Defense
 * - Exponential Rate Limiting
 * - Constant-Time Comparison
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include "rhc_f2.h"

/* ═══════════════════════════════════════════════════════
 *  Internal Helpers
 * ═══════════════════════════════════════════════════════ */

/* Valid header pool (same as original) */
static const char *VALID_HEADERS[] = {
    "X-A1", "X-B3", "X-C7", "X-D2", "X-E8", "X-F5", "X-G4", "X-H6"
};
#define VALID_POOL_SIZE 8

/* Decoy header pool */
static const char *DECOY_HEADERS[] = {
    "X-T1", "X-T2", "X-T3", "X-T4", "X-T5",
    "X-M1", "X-M2", "X-M3", "X-N9", "X-P0", "X-Q2", "X-R7"
};
#define DECOY_POOL_SIZE 12

/* Constant-time comparison — no timing leaks */
static int rhc_f2_ct_memcmp(const char *a, const char *b, size_t len) {
    volatile unsigned char result = 0;
    for (size_t i = 0; i < len; i++)
        result |= ((const unsigned char*)a)[i] ^ ((const unsigned char*)b)[i];
    return (result != 0);
}

/* Generate random hex string of specified byte length */
static void rhc_f2_gen_hex(char *out, int byte_len) {
    unsigned char buf[64];
    int actual = (byte_len > 64) ? 64 : byte_len;
    RAND_bytes(buf, actual);
    for (int i = 0; i < actual; i++)
        snprintf(out + i * 2, 3, "%02x", buf[i]);
    out[actual * 2] = '\0';
}

/* Generate a nonce (16 bytes = 32 hex chars) */
static void rhc_f2_gen_nonce(char *out) {
    rhc_f2_gen_hex(out, 16);
}

/* Compute HMAC-SHA256 token from session secret + nonce + timestamp */
static void rhc_f2_compute_hmac(const RhcF2Session *session,
                                const char *nonce, time_t timestamp,
                                char *out_hex) {
    char data[256];
    snprintf(data, sizeof(data), "%s|%ld|%u", nonce, (long)timestamp, session->session_id);

    unsigned char digest[32];
    unsigned int dlen = 0;
    HMAC(EVP_sha256(), session->hmac_secret, 32,
         (unsigned char*)data, strlen(data), digest, &dlen);

    for (unsigned int i = 0; i < dlen; i++)
        snprintf(out_hex + i * 2, 3, "%02x", digest[i]);
    out_hex[dlen * 2] = '\0';
}

/* Check if an IP is in the ban list */
static int rhc_f2_is_ip_banned(const RhcF2Session *session, const char *ip) {
    if (session->is_banned) return 1;
    for (int i = 0; i < session->ban_count; i++) {
        if (strcmp(session->banned_ips[i], ip) == 0) return 1;
    }
    return 0;
}

/* Ban an IP address */
static void rhc_f2_ban_ip(RhcF2Session *session, const char *ip) {
    session->is_banned = 1;
    if (session->ban_count < RHC_F2_MAX_BANS) {
        snprintf(session->banned_ips[session->ban_count], RHC_F2_MAX_IP_LEN, "%s", ip);
        session->ban_count++;
    }
}

/* Check nonce against cache */
static int rhc_f2_nonce_seen(const RhcF2Session *session, const char *nonce) {
    int limit = (session->nonce_cache_count < RHC_NONCE_CACHE)
                ? session->nonce_cache_count : RHC_NONCE_CACHE;
    for (int i = 0; i < limit; i++) {
        if (strcmp(session->nonce_cache[i], nonce) == 0)
            return 1;
    }
    return 0;
}

/* Record nonce in circular cache */
static void rhc_f2_nonce_record(RhcF2Session *session, const char *nonce) {
    snprintf(session->nonce_cache[session->nonce_cache_idx],
             RHC_MAX_NONCE_LEN, "%s", nonce);
    session->nonce_cache_idx = (session->nonce_cache_idx + 1) % RHC_NONCE_CACHE;
    if (session->nonce_cache_count < RHC_NONCE_CACHE)
        session->nonce_cache_count++;
}

/* Fisher-Yates shuffle for integer array */
static void shuffle_ints(int *arr, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
}

/* ═══════════════════════════════════════════════════════
 *  Audit & Forensics Logger
 * ═══════════════════════════════════════════════════════ */

void rhc_f2_audit_enable(RhcF2Session *session, const char *filepath) {
    session->audit_enabled = 1;
    if (filepath) {
        snprintf(session->audit_filepath, sizeof(session->audit_filepath), "%s", filepath);
    } else {
        snprintf(session->audit_filepath, sizeof(session->audit_filepath), "%s", RHC_F2_AUDIT_FILE);
    }
}

void rhc_f2_audit_disable(RhcF2Session *session) {
    session->audit_enabled = 0;
}

static void rhc_f2_audit_write(const RhcF2Session *session, const RhcF2AuditEntry *entry) {
    if (!session->audit_enabled) return;

    FILE *f = fopen(session->audit_filepath, "a");
    if (!f) return;

    fprintf(f,
        "{\"timestamp\":%ld,\"session_id\":\"0x%08X\","
        "\"client_ip\":\"%s\",\"action\":\"%s\","
        "\"result\":\"%s\",\"reason\":\"%s\","
        "\"conjoint_matched\":%d,\"conjoint_required\":%d}\n",
        (long)entry->timestamp, entry->session_id,
        entry->client_ip, entry->action,
        entry->result, entry->reason,
        entry->conjoint_matched, entry->conjoint_required
    );

    fclose(f);
}

/* ═══════════════════════════════════════════════════════
 *  Token TTL API
 * ═══════════════════════════════════════════════════════ */

void rhc_f2_set_token_ttl(RhcF2Session *session, int ttl_seconds) {
    session->token_ttl = ttl_seconds;
}

/* ═══════════════════════════════════════════════════════
 *  Session Initialization
 * ═══════════════════════════════════════════════════════ */

void rhc_f2_session_init(RhcF2Session *session, RhcF2Level level, RhcF2Mode mode,
                         const char *client_ip, const char *user_agent) {
    memset(session, 0, sizeof(RhcF2Session));
    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    session->level = level;
    session->mode  = mode;
    session->session_id = (uint32_t)rand();

    /* Generate HMAC secret */
    RAND_bytes(session->hmac_secret, 32);

    /* Bind client IP and User-Agent */
    snprintf(session->bound_ip, RHC_F2_MAX_IP_LEN, "%s", client_ip);
    snprintf(session->bound_ua, RHC_F2_MAX_UA_LEN, "%s", user_agent);

    /* Default Token TTL */
    session->token_ttl = RHC_F2_DEFAULT_TOKEN_TTL;
    session->token_created_at = time(NULL);

    /* Default audit off */
    session->audit_enabled = 0;
    snprintf(session->audit_filepath, sizeof(session->audit_filepath), "%s", RHC_F2_AUDIT_FILE);

    /* Determine token byte length based on level */
    int sizes[] = {8, 8, 16, 32};
    session->token_byte_len = sizes[level - 1];

    /* ── Conjoint Validation: Pick 1-3 valid headers ── */
    if (level == RHC_F2_LEVEL_4) {
        /* Level 4: randomly choose 1, 2, or 3 conjoint valid headers */
        session->num_active_valid = 1 + (rand() % RHC_F2_MAX_CONJOINT);
    } else {
        session->num_active_valid = 1;
    }

    /* Shuffle valid pool indices and pick N */
    int indices[VALID_POOL_SIZE];
    for (int i = 0; i < VALID_POOL_SIZE; i++) indices[i] = i;
    shuffle_ints(indices, VALID_POOL_SIZE);

    for (int v = 0; v < session->num_active_valid; v++) {
        snprintf(session->expected_headers[v], RHC_MAX_HEADER_NAME, "%s",
                 VALID_HEADERS[indices[v]]);
        rhc_f2_gen_hex(session->expected_tokens[v], session->token_byte_len);
    }
}

/* ═══════════════════════════════════════════════════════
 *  Session Rotation
 * ═══════════════════════════════════════════════════════ */

void rhc_f2_rotate(RhcF2Session *session) {
    /* Variable token length for Level 3+ */
    if (session->level >= RHC_F2_LEVEL_3) {
        int sizes[] = {8, 16, 32, 64};
        session->token_byte_len = sizes[rand() % 4];
    }

    /* Re-pick conjoint count for Level 4 */
    if (session->level == RHC_F2_LEVEL_4) {
        session->num_active_valid = 1 + (rand() % RHC_F2_MAX_CONJOINT);
    }

    /* Shuffle and pick new valid headers */
    int indices[VALID_POOL_SIZE];
    for (int i = 0; i < VALID_POOL_SIZE; i++) indices[i] = i;
    shuffle_ints(indices, VALID_POOL_SIZE);

    for (int v = 0; v < session->num_active_valid; v++) {
        snprintf(session->expected_headers[v], RHC_MAX_HEADER_NAME, "%s",
                 VALID_HEADERS[indices[v]]);
        rhc_f2_gen_hex(session->expected_tokens[v], session->token_byte_len);
    }

    /* Reset Token TTL clock */
    session->token_created_at = time(NULL);

    /* New mode assignment for Mode B */
    if (session->mode == RHC_F2_MODE_B) {
        session->mode = (rand() % 2) ? RHC_F2_MODE_B : RHC_F2_MODE_A;
    }
}

/* ═══════════════════════════════════════════════════════
 *  Build Request (Client-Side)
 * ═══════════════════════════════════════════════════════ */

RhcF2Request rhc_f2_build_request(RhcF2Session *session) {
    RhcF2Request req;
    memset(&req, 0, sizeof(req));

    req.timestamp = time(NULL);
    rhc_f2_gen_nonce(req.nonce);
    snprintf(req.client_ip, RHC_F2_MAX_IP_LEN, "%s", session->bound_ip);
    snprintf(req.user_agent, RHC_F2_MAX_UA_LEN, "%s", session->bound_ua);

    /* Compute HMAC token for each conjoint valid header */
    char hmac_token[RHC_MAX_TOKEN_LEN];
    rhc_f2_compute_hmac(session, req.nonce, req.timestamp, hmac_token);

    if (session->level < RHC_F2_LEVEL_4) {
        /* Levels 1-3: Only the first valid header, no decoys */
        req.header_count = 1;
        snprintf(req.headers[0].name, RHC_MAX_HEADER_NAME, "%s", session->expected_headers[0]);
        snprintf(req.headers[0].value, RHC_MAX_TOKEN_LEN, "%s", hmac_token);
        req.headers[0].is_decoy = 0;
        return req;
    }

    /* ── Level 4: Full conjoint + decoy generation ── */

    /* Track which valid headers are active (for flat frequency) */
    int is_active_valid[VALID_POOL_SIZE];
    memset(is_active_valid, 0, sizeof(is_active_valid));

    /* Place all conjoint valid headers with the HMAC token */
    int positions[RHC_MAX_HEADERS];
    int total = VALID_POOL_SIZE + DECOY_POOL_SIZE;
    req.header_count = total;

    /* First: fill all valid pool headers */
    for (int i = 0; i < VALID_POOL_SIZE; i++) {
        snprintf(req.headers[i].name, RHC_MAX_HEADER_NAME, "%s", VALID_HEADERS[i]);
        req.headers[i].is_decoy = 1; /* Default: decoy */

        /* Check if this is one of our active valid headers */
        for (int v = 0; v < session->num_active_valid; v++) {
            if (strcmp(VALID_HEADERS[i], session->expected_headers[v]) == 0) {
                snprintf(req.headers[i].value, RHC_MAX_TOKEN_LEN, "%s", hmac_token);
                req.headers[i].is_decoy = 0;
                is_active_valid[i] = 1;
                break;
            }
        }

        /* Non-active valid headers get random decoy values */
        if (is_active_valid[i] == 0) {
            rhc_f2_gen_hex(req.headers[i].value, session->token_byte_len);
        }
    }

    /* Next: fill decoy pool headers with random values */
    for (int i = 0; i < DECOY_POOL_SIZE; i++) {
        int idx = VALID_POOL_SIZE + i;
        snprintf(req.headers[idx].name, RHC_MAX_HEADER_NAME, "%s", DECOY_HEADERS[i]);
        rhc_f2_gen_hex(req.headers[idx].value, session->token_byte_len);
        req.headers[idx].is_decoy = 1;
    }

    /* Shuffle all positions for randomized ordering */
    for (int i = 0; i < total; i++) positions[i] = i;
    shuffle_ints(positions, total);

    RhcF2Header shuffled[RHC_MAX_HEADERS];
    for (int i = 0; i < total; i++)
        shuffled[i] = req.headers[positions[i]];
    memcpy(req.headers, shuffled, sizeof(RhcF2Header) * total);

    return req;
}

/* ═══════════════════════════════════════════════════════
 *  Validate Request (Server-Side)
 * ═══════════════════════════════════════════════════════ */

RhcF2Result rhc_f2_validate(RhcF2Session *session, const RhcF2Request *req) {
    RhcF2Result result;
    memset(&result, 0, sizeof(result));
    result.conjoint_required = session->num_active_valid;

    /* ── Pre-Check 1: Ban List ── */
    if (rhc_f2_is_ip_banned(session, req->client_ip)) {
        result.status  = RHC_F2_ERR_BANNED;
        result.message = "REJECT: IP is permanently banned (honeypot triggered)";

        if (session->audit_enabled) {
            RhcF2AuditEntry entry = { time(NULL), session->session_id,
                "", "VALIDATE", "REJECT", "IP_BANNED", 0, session->num_active_valid };
            snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
            rhc_f2_audit_write(session, &entry);
        }
        return result;
    }

    /* ── Pre-Check 2: Rate Limiting ── */
    if (session->failed_attempts >= 3) {
        int delay_ms = 100 * (1 << (session->failed_attempts - 3));
        if (delay_ms > 5000) delay_ms = 5000;
        result.delay_applied_ms = delay_ms;
        {
            struct timespec ts = { .tv_sec = delay_ms / 1000, .tv_nsec = (delay_ms % 1000) * 1000000L };
            nanosleep(&ts, NULL);
        }
    }

    /* ── Pre-Check 3: IP Binding ── */
    if (strcmp(req->client_ip, session->bound_ip) != 0) {
        result.status  = RHC_F2_ERR_IP_MISMATCH;
        result.message = "REJECT: Client IP does not match bound session IP";
        session->failed_attempts++;

        if (session->audit_enabled) {
            RhcF2AuditEntry entry = { time(NULL), session->session_id,
                "", "VALIDATE", "REJECT", "IP_MISMATCH", 0, session->num_active_valid };
            snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
            rhc_f2_audit_write(session, &entry);
        }
        return result;
    }

    /* ── Pre-Check 4: Timestamp Expiry (30-second window) ── */
    time_t now = time(NULL);
    if (labs(now - req->timestamp) > RHC_TIMESTAMP_WINDOW) {
        result.status  = RHC_F2_ERR_EXPIRED;
        result.message = "REJECT: Request timestamp expired (>30s window)";
        session->failed_attempts++;

        if (session->audit_enabled) {
            RhcF2AuditEntry entry = { time(NULL), session->session_id,
                "", "VALIDATE", "REJECT", "TIMESTAMP_EXPIRED", 0, session->num_active_valid };
            snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
            rhc_f2_audit_write(session, &entry);
        }
        return result;
    }

    /* ── Pre-Check 5: Token TTL (per-token expiry) ── */
    if (labs(now - session->token_created_at) > session->token_ttl) {
        result.status  = RHC_F2_ERR_TOKEN_TTL;
        result.message = "REJECT: Token TTL expired (individual token lifetime exceeded)";
        session->failed_attempts++;

        if (session->audit_enabled) {
            RhcF2AuditEntry entry = { time(NULL), session->session_id,
                "", "VALIDATE", "REJECT", "TOKEN_TTL_EXPIRED", 0, session->num_active_valid };
            snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
            rhc_f2_audit_write(session, &entry);
        }
        return result;
    }

    /* ── Pre-Check 6: Nonce Replay ── */
    if (rhc_f2_nonce_seen(session, req->nonce)) {
        result.status  = RHC_F2_ERR_REPLAY;
        result.message = "REJECT: Nonce already used (replay attack detected)";
        session->failed_attempts++;

        if (session->audit_enabled) {
            RhcF2AuditEntry entry = { time(NULL), session->session_id,
                "", "VALIDATE", "REJECT", "REPLAY_DETECTED", 0, session->num_active_valid };
            snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
            rhc_f2_audit_write(session, &entry);
        }
        return result;
    }

    /* ── Compute expected HMAC for this request ── */
    char expected_hmac[RHC_MAX_TOKEN_LEN];
    rhc_f2_compute_hmac(session, req->nonce, req->timestamp, expected_hmac);

    /* ── Honeypot Detection: Scan decoy headers for valid HMAC ── */
    for (int i = 0; i < req->header_count; i++) {
        /* Check if this header is a known decoy */
        int is_decoy_pool = 0;
        for (int d = 0; d < DECOY_POOL_SIZE; d++) {
            if (strcmp(req->headers[i].name, DECOY_HEADERS[d]) == 0) {
                is_decoy_pool = 1;
                break;
            }
        }
        if (!is_decoy_pool) continue;

        /* If a decoy header contains a valid HMAC → Honeypot triggered! */
        size_t token_len = strlen(expected_hmac);
        if (token_len > 0 && strlen(req->headers[i].value) == token_len) {
            if (rhc_f2_ct_memcmp(req->headers[i].value, expected_hmac, token_len) == 0) {
                rhc_f2_ban_ip(session, req->client_ip);
                result.status  = RHC_F2_ERR_DECOY_SENT;
                result.message = "REJECT + BAN: Valid token found in DECOY header — honeypot triggered!";
                snprintf(result.found_header, RHC_MAX_HEADER_NAME, "%s", req->headers[i].name);

                if (session->audit_enabled) {
                    RhcF2AuditEntry entry = { time(NULL), session->session_id,
                        "", "HONEYPOT_BAN", "REJECT", "DECOY_TOKEN_MATCH", 0, session->num_active_valid };
                    snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
                    rhc_f2_audit_write(session, &entry);
                }
                return result;
            }
        }
    }

    /* ═══════════════════════════════════════════════════
     *  CONJOINT VALIDATION: All active valid headers must match
     * ═══════════════════════════════════════════════════ */
    int matched = 0;

    for (int v = 0; v < session->num_active_valid; v++) {
        int found = 0;
        for (int i = 0; i < req->header_count; i++) {
            if (strcmp(req->headers[i].name, session->expected_headers[v]) != 0)
                continue;

            /* Found the expected header — verify token */
            size_t token_len = strlen(expected_hmac);
            if (strlen(req->headers[i].value) == token_len &&
                rhc_f2_ct_memcmp(req->headers[i].value, expected_hmac, token_len) == 0) {
                matched++;
                found = 1;
                snprintf(result.found_header, RHC_MAX_HEADER_NAME, "%s", req->headers[i].name);
                snprintf(result.found_token, RHC_MAX_TOKEN_LEN, "%s", req->headers[i].value);
            }
            break;
        }

        if (!found) {
            /* Missing or wrong token for one of the conjoint headers */
            result.status  = RHC_F2_ERR_CONJOINT_MISS;
            result.message = "REJECT: Conjoint validation failed — missing or invalid token for required header";
            result.conjoint_matched = matched;
            session->failed_attempts++;

            if (session->audit_enabled) {
                RhcF2AuditEntry entry = { time(NULL), session->session_id,
                    "", "VALIDATE", "REJECT", "CONJOINT_MISS", matched, session->num_active_valid };
                snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
                rhc_f2_audit_write(session, &entry);
            }
            return result;
        }
    }

    /* ── All conjoint headers matched! Accept. ── */
    rhc_f2_nonce_record(session, req->nonce);
    session->failed_attempts = 0;

    result.status  = RHC_F2_OK;
    result.message = "ACCEPT: All conjoint headers verified, HMAC valid, fresh nonce";
    result.conjoint_matched = matched;

    if (session->audit_enabled) {
        RhcF2AuditEntry entry = { time(NULL), session->session_id,
            "", "VALIDATE", "ACCEPT", "ALL_CONJOINT_VALID", matched, session->num_active_valid };
        snprintf((char*)entry.client_ip, RHC_F2_MAX_IP_LEN, "%s", req->client_ip);
        rhc_f2_audit_write(session, &entry);
    }

    /* Auto-rotate for next cycle */
    rhc_f2_rotate(session);

    return result;
}

/* ═══════════════════════════════════════════════════════
 *  Display Helpers
 * ═══════════════════════════════════════════════════════ */

void rhc_f2_print_session(const RhcF2Session *session) {
    const char *lvl_names[] = {"", "Level 1 Basic", "Level 2 Medium", "Level 3 Variable", "Level 4 Dynamic"};
    printf("\n╔═══ RHC F2 Session State ═════════════════════════════╗\n");
    printf("║ Session ID       : 0x%08X\n", session->session_id);
    printf("║ Level            : %s\n", lvl_names[session->level]);
    printf("║ Token Len        : %d bytes\n", session->token_byte_len);
    printf("║ Conjoint Active  : %d valid headers required\n", session->num_active_valid);
    printf("║ Token TTL        : %d seconds\n", session->token_ttl);
    printf("║ Audit Logging    : %s\n", session->audit_enabled ? "ENABLED" : "DISABLED");
    printf("║ Bound IP         : %s\n", session->bound_ip);
    printf("║ Failed Attempts  : %d\n", session->failed_attempts);
    printf("║ Bans Active      : %d\n", session->ban_count);
    for (int v = 0; v < session->num_active_valid; v++) {
        printf("║ Valid Header [%d] : %s  Token: %.16s...\n",
               v + 1, session->expected_headers[v], session->expected_tokens[v]);
    }
    printf("╚═════════════════════════════════════════════════════╝\n");
}

void rhc_f2_print_request(const RhcF2Request *req) {
    printf("\n┌─── RHC F2 Request ──────────────────────────────────\n");
    printf("│ Timestamp : %ld\n", (long)req->timestamp);
    printf("│ Nonce     : %.12s...\n", req->nonce);
    printf("│ Client IP : %s\n", req->client_ip);
    printf("│ Headers   :\n");
    for (int i = 0; i < req->header_count; i++) {
        printf("│   [%s] %-10s : %.20s...\n",
               req->headers[i].is_decoy ? "DECOY" : "REAL ",
               req->headers[i].name, req->headers[i].value);
    }
    printf("└─────────────────────────────────────────────────────\n");
}

void rhc_f2_print_result(const RhcF2Result *result) {
    printf("\n┌─── Validation Result ────────────────────────────────\n");
    printf("│ %s\n", result->message);
    if (result->conjoint_required > 1) {
        printf("│ Conjoint: %d/%d headers matched\n",
               result->conjoint_matched, result->conjoint_required);
    }
    if (result->delay_applied_ms > 0) {
        printf("│ Rate-limit delay: %d ms applied\n", result->delay_applied_ms);
    }
    printf("└─────────────────────────────────────────────────────\n");
}
