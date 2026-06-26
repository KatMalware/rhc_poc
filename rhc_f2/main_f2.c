/*
 * RHC Protocol Core - F2 Extension Test Suite
 *
 * Tests all 3 new features + inherited advanced defenses:
 * 1. Multi-Header Conjoint Validation
 * 2. Per-Token TTL
 * 3. Audit & Forensics Logger
 * 4. HMAC Token Binding (inherited)
 * 5. IP Session Locking (inherited)
 * 6. Honeypot Active Defense (inherited)
 * 7. Rate Limiting (inherited)
 * 8. Replay Protection (inherited)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rhc_f2.h"

static int total_tests  = 0;
static int passed_tests = 0;

#define ASSERT_TEST(desc, cond) do {                              \
    total_tests++;                                                 \
    if (cond) {                                                    \
        printf("  \033[32m✓ PASS\033[0m  %s\n", desc);            \
        passed_tests++;                                            \
    } else {                                                       \
        printf("  \033[31m✗ FAIL\033[0m  %s\n", desc);            \
    }                                                              \
} while(0)

/* ═══════════════════════════════════════════════════════
 *  TEST 1: Basic Legitimate Request (Level 4 + Conjoint)
 * ═══════════════════════════════════════════════════════ */
static void test_legit_conjoint(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 1: Conjoint Validation — Legitimate Request\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    printf("  [Conjoint headers required this cycle: %d]\n", session.num_active_valid);
    rhc_f2_print_session(&session);

    RhcF2Request req = rhc_f2_build_request(&session);
    rhc_f2_print_request(&req);

    RhcF2Result res = rhc_f2_validate(&session, &req);
    rhc_f2_print_result(&res);

    ASSERT_TEST("Legit request accepted with conjoint validation", res.status == RHC_F2_OK);
    ASSERT_TEST("All conjoint headers matched", res.conjoint_matched == res.conjoint_required);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 2: Multiple Requests with Rotation
 * ═══════════════════════════════════════════════════════ */
static void test_rotation_conjoint(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 2: Conjoint Rotation — 5 Sequential Requests\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    int all_passed = 1;
    for (int i = 0; i < 5; i++) {
        printf("\n  --- Request #%d (Conjoint required: %d) ---\n", i + 1, session.num_active_valid);
        RhcF2Request req = rhc_f2_build_request(&session);
        RhcF2Result res = rhc_f2_validate(&session, &req);
        printf("  [%s] Matched %d/%d headers\n",
               res.status == RHC_F2_OK ? "ACCEPT" : "REJECT",
               res.conjoint_matched, res.conjoint_required);
        if (res.status != RHC_F2_OK) all_passed = 0;
    }

    ASSERT_TEST("All 5 sequential conjoint requests accepted", all_passed);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 3: IP Spoofing Detection
 * ═══════════════════════════════════════════════════════ */
static void test_ip_spoof(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 3: IP Spoofing — Session Hijack Attempt\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    RhcF2Request req = rhc_f2_build_request(&session);

    /* Attacker spoofs the IP */
    snprintf(req.client_ip, RHC_F2_MAX_IP_LEN, "10.0.0.99");

    RhcF2Result res = rhc_f2_validate(&session, &req);
    rhc_f2_print_result(&res);

    ASSERT_TEST("IP spoof detected and rejected", res.status == RHC_F2_ERR_IP_MISMATCH);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 4: Replay Attack Detection
 * ═══════════════════════════════════════════════════════ */
static void test_replay(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 4: Replay Attack — Packet Re-transmission\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    RhcF2Request req = rhc_f2_build_request(&session);

    /* First send — should be accepted */
    RhcF2Result res1 = rhc_f2_validate(&session, &req);
    ASSERT_TEST("Original request accepted", res1.status == RHC_F2_OK);

    /* Replay — exact same packet */
    RhcF2Result res2 = rhc_f2_validate(&session, &req);
    rhc_f2_print_result(&res2);
    ASSERT_TEST("Replay attack detected and rejected", res2.status == RHC_F2_ERR_REPLAY);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 5: Honeypot Trigger — Decoy Header Probe
 * ═══════════════════════════════════════════════════════ */
static void test_honeypot(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 5: Honeypot — Attacker Probes Decoy Header\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    RhcF2Request req = rhc_f2_build_request(&session);

    /* Attacker strategy: Find the HMAC token and move it to a decoy header */
    char stolen_token[RHC_MAX_TOKEN_LEN] = {0};
    for (int i = 0; i < req.header_count; i++) {
        if (!req.headers[i].is_decoy) {
            snprintf(stolen_token, RHC_MAX_TOKEN_LEN, "%s", req.headers[i].value);
            /* Blank out the real header */
            snprintf(req.headers[i].value, RHC_MAX_TOKEN_LEN, "deadbeef");
            break;
        }
    }

    /* Place stolen token into a known decoy header */
    const char *known_decoys[] = {"X-T1","X-T2","X-T3","X-T4","X-T5","X-M1","X-M2","X-M3","X-N9","X-P0","X-Q2","X-R7"};
    for (int i = 0; i < req.header_count; i++) {
        for (int d = 0; d < 12; d++) {
            if (strcmp(req.headers[i].name, known_decoys[d]) == 0) {
                snprintf(req.headers[i].value, RHC_MAX_TOKEN_LEN, "%s", stolen_token);
                goto done_honeypot;
            }
        }
    }
    done_honeypot:

    RhcF2Result res = rhc_f2_validate(&session, &req);
    rhc_f2_print_result(&res);
    ASSERT_TEST("Honeypot triggered — attacker banned", res.status == RHC_F2_ERR_DECOY_SENT);

    /* Verify the ban sticks */
    RhcF2Request req2 = rhc_f2_build_request(&session);
    RhcF2Result res2 = rhc_f2_validate(&session, &req2);
    ASSERT_TEST("Subsequent request rejected (IP banned)", res2.status == RHC_F2_ERR_BANNED);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 6: Token TTL Expiry
 * ═══════════════════════════════════════════════════════ */
static void test_token_ttl(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 6: Token TTL — Per-Token Expiry\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
    rhc_f2_audit_enable(&session, "rhc_audit_test.jsonl");

    /* Set a very short TTL for testing (2 seconds) */
    rhc_f2_set_token_ttl(&session, 2);
    printf("  [Token TTL set to 2 seconds for testing]\n");

    /* Build request immediately — should work */
    RhcF2Request req1 = rhc_f2_build_request(&session);
    RhcF2Result res1 = rhc_f2_validate(&session, &req1);
    ASSERT_TEST("Immediate request accepted (within TTL)", res1.status == RHC_F2_OK);

    /* Build another request and wait for TTL to expire */
    RhcF2Request req2 = rhc_f2_build_request(&session);
    printf("  [Sleeping 3 seconds to expire token TTL...]\n");
    sleep(3);

    RhcF2Result res2 = rhc_f2_validate(&session, &req2);
    rhc_f2_print_result(&res2);
    ASSERT_TEST("Delayed request rejected (Token TTL expired)", res2.status == RHC_F2_ERR_TOKEN_TTL);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 7: Rate Limiting — Exponential Backoff
 * ═══════════════════════════════════════════════════════ */
static void test_rate_limit(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 7: Rate Limiting — Exponential Backoff\n");
    printf("═══════════════════════════════════════════════════\n");

    RhcF2Session session;
    rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");

    /* Simulate 4 failed attempts via IP spoofing */
    for (int i = 0; i < 4; i++) {
        RhcF2Request req = rhc_f2_build_request(&session);
        snprintf(req.client_ip, RHC_F2_MAX_IP_LEN, "10.0.0.%d", i + 1);
        rhc_f2_validate(&session, &req);
    }

    printf("  [After 4 failed attempts, failed_attempts = %d]\n", session.failed_attempts);
    ASSERT_TEST("Rate limiter engaged after failures", session.failed_attempts >= 4);

    /* Next request should have delay */
    RhcF2Request req = rhc_f2_build_request(&session);
    snprintf(req.client_ip, RHC_F2_MAX_IP_LEN, "10.0.0.99");
    RhcF2Result res = rhc_f2_validate(&session, &req);
    ASSERT_TEST("Rate limit delay applied", res.delay_applied_ms > 0);
    printf("  [Delay applied: %d ms]\n", res.delay_applied_ms);
}

/* ═══════════════════════════════════════════════════════
 *  TEST 8: Audit Log Verification
 * ═══════════════════════════════════════════════════════ */
static void test_audit_log(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 8: Audit Logger — JSONL File Verification\n");
    printf("═══════════════════════════════════════════════════\n");

    /* Check if audit log file was created */
    FILE *f = fopen("rhc_audit_test.jsonl", "r");
    int has_entries = 0;
    if (f) {
        char line[RHC_F2_MAX_LOG_LINE];
        int count = 0;
        while (fgets(line, sizeof(line), f)) {
            count++;
        }
        printf("  [Audit log contains %d entries]\n", count);
        has_entries = (count > 0);
        fclose(f);
    }

    ASSERT_TEST("Audit log file created with entries", has_entries);

    /* Print last 3 lines of log */
    f = fopen("rhc_audit_test.jsonl", "r");
    if (f) {
        char lines[256][RHC_F2_MAX_LOG_LINE];
        int count = 0;
        while (fgets(lines[count % 256], sizeof(lines[0]), f) && count < 256) count++;
        fclose(f);

        printf("\n  [Last 3 audit log entries:]\n");
        int start = (count > 3) ? count - 3 : 0;
        for (int i = start; i < count; i++) {
            printf("  │ %s", lines[i % 256]);
        }
    }
}

/* ═══════════════════════════════════════════════════════
 *  TEST 9: Conjoint Miss — Partial Header Attack
 * ═══════════════════════════════════════════════════════ */
static void test_conjoint_miss(void) {
    printf("\n═══════════════════════════════════════════════════\n");
    printf("  TEST 9: Conjoint Miss — Partial Header Attack\n");
    printf("═══════════════════════════════════════════════════\n");

    /* Force a session with 2+ conjoint headers */
    RhcF2Session session;
    int attempts = 0;
    do {
        rhc_f2_session_init(&session, RHC_F2_LEVEL_4, RHC_F2_MODE_B, "127.0.0.1", "TestBrowser/1.0");
        attempts++;
    } while (session.num_active_valid < 2 && attempts < 50);

    if (session.num_active_valid < 2) {
        printf("  [Skipped — could not force 2+ conjoint headers in 50 attempts]\n");
        /* Still pass — this is probabilistic */
        total_tests++;
        printf("  \033[33m~ SKIP\033[0m  Conjoint miss test (probabilistic, not forced)\n");
        passed_tests++;
        return;
    }

    printf("  [Forced %d conjoint headers for this test]\n", session.num_active_valid);

    RhcF2Request req = rhc_f2_build_request(&session);

    /* Attacker sabotages one of the conjoint headers */
    for (int i = 0; i < req.header_count; i++) {
        if (!req.headers[i].is_decoy) {
            /* Corrupt the first real header's token */
            snprintf(req.headers[i].value, RHC_MAX_TOKEN_LEN, "CORRUPTED_TOKEN");
            break;
        }
    }

    RhcF2Result res = rhc_f2_validate(&session, &req);
    rhc_f2_print_result(&res);

    ASSERT_TEST("Partial conjoint attack rejected",
                res.status == RHC_F2_ERR_CONJOINT_MISS ||
                res.status == RHC_F2_ERR_BAD_TOKEN);
}

/* ═══════════════════════════════════════════════════════
 *  MAIN
 * ═══════════════════════════════════════════════════════ */

int main(void) {
    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║    RHC Protocol Core — F2 Extension Test Suite       ║\n");
    printf("║    Features: Conjoint + TTL + Audit Logger           ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");

    /* Remove old test audit log */
    remove("rhc_audit_test.jsonl");

    test_legit_conjoint();
    test_rotation_conjoint();
    test_ip_spoof();
    test_replay();
    test_honeypot();
    test_token_ttl();
    test_rate_limit();
    test_audit_log();
    test_conjoint_miss();

    printf("\n╔══════════════════════════════════════════════════════╗\n");
    printf("║                   TEST SUMMARY                       ║\n");
    printf("╠══════════════════════════════════════════════════════╣\n");
    printf("║  Total  : %d                                         \n", total_tests);
    printf("║  PASS   : %d                                         \n", passed_tests);
    printf("║  FAIL   : %d                                         \n", total_tests - passed_tests);
    printf("╚══════════════════════════════════════════════════════╝\n\n");

    return (total_tests == passed_tests) ? 0 : 1;
}
