/*
 * RHC Protocol Core - C PoC
 * main.c — Test Runner
 *
 * Tests:
 *   1. All 4 levels happy path (legitimate client)
 *   2. Wrong token attack
 *   3. Wrong header attack
 *   4. Replay attack (same nonce/request twice)
 *   5. Decoy header attack (attacker guesses decoy)
 *   6. Expired timestamp attack
 *   7. Level 4 full flow with rotation
 */

#include "rhc.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>   /* sleep() for timestamp test */
#include <time.h>

/* ── ANSI colors ── */
#define C_RESET   "\033[0m"
#define C_BOLD    "\033[1m"
#define C_CYAN    "\033[1;36m"
#define C_YELLOW  "\033[1;33m"
#define C_GREEN   "\033[1;32m"
#define C_RED     "\033[1;31m"
#define C_MAGENTA "\033[1;35m"
#define C_WHITE   "\033[1;37m"

static int tests_pass = 0;
static int tests_fail = 0;

/* ─────────────────────────────────────────────
   HELPER: print a section banner
   ───────────────────────────────────────────── */
static void banner(const char *title) {
    printf("\n%s═══════════════════════════════════════════════════%s\n", C_MAGENTA, C_RESET);
    printf("%s  %s%s\n", C_BOLD, title, C_RESET);
    printf("%s═══════════════════════════════════════════════════%s\n\n", C_MAGENTA, C_RESET);
}

/* ─────────────────────────────────────────────
   HELPER: check a test result
   ───────────────────────────────────────────── */
static void check(const char *test_name, int expected_ok, RhcStatus got) {
    int passed = (expected_ok ? (got == RHC_OK) : (got != RHC_OK));

    if (passed) {
        printf("  %s✓ PASS%s  %s\n", C_GREEN, C_RESET, test_name);
        tests_pass++;
    } else {
        printf("  %s✗ FAIL%s  %s  (status=%d)\n", C_RED, C_RESET, test_name, (int)got);
        tests_fail++;
    }
}

/* ═══════════════════════════════════════════════════
   TEST 1: Level 1 — Basic single header rotation
   ═══════════════════════════════════════════════════ */
static void test_level1(void) {
    banner("TEST 1: Level 1 — Basic Header Rotation");

    RhcSession session;
    rhc_session_init(&session, RHC_LEVEL_1, RHC_MODE_A);

    printf("%s[Server Session State]%s\n", C_CYAN, C_RESET);
    rhc_print_session(&session);

    /* Legitimate request */
    RhcRequest req = rhc_build_request(&session);
    printf("\n%s[Client Request (what attacker sees)]%s", C_CYAN, C_RESET);
    rhc_print_request(&req);

    RhcResult result = rhc_validate(&session, &req);
    printf("%s[Server Validation]%s", C_CYAN, C_RESET);
    rhc_print_result(&result);

    check("Level 1: Legitimate request accepted", 1, result.status);
}

/* ═══════════════════════════════════════════════════
   TEST 2: Level 2 — Dual entropy (header + token)
   ═══════════════════════════════════════════════════ */
static void test_level2(void) {
    banner("TEST 2: Level 2 — Mode B (Random Assignment)");

    RhcSession session;
    rhc_session_init(&session, RHC_LEVEL_2, RHC_MODE_B);

    printf("%s[3 consecutive requests — watch header rotation]%s\n", C_CYAN, C_RESET);

    for (int i = 1; i <= 3; i++) {
        printf("\n%s--- Request #%d ---%s\n", C_YELLOW, i, C_RESET);
        rhc_print_session(&session);

        RhcRequest req = rhc_build_request(&session);
        rhc_print_request(&req);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);

        char label[64];
        snprintf(label, sizeof(label), "Level 2: Request #%d accepted", i);
        check(label, 1, res.status);

        /* Rotate for next request */
        rhc_rotate(&session);
    }
}

/* ═══════════════════════════════════════════════════
   TEST 3: Level 3 — Variable token lengths
   ═══════════════════════════════════════════════════ */
static void test_level3(void) {
    banner("TEST 3: Level 3 — Variable Token Lengths (Mode B)");

    RhcSession session;
    rhc_session_init(&session, RHC_LEVEL_3, RHC_MODE_B);

    printf("%s[Token length changes each request — attacker can't infer structure]%s\n\n",
           C_CYAN, C_RESET);

    for (int i = 1; i <= 4; i++) {
        printf("%s--- Request #%d (token_len=%d bytes) ---%s\n",
               C_YELLOW, i, session.token_byte_len, C_RESET);

        RhcRequest req = rhc_build_request(&session);
        rhc_print_request(&req);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);

        char label[64];
        snprintf(label, sizeof(label), "Level 3: Request #%d accepted", i);
        check(label, 1, res.status);

        rhc_rotate(&session);
    }
}

/* ═══════════════════════════════════════════════════
   TEST 4: Level 4 — Full Dynamic with Decoys
   ═══════════════════════════════════════════════════ */
static void test_level4(void) {
    banner("TEST 4: Level 4 — Decoys + Adaptive Entropy");

    RhcSession session;
    rhc_session_init(&session, RHC_LEVEL_4, RHC_MODE_B);

    printf("%s[Watch how decoy headers hide the real token]%s\n\n", C_CYAN, C_RESET);

    for (int i = 1; i <= 3; i++) {
        printf("%s--- Request #%d ---%s\n", C_YELLOW, i, C_RESET);
        rhc_print_session(&session);

        RhcRequest req = rhc_build_request(&session);
        rhc_print_request(&req);

        printf("  %sAttacker sees %d headers — only 1 is real!%s\n",
               C_RED, req.header_count, C_RESET);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);

        char label[64];
        snprintf(label, sizeof(label), "Level 4: Request #%d accepted", i);
        check(label, 1, res.status);

        rhc_rotate(&session);
    }
}

/* ═══════════════════════════════════════════════════
   TEST 5: Attack Simulations
   ═══════════════════════════════════════════════════ */
static void test_attacks(void) {
    banner("TEST 5: Attack Simulations");

    /* ── 5a: Wrong token ── */
    {
        printf("%s[Attack 5a: Wrong Token]%s\n", C_RED, C_RESET);
        RhcSession session;
        rhc_session_init(&session, RHC_LEVEL_2, RHC_MODE_A);

        RhcRequest req = rhc_build_request(&session);

        /* Tamper: overwrite the token value */
        strncpy(req.headers[0].value, "deadbeefdeadbeef", RHC_MAX_TOKEN_LEN - 1);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);
        check("Attack 5a: Wrong token rejected", 0, res.status);
    }

    /* ── 5b: Wrong header name ── */
    {
        printf("%s[Attack 5b: Wrong Header Name]%s\n", C_RED, C_RESET);
        RhcSession session;
        rhc_session_init(&session, RHC_LEVEL_2, RHC_MODE_A);

        RhcRequest req = rhc_build_request(&session);

        /* Tamper: change the header name */
        strncpy(req.headers[0].name, "X-Hacked", RHC_MAX_HEADER_NAME - 1);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);
        check("Attack 5b: Wrong header rejected", 0, res.status);
    }

    /* ── 5c: Replay Attack (send same request twice) ── */
    {
        printf("%s[Attack 5c: Replay Attack — same request sent twice]%s\n",
               C_RED, C_RESET);
        RhcSession session;
        rhc_session_init(&session, RHC_LEVEL_3, RHC_MODE_A);

        RhcRequest req = rhc_build_request(&session);

        /* First time: should succeed */
        RhcResult res1 = rhc_validate(&session, &req);
        printf("  First send: ");
        rhc_print_result(&res1);
        check("Attack 5c: First request accepted", 1, res1.status);

        /* Second time with SAME request: replay must be rejected */
        RhcResult res2 = rhc_validate(&session, &req);
        printf("  Replay send: ");
        rhc_print_result(&res2);
        check("Attack 5c: Replay request rejected", 0, res2.status);
    }

    /* ── 5d: Expired timestamp ── */
    {
        printf("%s[Attack 5d: Expired Timestamp]%s\n", C_RED, C_RESET);
        RhcSession session;
        rhc_session_init(&session, RHC_LEVEL_2, RHC_MODE_A);

        RhcRequest req = rhc_build_request(&session);

        /* Simulate an old timestamp (beyond the window) */
        req.timestamp = time(NULL) - (RHC_TIMESTAMP_WINDOW + 10);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);
        check("Attack 5d: Expired request rejected", 0, res.status);
    }

    /* ── 5e: Level 4 decoy header used as auth ── */
    {
        printf("%s[Attack 5e: Attacker sends a decoy header as auth]%s\n",
               C_RED, C_RESET);
        RhcSession session;
        rhc_session_init(&session, RHC_LEVEL_4, RHC_MODE_B);

        /* Build a fake request using ONLY a decoy header */
        RhcRequest fake_req;
        memset(&fake_req, 0, sizeof(RhcRequest));
        fake_req.timestamp = time(NULL);
        rhc_gen_nonce(fake_req.nonce);

        /* Attacker guesses X-T1 is the real header */
        strncpy(fake_req.headers[0].name,  "X-T1", RHC_MAX_HEADER_NAME - 1);
        strncpy(fake_req.headers[0].value, "some_guessed_token", RHC_MAX_TOKEN_LEN - 1);
        fake_req.header_count = 1;

        rhc_print_request(&fake_req);
        RhcResult res = rhc_validate(&session, &fake_req);
        rhc_print_result(&res);
        check("Attack 5e: Decoy-as-auth rejected", 0, res.status);
    }
}

/* ═══════════════════════════════════════════════════
   TEST 6: Full multi-request session (Level 4)
            Demonstrates channel continuity
   ═══════════════════════════════════════════════════ */
static void test_full_session(void) {
    banner("TEST 6: Full Session — 5 Requests with Rotation (Level 4)");

    RhcSession session;
    rhc_session_init(&session, RHC_LEVEL_4, RHC_MODE_B);

    int all_ok = 1;

    for (int i = 1; i <= 5; i++) {
        printf("\n%s[Request %d/5]%s  Header: %s%s%s  Token length: %d bytes\n",
               C_CYAN, i, C_RESET,
               C_GREEN, session.expected_header, C_RESET,
               session.token_byte_len);

        RhcRequest req = rhc_build_request(&session);
        rhc_print_request(&req);

        RhcResult res = rhc_validate(&session, &req);
        rhc_print_result(&res);

        if (res.status != RHC_OK) {
            all_ok = 0;
            printf("  %s✗ FAIL at request %d%s\n", C_RED, i, C_RESET);
        }

        rhc_rotate(&session);
    }

    check("Full session: All 5 Level-4 requests accepted", 1,
          all_ok ? RHC_OK : RHC_ERR_BAD_TOKEN);
}

/* ═══════════════════════════════════════════════════
   MAIN
   ═══════════════════════════════════════════════════ */
int main(void) {
    printf("\n");
    printf("%s╔══════════════════════════════════════════════════════╗%s\n", C_CYAN, C_RESET);
    printf("%s║         RHC Protocol Core — C PoC Test Suite         ║%s\n", C_CYAN, C_RESET);
    printf("%s║   Randomized Header Channel for Comm. Integrity       ║%s\n", C_CYAN, C_RESET);
    printf("%s╚══════════════════════════════════════════════════════╝%s\n", C_CYAN, C_RESET);

    test_level1();
    test_level2();
    test_level3();
    test_level4();
    test_attacks();
    test_full_session();

    /* ── Final Summary ── */
    printf("\n%s╔══════════════════════════════════════════════════════╗%s\n", C_BOLD, C_RESET);
    printf("%s║                   TEST SUMMARY                       ║%s\n", C_BOLD, C_RESET);
    printf("%s╠══════════════════════════════════════════════════════╣%s\n", C_BOLD, C_RESET);
    printf("%s║%s  Total  : %-3d                                        %s║%s\n",
           C_BOLD, C_WHITE, tests_pass + tests_fail, C_BOLD, C_RESET);
    printf("%s║%s  %sPASS%s   : %-3d                                        %s║%s\n",
           C_BOLD, C_RESET, C_GREEN, C_WHITE, tests_pass, C_BOLD, C_RESET);
    printf("%s║%s  %sFAIL%s   : %-3d                                        %s║%s\n",
           C_BOLD, C_RESET, C_RED, C_WHITE, tests_fail, C_BOLD, C_RESET);
    printf("%s╚══════════════════════════════════════════════════════╝%s\n\n", C_BOLD, C_RESET);

    return (tests_fail == 0) ? 0 : 1;
}
