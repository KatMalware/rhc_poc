/*
 * RHC Protocol Core - ADVANCED Test Suite
 *
 * Demonstrates the 4 new security features:
 * HMAC, IP Binding, Honeypot Bans, Rate Limiting.
 */

#include "rhc_adv.h"
#include <stdio.h>
#include <string.h>

#define C_RESET   "\033[0m"
#define C_RED     "\033[1;31m"
#define C_GREEN   "\033[1;32m"
#define C_YELLOW  "\033[1;33m"
#define C_CYAN    "\033[1;36m"
#define C_MAGENTA "\033[1;35m"

int tests_passed = 0;
int total_tests = 0;

void assert_test(int condition, const char *name) {
    total_tests++;
    if (condition) {
        printf("  %s✓ PASS%s  %s\n", C_GREEN, C_RESET, name);
        tests_passed++;
    } else {
        printf("  %s✗ FAIL%s  %s\n", C_RED, C_RESET, name);
    }
}

int main(void) {
    printf("\n%s╔══════════════════════════════════════════════════════╗%s\n", C_MAGENTA, C_RESET);
    printf("%s║   RHC Protocol — ADVANCED Security Features Test     ║%s\n", C_MAGENTA, C_RESET);
    printf("%s╚══════════════════════════════════════════════════════╝%s\n\n", C_MAGENTA, C_RESET);

    RhcAdvSession session;
    rhc_adv_session_init(&session, RHC_ADV_LEVEL_4, RHC_ADV_MODE_B, "192.168.1.100", "Mozilla/5.0");

    printf("%s[SCENARIO 1: Legitimate Request]%s\n", C_CYAN, C_RESET);
    RhcAdvRequest req1 = rhc_adv_build_request(&session);
    RhcAdvResult res1 = rhc_adv_validate(&session, &req1);
    assert_test(res1.status == RHC_ADV_OK, "Valid HMAC token and correct IP accepted");
    rhc_adv_rotate(&session);

    printf("\n%s[SCENARIO 2: IP Spoofing (Session Hijacking)]%s\n", C_CYAN, C_RESET);
    RhcAdvRequest req2 = rhc_adv_build_request(&session);
    strcpy(req2.client_ip, "10.0.0.5"); /* Attacker changed IP */
    RhcAdvResult res2 = rhc_adv_validate(&session, &req2);
    assert_test(res2.status == RHC_ADV_ERR_IP_MISMATCH, "Request from different IP rejected");
    assert_test(session.failed_attempts == 1, "Failed attempt counter incremented");

    printf("\n%s[SCENARIO 3: Rate Limiting (Exponential Backoff)]%s\n", C_CYAN, C_RESET);
    /* Send another invalid request to see the delay applied */
    RhcAdvRequest req3 = rhc_adv_build_request(&session);
    req3.timestamp -= 100; /* Expired timestamp */
    RhcAdvResult res3 = rhc_adv_validate(&session, &req3);
    assert_test(res3.status == RHC_ADV_ERR_EXPIRED, "Expired timestamp rejected");
    assert_test(res3.delay_applied_ms > 0, "Rate limiting delay was applied by the server");
    assert_test(session.failed_attempts == 2, "Failed attempt counter is now 2");

    printf("\n%s[SCENARIO 4: Honeypot Trigger (Active Ban)]%s\n", C_CYAN, C_RESET);
    RhcAdvRequest req4 = rhc_adv_build_request(&session);
    
    /* Simulate attacker using a Decoy header as the actual auth header */
    char valid_token[RHC_MAX_TOKEN_LEN] = {0};
    for(int i=0; i<req4.header_count; i++) {
        if(!req4.headers[i].is_decoy) {
            strcpy(valid_token, req4.headers[i].value);
            req4.headers[i].name[0] = 'Z'; /* Break the real header so it's not found */
            break;
        }
    }
    for(int i=0; i<req4.header_count; i++) {
        if(req4.headers[i].is_decoy) {
            strcpy(req4.headers[i].value, valid_token); /* Attacker pastes valid token into decoy header */
            break;
        }
    }
    
    RhcAdvResult res4 = rhc_adv_validate(&session, &req4);
    assert_test(res4.status == RHC_ADV_ERR_DECOY_SENT, "Honeypot triggered, attacker detected");
    assert_test(session.is_banned == 1, "Session marked as BANNED permanently");

    printf("\n%s[SCENARIO 5: Banned State Enforcement]%s\n", C_CYAN, C_RESET);
    /* Attacker tries to send a perfectly valid request now */
    rhc_adv_rotate(&session);
    RhcAdvRequest req5 = rhc_adv_build_request(&session);
    RhcAdvResult res5 = rhc_adv_validate(&session, &req5);
    assert_test(res5.status == RHC_ADV_ERR_BANNED, "Perfectly valid request rejected because IP is banned");

    printf("\n%s╔══════════════════════════════════════════════════════╗%s\n", C_MAGENTA, C_RESET);
    printf("%s║                   ADVANCED TEST SUMMARY              ║%s\n", C_MAGENTA, C_RESET);
    printf("%s╠══════════════════════════════════════════════════════╣%s\n", C_MAGENTA, C_RESET);
    printf("%s║  Total  : %d                                         ║%s\n", C_MAGENTA, total_tests, C_RESET);
    printf("%s║  PASS   : %d                                         ║%s\n", C_MAGENTA, tests_passed, C_RESET);
    printf("%s║  FAIL   : %d                                          ║%s\n", C_MAGENTA, total_tests - tests_passed, C_RESET);
    printf("%s╚══════════════════════════════════════════════════════╝%s\n\n", C_MAGENTA, C_RESET);

    return (tests_passed == total_tests) ? 0 : 1;
}
