# Advanced RHC Protocol Implementation

This directory (`f_rhc`) contains the **Advanced** version of the RHC Protocol Proof-of-Concept. It builds upon the core protocol by introducing military-grade active defenses and cryptographic bindings.

## 🛡️ Advanced Features Implemented
1. **HMAC-SHA256 Token Binding**: Tokens are mathematically bound to the `Nonce`, `Timestamp`, and `SessionID` using OpenSSL's HMAC algorithm. You cannot tamper with timestamps or replay nonces without invalidating the token signature.
2. **IP & User-Agent Binding**: Sessions are strictly locked to the client's initial IP address and User-Agent.
3. **Honeypot Active Defense**: If an attacker attempts to use a decoy header to authenticate, their IP is immediately placed on a permanent ban list.
4. **Exponential Rate Limiting**: Consecutive failed attempts automatically introduce compounding micro-delays (`usleep`) to completely neutralize brute-force attacks.

---

## ⚙️ How to Compile & Run

Because this version uses HMAC-SHA256, it requires the OpenSSL library (`libcrypto`).

**To run the advanced test suite:**
```bash
make -f Makefile.adv run_adv
```

---

## 💻 API Usage (How to integrate this into your project)

To use these advanced features in your own C project, include `rhc_adv.h` and link against `-lcrypto`.

### 1. Initialize an Advanced Session (Server-Side)
You must initialize the session with the client's IP and User-Agent to enable binding.
```c
#include "rhc_adv.h"

RhcAdvSession session;
// Initialize Level 4 with client IP "192.168.1.100"
rhc_adv_session_init(&session, RHC_ADV_LEVEL_4, RHC_ADV_MODE_B, "192.168.1.100", "Mozilla/5.0");
```

### 2. Build a Request (Client-Side)
The request automatically injects the bound IP/UA, generates a nonce, and calculates the required HMAC-SHA256 signature for the token.
```c
RhcAdvRequest req = rhc_adv_build_request(&session);
```

### 3. Validate and Handle Bans (Server-Side)
Validation performs IP checking, Honeypot detection, Rate Limiting delays, and HMAC verification.

```c
RhcAdvResult result = rhc_adv_validate(&session, &req);

if (result.status == RHC_ADV_OK) {
    printf("Access Granted!\n");
    rhc_adv_rotate(&session); // Rotate header for the next request
    
} else if (result.status == RHC_ADV_ERR_BANNED || result.status == RHC_ADV_ERR_DECOY_SENT) {
    // CRITICAL: Honeypot triggered or IP is already banned. 
    // You should block this IP at your firewall level.
    printf("ALERT: IP BANNED! %s\n", result.message);
    
} else {
    // Normal failure (e.g., mismatch IP, expired timestamp, invalid token)
    // A rate-limiting delay was automatically applied by the server.
    printf("Access Denied: %s\n", result.message);
}
```
