# RHC Protocol Core - C Implementation

This repository contains a full C-language Proof-of-Concept (PoC) for the **Randomized Header Channel (RHC)** protocol. Originally designed in PHP, this C port implements all four protocol levels and introduces critical security enhancements, including robust replay protection and mitigations against timing side-channels and frequency analysis attacks.

## 🚀 Features
- **All 4 Protocol Levels Supported**: From basic rotation (Level 1) to dynamic entropy and decoy headers (Level 4).
- **Replay Protection**: Full defense against replay attacks using a Nonce cache and Timestamp expiration window.
- **Constant-Time Validation**: Uses a custom `rhc_ct_memcmp` function to prevent token leakage via timing side-channels (CWE-208).
- **Flat Frequency Distribution**: Forces a 100% appearance frequency for all decoy and valid headers in Level 4, completely neutralizing statistical distinguishability attacks.

## 🛠️ Prerequisites
To compile and run this code, you will need a standard C development environment:
- GCC (GNU Compiler Collection) or any standard C compiler.
- Make

## ⚙️ How to Build and Run

### 1. Run the Test Suite (Protocol Demonstration)
To compile the core protocol and run all 18 automated tests (which validate legitimate requests, rejection of bad tokens, replay attacks, expired timestamps, etc.):

```bash
make run
```
*(This will execute `./rhc_poc` and print the live rotation of headers, nonces, and the final 18/18 PASS test summary).*

### 2. Run the Security Flaw Demonstrations
We have included a dedicated attack simulation to demonstrate why the security fixes (timing side-channels and frequency analysis) were necessary and how they work:

```bash
make attack && ./attack_demo
```
*(This will execute `./attack_demo` and show live timing differences between `strcmp` vs constant-time `memcmp`, as well as a frequency analysis simulation).*

## 💻 How to Use in Your Own Project (API Usage)

The core logic is completely self-contained within `rhc.h` and `rhc.c`. You can easily drop these two files into your own C/C++ projects, web servers, or IoT devices.

### 1. Include the Header
```c
#include "rhc.h"
```

### 2. Initialize a Session (Server-Side)
Set up a session for a specific security level (1 to 4) and mode.
```c
RhcSession session;
// Initialize Level 4 (Highest Security: Decoys + Variable Entropy)
rhc_session_init(&session, RHC_LEVEL_4, RHC_MODE_B);
```

### 3. Build a Request (Client-Side)
Generate a request based on the current session state. This automatically generates the nonce, adds the current timestamp, and securely hides the real token among decoys.
```c
RhcRequest req = rhc_build_request(&session);
```

### 4. Validate the Request (Server-Side)
When the request arrives, validate it. This will perform all security checks: Timestamp expiration, Nonce replay detection, and Constant-Time token matching.
```c
RhcResult result = rhc_validate(&session, &req);

if (result.status == RHC_OK) {
    // Validation passed! 
    // Important: Rotate the headers/tokens for the next request
    rhc_rotate(&session);
} else {
    // Validation failed (e.g. RHC_ERR_REPLAY, RHC_ERR_EXPIRED, RHC_ERR_BAD_TOKEN)
    printf("Access Denied: %s\n", result.message);
}
```

## 📄 Security Report
For a detailed technical breakdown of the vulnerabilities found in the original PHP design and exactly how they were fixed in this C implementation, please read the [SECURITY_REPORT.md](./SECURITY_REPORT.md) file included in this repository.

## 🧹 Clean Up
To remove compiled binaries from your directory:
```bash
make clean
```

---
*This codebase is maintained as a community contribution to support the ongoing evolution of the RHC Protocol.*
