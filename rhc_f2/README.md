# RHC F2 Extension — Advanced Security Features

This module extends the RHC Advanced Implementation (`f_rhc/`) with **three new security features** inspired by the RHC Protocol Complexity Model (Levels 0-3).

---

## 🆕 New Features

### 1. Multi-Header Conjoint Validation
Instead of validating a single header per request, the server randomly selects **1 to 3 valid headers** each cycle. **All** selected headers must carry a valid HMAC token for the request to be accepted. If an attacker guesses one correctly but misses the others, the entire request is rejected.

**Impact on Attacker Search Space (Ω):**
| Conjoint Headers | Combinations | Ω (approx) |
|---|---|---|
| 1 (standard) | C(8,1) = 8 | ~112 |
| 2 (conjoint) | C(8,2) = 28 | ~1,344+ |
| 3 (conjoint) | C(8,3) = 56 | ~10,752+ |

The server randomly alternates between these modes — the attacker doesn't know how many headers to guess.

### 2. Per-Token TTL (Time-To-Live)
Each set of generated tokens has an independent expiry timer, separate from the global 30-second timestamp window. Default TTL is **10 seconds**.

**Why it matters:** Even if an attacker bypasses nonce caching, the token itself expires in 10 seconds. The combined defense of Nonce Cache + Timestamp Window + Token TTL creates a triple-layered replay shield.

### 3. Audit & Forensics Logger (JSONL)
Every validation attempt (accept or reject) is recorded in a structured **JSON Lines** log file for incident response and security auditing.

**Log entry example:**
```json
{"timestamp":1782479462,"session_id":"0x5D15BFB5","client_ip":"127.0.0.1","action":"VALIDATE","result":"ACCEPT","reason":"ALL_CONJOINT_VALID","conjoint_matched":2,"conjoint_required":2}
```

---

## 📁 Files

| File | Purpose |
|---|---|
| `rhc_f2.h` | Public API — structs, enums, function declarations |
| `rhc_f2.c` | Core implementation — all features |
| `main_f2.c` | Test suite — 14 assertions |
| `Makefile.f2` | Build commands |

---

## 🚀 Quick Start

### Prerequisites
- GCC (C11)
- OpenSSL (`libcrypto`)

### Build & Run
```bash
cd rhc_f2/
make -f Makefile.f2 run
```

### Expected Output
```
║  Total  : 14
║  PASS   : 14
║  FAIL   : 0
```

### View Audit Log
After running the tests, inspect the generated log:
```bash
cat rhc_audit_test.jsonl | python3 -m json.tool --no-ensure-ascii
```

---

## 🧪 Test Cases (14/14 PASS)

| Test | Description | Status |
|---|---|---|
| 1 | Conjoint Validation — Legit request with 1-3 valid headers | ✅ PASS |
| 2 | Conjoint Rotation — 5 sequential requests with varying conjoint count | ✅ PASS |
| 3 | IP Spoofing — Session hijack attempt rejected | ✅ PASS |
| 4 | Replay Attack — Nonce reuse detected and blocked | ✅ PASS |
| 5 | Honeypot — Decoy probe triggers permanent IP ban | ✅ PASS |
| 6 | Token TTL — Expired token rejected after timeout | ✅ PASS |
| 7 | Rate Limiting — Exponential backoff after failures | ✅ PASS |
| 8 | Audit Logger — JSONL file created with structured entries | ✅ PASS |
| 9 | Conjoint Miss — Partial header attack rejected | ✅ PASS |

---

## 🛡️ Complete Defense Stack

| Layer | Feature | Source |
|---|---|---|
| 1 | Constant-Time Token Comparison | Base |
| 2 | Flat Frequency Distribution | Base |
| 3 | Nonce + Timestamp Replay Cache | Base |
| 4 | HMAC-SHA256 Token Binding | f_rhc |
| 5 | IP/UA Session Locking | f_rhc |
| 6 | Honeypot Active Defense | f_rhc |
| 7 | Exponential Rate Limiting | f_rhc |
| **8** | **Multi-Header Conjoint Validation** | **rhc_f2 (NEW)** |
| **9** | **Per-Token TTL** | **rhc_f2 (NEW)** |
| **10** | **Audit & Forensics Logger** | **rhc_f2 (NEW)** |
