# RHC Live Server Dashboard

This directory contains a complete, interactive **Python Flask Web Dashboard** that acts as a real-time wrapper around the advanced C protocol (`librhc_adv.so`). 

It provides a visual UI to simulate attacks (IP Spoofing, Honeypot triggers) and watch the C server's defenses react in real-time.

## 🚀 Quick Start Guide

### Prerequisites
1. **Linux Environment** (Compiled C shared libraries are OS-dependent).
2. **GCC & OpenSSL** (To compile the C code).
3. **Python 3** installed.

### Step 1: Compile the C Library
First, you need to compile the advanced C protocol into a Shared Object (`.so`) file so Python can use it.
Run this from inside the `rhc_live_server` directory:
```bash
gcc -shared -fPIC -Wall -Wextra -O2 -std=c11 -o librhc_adv.so ../rhc_adv.c -lcrypto -I..
```

### Step 2: Setup Python Virtual Environment
We recommend using a virtual environment so you don't mess up your system Python packages.
```bash
# Create the virtual environment
python3 -m venv venv

# Activate it and install Flask
source venv/bin/activate
pip install flask
```

### Step 3: Run the Server
While still inside the activated virtual environment, start the Flask server:
```bash
python server.py
```
*(If you didn't activate the environment in step 2, you can also just run `./venv/bin/python server.py`)*

### Step 4: Access the Dashboard
Open your web browser and go to:
**http://localhost:5000**

---

## 🎮 How to use the Dashboard

1. **Send Legit Request:** Simulates a normal client passing the correct HMAC token in the correct rotating header. You will see an `ACCEPT` log.
2. **Spoof IP (Hijack):** Simulates an attacker stealing a valid token but sending it from a different IP (`10.0.0.99`). The server will `REJECT` it.
3. **Trigger Honeypot:** Simulates a blind attacker placing a valid HMAC token into a *Decoy* header. The server will catch this, apply a micro-delay, and permanently **BAN** the IP. 
4. **Reset Server:** Clears all session states, resets rate-limits, and unbans all IPs so you can start the demo over.
