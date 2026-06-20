from flask import Flask, render_template, request, jsonify
import ctypes
import os
import time

app = Flask(__name__)

# Load the compiled shared library
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'librhc_adv.so'))
rhc_lib = ctypes.CDLL(lib_path)

# --- Define C Structs in Python (ctypes) ---

RHC_MAX_HEADERS = 24
RHC_MAX_HEADER_NAME = 32
RHC_MAX_TOKEN_LEN = 129
RHC_MAX_NONCE_LEN = 33
RHC_ADV_MAX_IP_LEN = 46
RHC_ADV_MAX_UA_LEN = 256
RHC_NONCE_CACHE = 64

class RhcAdvHeader(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * RHC_MAX_HEADER_NAME),
        ("value", ctypes.c_char * RHC_MAX_TOKEN_LEN),
        ("is_decoy", ctypes.c_int)
    ]

class RhcAdvRequest(ctypes.Structure):
    _fields_ = [
        ("headers", RhcAdvHeader * RHC_MAX_HEADERS),
        ("header_count", ctypes.c_int),
        ("nonce", ctypes.c_char * RHC_MAX_NONCE_LEN),
        ("timestamp", ctypes.c_long),  # time_t can be c_long
        ("client_ip", ctypes.c_char * RHC_ADV_MAX_IP_LEN),
        ("user_agent", ctypes.c_char * RHC_ADV_MAX_UA_LEN)
    ]

class RhcAdvSession(ctypes.Structure):
    _fields_ = [
        ("level", ctypes.c_int),
        ("mode", ctypes.c_int),
        ("expected_header", ctypes.c_char * RHC_MAX_HEADER_NAME),
        ("expected_token", ctypes.c_char * RHC_MAX_TOKEN_LEN),
        ("token_byte_len", ctypes.c_int),
        ("nonce_cache", (ctypes.c_char * RHC_MAX_NONCE_LEN) * RHC_NONCE_CACHE),
        ("nonce_cache_idx", ctypes.c_int),
        ("nonce_cache_count", ctypes.c_int),
        ("session_id", ctypes.c_uint32),
        ("hmac_secret", ctypes.c_uint8 * 32),
        ("bound_ip", ctypes.c_char * RHC_ADV_MAX_IP_LEN),
        ("bound_ua", ctypes.c_char * RHC_ADV_MAX_UA_LEN),
        ("is_banned", ctypes.c_int),
        ("banned_ips", (ctypes.c_char * RHC_ADV_MAX_IP_LEN) * 128),
        ("ban_count", ctypes.c_int),
        ("failed_attempts", ctypes.c_int),
        ("lockout_until", ctypes.c_long)
    ]

class RhcAdvResult(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_int),
        ("message", ctypes.c_char_p),
        ("found_header", ctypes.c_char * RHC_MAX_HEADER_NAME),
        ("found_token", ctypes.c_char * RHC_MAX_TOKEN_LEN),
        ("delay_applied_ms", ctypes.c_int)
    ]

# Define function signatures
rhc_lib.rhc_adv_session_init.argtypes = [ctypes.POINTER(RhcAdvSession), ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
rhc_lib.rhc_adv_build_request.argtypes = [ctypes.POINTER(RhcAdvSession)]
rhc_lib.rhc_adv_build_request.restype = RhcAdvRequest
rhc_lib.rhc_adv_validate.argtypes = [ctypes.POINTER(RhcAdvSession), ctypes.POINTER(RhcAdvRequest)]
rhc_lib.rhc_adv_validate.restype = RhcAdvResult
rhc_lib.rhc_adv_rotate.argtypes = [ctypes.POINTER(RhcAdvSession)]

# --- Global Server State ---
server_session = RhcAdvSession()

def init_server():
    ip = b"127.0.0.1"
    ua = b"Flask-Demo-Browser"
    # Level 4, Mode B
    rhc_lib.rhc_adv_session_init(ctypes.byref(server_session), 4, 1, ip, ua)

init_server()

# --- Routes ---

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "expected_header": server_session.expected_header.decode('utf-8', 'ignore'),
        "bound_ip": server_session.bound_ip.decode('utf-8', 'ignore'),
        "failed_attempts": server_session.failed_attempts,
        "is_banned": server_session.is_banned == 1
    })

@app.route("/api/reset", methods=["POST"])
def reset_server():
    init_server()
    return jsonify({"success": True})

@app.route("/api/legit_request", methods=["POST"])
def legit_request():
    req = rhc_lib.rhc_adv_build_request(ctypes.byref(server_session))
    
    start_time = time.time()
    res = rhc_lib.rhc_adv_validate(ctypes.byref(server_session), ctypes.byref(req))
    end_time = time.time()
    
    if res.status == 0:  # OK
        rhc_lib.rhc_adv_rotate(ctypes.byref(server_session))
        
    return build_response(req, res, end_time - start_time)

@app.route("/api/spoof_ip", methods=["POST"])
def spoof_ip():
    req = rhc_lib.rhc_adv_build_request(ctypes.byref(server_session))
    req.client_ip = b"10.0.0.99" # SPOOF IP
    
    start_time = time.time()
    res = rhc_lib.rhc_adv_validate(ctypes.byref(server_session), ctypes.byref(req))
    end_time = time.time()
    
    return build_response(req, res, end_time - start_time)

@app.route("/api/trigger_honeypot", methods=["POST"])
def trigger_honeypot():
    req = rhc_lib.rhc_adv_build_request(ctypes.byref(server_session))
    
    # Simulating attacker copying the valid token into a decoy header
    valid_token = b""
    for i in range(req.header_count):
        if req.headers[i].is_decoy == 0:
            valid_token = req.headers[i].value
            req.headers[i].name = b"Z" # Hide original
            break
            
    for i in range(req.header_count):
        if req.headers[i].is_decoy == 1:
            req.headers[i].value = valid_token
            break
            
    start_time = time.time()
    res = rhc_lib.rhc_adv_validate(ctypes.byref(server_session), ctypes.byref(req))
    end_time = time.time()
    
    return build_response(req, res, end_time - start_time)

def build_response(req, res, exec_time):
    headers = []
    for i in range(req.header_count):
        headers.append({
            "name": req.headers[i].name.decode('utf-8', 'ignore'),
            "value": req.headers[i].value.decode('utf-8', 'ignore')[:15] + "...",
            "is_decoy": req.headers[i].is_decoy == 1
        })
        
    return jsonify({
        "status": res.status,
        "message": res.message.decode('utf-8', 'ignore') if res.message else "",
        "delay_ms": res.delay_applied_ms,
        "exec_time_ms": round(exec_time * 1000, 2),
        "request": {
            "ip": req.client_ip.decode('utf-8', 'ignore'),
            "nonce": req.nonce.decode('utf-8', 'ignore')[:12] + "...",
            "headers": headers
        }
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
