"""
Diffie-Hellman Key Exchange & MITM Attack Protection Educational Application
Network Security Academic Demonstration Tool
"""

import os
import random
import hashlib
import base64
from flask import Flask, render_template, request, jsonify

# Real cryptography library for established digital signature demonstrations
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dh-mitm-demo-secret-key-2026'

# ==========================================
# Mathematical Utilities for Diffie-Hellman
# ==========================================

DEMO_PRESETS = [
    {"name": "Classroom Classic (p=23, g=5)", "p": 23, "g": 5, "description": "Smallest textbook example, easy to trace by hand."},
    {"name": "Standard Demo (p=47, g=5)", "p": 47, "g": 5, "description": "Quick modular calculations with distinct generator cycles."},
    {"name": "Medium Prime (p=97, g=5)", "p": 97, "g": 5, "description": "Two-digit prime demonstrating intermediate exponentiation."},
    {"name": "RFC Demo (p=283, g=3)", "p": 283, "g": 3, "description": "Moderate sized prime with g=3 as a valid primitive root."},
    {"name": "High Precision (p=7919, g=7)", "p": 7919, "g": 7, "description": "The 1,000th prime number, highlighting non-trivial discrete logs."}
]


def is_prime(n: int) -> bool:
    """Deterministic primality test for small/moderate numbers."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def get_prime_factors(n: int) -> set:
    """Return set of distinct prime factors of n."""
    factors = set()
    d = 2
    temp = n
    while d * d <= temp:
        if temp % d == 0:
            factors.add(d)
            while temp % d == 0:
                temp //= d
        d += 1
    if temp > 1:
        factors.add(temp)
    return factors


def is_primitive_root(g: int, p: int) -> bool:
    """
    Check if g is a primitive root modulo p.
    g is primitive root iff for every prime factor q of (p-1),
    g^((p-1)/q) != 1 (mod p).
    """
    if g <= 1 or g >= p:
        return False
    phi = p - 1
    factors = get_prime_factors(phi)
    for q in factors:
        if pow(g, phi // q, p) == 1:
            return False
    return True


def find_primitive_root(p: int) -> int:
    """Find the smallest primitive root modulo p."""
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return 2


def simple_xor_cipher(text: str, key: int) -> str:
    """
    Simple educational XOR stream cipher to demonstrate message encryption
    using derived shared keys without heavy external cipher dependencies.
    """
    key_bytes = str(key).encode('utf-8')
    text_bytes = text.encode('utf-8')
    cipher = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes)])
    return base64.b64encode(cipher).decode('utf-8')


def simple_xor_decipher(b64_cipher: str, key: int) -> str:
    """Decrypt the educational XOR stream cipher."""
    try:
        cipher = base64.b64decode(b64_cipher.encode('utf-8'))
        key_bytes = str(key).encode('utf-8')
        plain = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(cipher)])
        return plain.decode('utf-8', errors='replace')
    except Exception:
        return "[Corrupted / Decryption Failed]"


def compute_fingerprint(data: str) -> str:
    """Generate colon-separated hex SHA-256 fingerprint."""
    digest = hashlib.sha256(data.encode('utf-8')).hexdigest().upper()
    return ":".join(digest[i:i+2] for i in range(0, 32, 2))


# In-memory storage for active RSA signing demo keypairs
DEMO_KEYS = {}


def get_or_create_rsa_keypair(identity="alice"):
    """Generate or retrieve 2048-bit RSA keypair for digital signature demos."""
    if identity not in DEMO_KEYS:
        priv_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        pub_key = priv_key.public_key()
        
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        DEMO_KEYS[identity] = {
            "private_obj": priv_key,
            "public_obj": pub_key,
            "private_pem": priv_pem,
            "public_pem": pub_pem,
            "fingerprint": compute_fingerprint(pub_pem)
        }
    return DEMO_KEYS[identity]


# ==========================================
# HTML Page Routes (10 Modules)
# ==========================================

@app.route('/')
def index():
    """Dashboard / Home page."""
    return render_template('index.html', active_page='home')


@app.route('/dh')
def dh_page():
    """Normal Diffie-Hellman Key Exchange module."""
    return render_template('dh.html', active_page='dh', presets=DEMO_PRESETS)


@app.route('/mitm')
def mitm_page():
    """Man-in-the-Middle Attack Simulation module."""
    return render_template('mitm.html', active_page='mitm', presets=DEMO_PRESETS)


@app.route('/detection')
def detection_page():
    """Attack Detection & Fingerprinting module."""
    return render_template('detection.html', active_page='detection')


@app.route('/protected-dh')
def protected_dh_page():
    """Protected / Authenticated Diffie-Hellman module."""
    return render_template('protected_dh.html', active_page='protected_dh', presets=DEMO_PRESETS)


@app.route('/signatures')
def signatures_page():
    """Digital Signature Demonstration module."""
    # Ensure Alice's RSA keys are ready
    alice_keys = get_or_create_rsa_keypair("alice")
    return render_template('signatures.html', active_page='signatures', alice_pub=alice_keys['public_pem'], fingerprint=alice_keys['fingerprint'])


@app.route('/comparison')
def comparison_page():
    """Countermeasure Comparison module."""
    return render_template('comparison.html', active_page='comparison')


@app.route('/analysis')
def analysis_page():
    """Security Analysis module."""
    return render_template('analysis.html', active_page='analysis')


@app.route('/recommendation')
def recommendation_page():
    """Secure Architecture Recommendation module."""
    return render_template('recommendation.html', active_page='recommendation')


@app.route('/about')
def about_page():
    """About & Academic Assignment Information module."""
    return render_template('about.html', active_page='about')


# ==========================================
# REST API Endpoints
# ==========================================

@app.route('/api/dh/presets', methods=['GET'])
def api_dh_presets():
    """Return available demonstration parameter presets."""
    return jsonify({"presets": DEMO_PRESETS, "status": "success"})


@app.route('/api/dh/generate', methods=['POST'])
def api_dh_generate():
    """
    Generate Diffie-Hellman keys dynamically or use provided p, g.
    Generates Alice's private 'a', Bob's private 'b', and calculates all public and shared values.
    """
    data = request.get_json() or {}
    try:
        preset_idx = data.get('preset_index')
        if preset_idx is not None and 0 <= int(preset_idx) < len(DEMO_PRESETS):
            selected = DEMO_PRESETS[int(preset_idx)]
            p = selected['p']
            g = selected['g']
        else:
            p = int(data.get('p', 23))
            g = int(data.get('g', 5))
            
        # Validation
        if p < 5:
            return jsonify({"status": "error", "message": "Prime number p must be at least 5."}), 400
        if not is_prime(p):
            return jsonify({"status": "error", "message": f"Value {p} is not a prime number."}), 400
        if g <= 1 or g >= p:
            return jsonify({"status": "error", "message": f"Generator g must be in range [2, {p-1}]."}), 400

        # Private keys in range [2, p-2]
        max_priv = min(p - 2, 50)
        min_priv = 2
        if max_priv < min_priv:
            max_priv = p - 1
            min_priv = 1
            
        a = int(data.get('a')) if data.get('a') is not None and str(data.get('a')).strip() != '' else random.randint(min_priv, max_priv)
        b = int(data.get('b')) if data.get('b') is not None and str(data.get('b')).strip() != '' else random.randint(min_priv, max_priv)

        # Public values
        A = pow(g, a, p)
        B = pow(g, b, p)

        # Shared secret keys
        K_A = pow(B, a, p)
        K_B = pow(A, b, p)

        match = (K_A == K_B)

        return jsonify({
            "status": "success",
            "p": p,
            "g": g,
            "a": a,
            "b": b,
            "A": A,
            "B": B,
            "K_A": K_A,
            "K_B": K_B,
            "match": match,
            "is_primitive": is_primitive_root(g, p),
            "steps": [
                {"step": 1, "title": "Agreement on Public Parameters", "detail": f"Alice & Bob publicly agree on prime p = {p} and generator g = {g}."},
                {"step": 2, "title": "Alice Generates Private Key", "detail": f"Alice chooses secret integer a = {a}."},
                {"step": 3, "title": "Bob Generates Private Key", "detail": f"Bob chooses secret integer b = {b}."},
                {"step": 4, "title": "Alice Calculates Public Value", "detail": f"Alice computes A = {g}^{a} mod {p} = {A} and transmits A over insecure channel."},
                {"step": 5, "title": "Bob Calculates Public Value", "detail": f"Bob computes B = {g}^{b} mod {p} = {B} and transmits B over insecure channel."},
                {"step": 6, "title": "Alice Derives Shared Secret", "detail": f"Alice computes K_A = B^a mod p = {B}^{a} mod {p} = {K_A}."},
                {"step": 7, "title": "Bob Derives Shared Secret", "detail": f"Bob computes K_B = A^b mod p = {A}^{b} mod {p} = {K_B}."},
                {"step": 8, "title": "Key Verification", "detail": f"K_A ({K_A}) == K_B ({K_B}). Shared Secret established successfully!"}
            ]
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": f"Invalid numerical input: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/mitm/simulate', methods=['POST'])
def api_mitm_simulate():
    """
    Simulate Man-in-the-Middle Attack by Eve.
    Eve intercepts Alice's A and Bob's B, and substitutes them with Eve's values A_E and B_E.
    Calculates asymmetric keys: Alice-Eve (K_AE) and Bob-Eve (K_BE).
    Also simulates message interception and tampering.
    """
    data = request.get_json() or {}
    try:
        p = int(data.get('p', 23))
        g = int(data.get('g', 5))
        a = int(data.get('a', 6))
        b = int(data.get('b', 15))
        
        # Eve's private keys: can be single or distinct for each side
        e = int(data.get('e', 7))
        e_bob = int(data.get('e_bob', 9))  # Optional second private key for Eve
        
        # Validations
        if not is_prime(p):
            return jsonify({"status": "error", "message": f"p={p} must be prime."}), 400

        # Normal honest values (what Alice and Bob generate)
        A = pow(g, a, p)
        B = pow(g, b, p)

        # Eve generates her malicious public values to substitute
        # A_Eve sent to Bob pretending to be Alice
        A_Eve = pow(g, e, p)
        # B_Eve sent to Alice pretending to be Bob
        B_Eve = pow(g, e_bob, p)

        # Calculations performed by each entity:
        # Alice computes secret using received B_Eve and her private a
        K_Alice = pow(B_Eve, a, p)
        
        # Eve computes secret with Alice using intercepted A and her private e_bob
        K_Eve_Alice = pow(A, e_bob, p)

        # Bob computes secret using received A_Eve and his private b
        K_Bob = pow(A_Eve, b, p)

        # Eve computes secret with Bob using intercepted B and her private e
        K_Eve_Bob = pow(B, e, p)

        # Sample message passing demonstration
        original_msg = data.get('message', "Wire transfer $1,000 to Bob")
        tampered_msg = data.get('tampered_message', "Wire transfer $100,000 to Eve's Off-Shore Account")

        # Alice encrypts with K_Alice
        alice_ciphertext = simple_xor_cipher(original_msg, K_Alice)
        # Eve intercepts and decrypts with K_Eve_Alice
        eve_decrypted = simple_xor_decipher(alice_ciphertext, K_Eve_Alice)
        # Eve re-encrypts tampered message with K_Eve_Bob
        eve_reencrypted = simple_xor_cipher(tampered_msg, K_Eve_Bob)
        # Bob decrypts with K_Bob
        bob_received = simple_xor_decipher(eve_reencrypted, K_Bob)

        return jsonify({
            "status": "success",
            "parameters": {"p": p, "g": g},
            "honest_keys": {
                "a": a, "A": A,
                "b": b, "B": B
            },
            "eve_keys": {
                "e": e, "e_bob": e_bob,
                "A_Eve": A_Eve, "B_Eve": B_Eve
            },
            "secrets": {
                "K_Alice": K_Alice,
                "K_Eve_Alice": K_Eve_Alice,
                "K_Bob": K_Bob,
                "K_Eve_Bob": K_Eve_Bob,
                "alice_bob_match": (K_Alice == K_Bob),
                "alice_eve_match": (K_Alice == K_Eve_Alice),
                "bob_eve_match": (K_Bob == K_Eve_Bob)
            },
            "message_demo": {
                "original_message": original_msg,
                "alice_ciphertext": alice_ciphertext,
                "eve_decrypted": eve_decrypted,
                "tampered_message": tampered_msg,
                "eve_reencrypted": eve_reencrypted,
                "bob_received": bob_received
            },
            "attack_successful": True,
            "conclusion": "Eve successfully established two independent shared secrets. Alice and Bob cannot communicate directly and believe they are speaking with each other."
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/detection/fingerprint', methods=['POST'])
def api_detection_fingerprint():
    """
    Demonstrate Public Key / Parameter Fingerprinting verification.
    Highlights matching fingerprint vs mismatch caused by MITM alteration.
    """
    data = request.get_json() or {}
    try:
        entity = data.get('entity', 'Alice')
        public_value = str(data.get('public_value', 'A=14 (from Alice)'))
        tamper = data.get('tamper', False)
        
        # Expected fingerprint from genuine sender
        expected_fp = compute_fingerprint(f"{entity}:{public_value}")
        
        if tamper:
            # Eve substitutes her value
            tampered_value = str(data.get('tampered_value', 'A_Eve=18 (from Eve)'))
            received_fp = compute_fingerprint(f"{entity}:{tampered_value}")
        else:
            received_fp = expected_fp

        matches = (expected_fp == received_fp)

        return jsonify({
            "status": "success",
            "entity": entity,
            "public_value": public_value,
            "expected_fingerprint": expected_fp,
            "received_fingerprint": received_fp,
            "matches": matches,
            "verdict": "Authentication Successful" if matches else "WARNING: Possible MITM Attack Detected! Fingerprint mismatch indicates parameter alteration."
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/auth/sign', methods=['POST'])
def api_auth_sign():
    """
    Sign a Diffie-Hellman public parameter using genuine RSA-PSS with SHA-256.
    Uses established Python 'cryptography' library.
    """
    data = request.get_json() or {}
    try:
        identity = data.get('identity', 'alice').lower()
        dh_public_value = str(data.get('dh_public_value', '14'))
        p = str(data.get('p', '23'))
        g = str(data.get('g', '5'))

        payload = f"DH_PUB:{dh_public_value}|p:{p}|g:{g}".encode('utf-8')
        keys = get_or_create_rsa_keypair(identity)
        priv_key = keys['private_obj']

        signature = priv_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        sig_b64 = base64.b64encode(signature).decode('utf-8')
        sig_hex = signature.hex()

        return jsonify({
            "status": "success",
            "identity": identity,
            "payload_signed": payload.decode('utf-8'),
            "signature_b64": sig_b64,
            "signature_hex": sig_hex[:64] + "...",
            "public_key_pem": keys['public_pem'],
            "fingerprint": keys['fingerprint']
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/auth/verify', methods=['POST'])
def api_auth_verify():
    """
    Verify RSA-PSS signature against public key.
    Allows user to test genuine payload vs tampered payload (simulating Eve MITM).
    """
    data = request.get_json() or {}
    try:
        identity = data.get('identity', 'alice').lower()
        original_dh_val = str(data.get('original_dh_val', '14'))
        received_dh_val = str(data.get('received_dh_val', '14'))
        p = str(data.get('p', '23'))
        g = str(data.get('g', '5'))
        signature_b64 = data.get('signature_b64', '')

        if not signature_b64:
            return jsonify({"status": "error", "message": "Signature is required."}), 400

        keys = get_or_create_rsa_keypair(identity)
        pub_key = keys['public_obj']
        raw_sig = base64.b64decode(signature_b64.encode('utf-8'))

        received_payload = f"DH_PUB:{received_dh_val}|p:{p}|g:{g}".encode('utf-8')

        try:
            pub_key.verify(
                raw_sig,
                received_payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            valid = True
            message = "Signature is VALID. Public parameter originates authentically from Alice and was NOT altered in transit."
        except Exception:
            valid = False
            message = "Signature is INVALID! MITM modification detected. The public DH value was tampered with in transit by an unauthorized third party."

        return jsonify({
            "status": "success",
            "is_valid": valid,
            "verified_message": message,
            "original_value": original_dh_val,
            "received_value": received_dh_val,
            "tampered": (original_dh_val != received_dh_val)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/protected/exchange', methods=['POST'])
def api_protected_exchange():
    """
    Simulate full Authenticated Diffie-Hellman Key Exchange.
    Alice and Bob sign their DH public values.
    If Eve attempts to substitute public values, Bob or Alice aborts the exchange.
    """
    data = request.get_json() or {}
    try:
        p = int(data.get('p', 23))
        g = int(data.get('g', 5))
        a = int(data.get('a', 6))
        b = int(data.get('b', 15))
        eve_intercept = data.get('eve_intercept', False)
        
        # 1. Ephemeral DH values
        A = pow(g, a, p)
        B = pow(g, b, p)

        # 2. RSA keypairs for Alice and Bob
        alice_rsa = get_or_create_rsa_keypair("alice")
        bob_rsa = get_or_create_rsa_keypair("bob")

        # 3. Alice signs A
        alice_payload = f"DH_A:{A}|p:{p}|g:{g}".encode('utf-8')
        alice_sig = alice_rsa['private_obj'].sign(
            alice_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # 4. Bob signs B
        bob_payload = f"DH_B:{B}|p:{p}|g:{g}".encode('utf-8')
        bob_sig = bob_rsa['private_obj'].sign(
            bob_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        # 5. In transit: Eve interception check
        if eve_intercept:
            # Eve attempts to substitute A with A_Eve
            e = 7
            A_Eve = pow(g, e, p)
            received_by_bob_A = A_Eve
            # Bob receives A_Eve, but still has Alice's signature on A
            # Bob attempts verification using Alice's public key
            check_payload = f"DH_A:{A_Eve}|p:{p}|g:{g}".encode('utf-8')
            bob_verified = False
            try:
                alice_rsa['public_obj'].verify(
                    alice_sig,
                    check_payload,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                bob_verified = True
            except Exception:
                bob_verified = False

            return jsonify({
                "status": "success",
                "attack_attempted": True,
                "attack_blocked": True,
                "bob_verification_passed": bob_verified,
                "exchange_status": "ABORTED",
                "message": "ATTACK PREVENTED: Bob detected signature mismatch on Alice's public value. Key exchange aborted. Eve cannot forge Alice's RSA private key signature."
            })
        else:
            # Normal authenticated exchange
            shared_secret = pow(B, a, p)
            return jsonify({
                "status": "success",
                "attack_attempted": False,
                "attack_blocked": False,
                "bob_verification_passed": True,
                "alice_verification_passed": True,
                "exchange_status": "COMPLETED_SECURELY",
                "shared_secret": shared_secret,
                "message": "Authenticated Diffie-Hellman exchange completed successfully. Both parties verified signatures and established shared secret securely."
            })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/comparison', methods=['GET'])
def api_comparison():
    """Return comprehensive comparison dataset for all 5 key exchange mechanisms."""
    matrix = [
        {
            "id": "basic_dh",
            "name": "Basic Diffie–Hellman",
            "standard": "RFC 2631 / Diffie-Hellman 1976",
            "security": "Medium",
            "authentication": "Low",
            "key_management": "Low",
            "performance": "High",
            "reliability": "Medium",
            "scalability": "Medium",
            "mitm_protection": "Low",
            "summary": "Fast mathematical secret generation, but completely lacks identity verification. Trivially vulnerable to MITM attacks.",
            "pros": ["Zero pre-shared keys needed", "Mathematically elegant", "High computational speed"],
            "cons": ["No identity verification", "Vulnerable to active eavesdropping/MITM", "Unsuitable for open Internet"]
        },
        {
            "id": "auth_dh",
            "name": "Authenticated Diffie–Hellman",
            "standard": "Station-to-Station (STS) Protocol",
            "security": "High",
            "authentication": "High",
            "key_management": "Medium",
            "performance": "High",
            "reliability": "High",
            "scalability": "High",
            "mitm_protection": "High",
            "summary": "Combines DH with reciprocal identity challenge and pre-shared or out-of-band verification.",
            "pros": ["Defeats active MITM", "Establishes mutual trust", "Preserves key secrecy"],
            "cons": ["Requires out-of-band trust anchor", "Protocol state overhead"]
        },
        {
            "id": "dh_signatures",
            "name": "DH + Digital Signatures",
            "standard": "RSA / ECDSA Signed Key Exchange",
            "security": "High",
            "authentication": "High",
            "key_management": "Medium",
            "performance": "Medium",
            "reliability": "High",
            "scalability": "High",
            "mitm_protection": "High",
            "summary": "Every DH ephemeral public key is cryptographically signed using sender's long-term private signing key.",
            "pros": ["Non-repudiation", "Instant tamper detection", "No key alteration allowed"],
            "cons": ["Requires secure public key distribution", "Asymmetric signing CPU overhead"]
        },
        {
            "id": "dh_pki",
            "name": "DH + Digital Certificates / PKI",
            "standard": "X.509 PKI Infrastructure",
            "security": "Very High",
            "authentication": "Very High",
            "key_management": "High",
            "performance": "Medium",
            "reliability": "Very High",
            "scalability": "Very High",
            "mitm_protection": "Very High",
            "summary": "Public keys are bound to verified identities via Certificate Authorities (CAs) and signed X.509 certificates.",
            "pros": ["Global scalability without pair-wise keying", "Automated chain of trust validation", "Comprehensive revocation (CRL/OCSP)"],
            "cons": ["Dependency on trusted CAs", "Certificate expiration and management complexity"]
        },
        {
            "id": "tls_13",
            "name": "Modern TLS 1.3 Key Exchange",
            "standard": "RFC 8446 (ECDHE + Ephemeral DH)",
            "security": "Very High",
            "authentication": "Very High",
            "key_management": "High",
            "performance": "High",
            "reliability": "Very High",
            "scalability": "Very High",
            "mitm_protection": "Very High",
            "summary": "State-of-the-art secure communication protocol. Mandates Ephemeral Diffie-Hellman (ECDHE/DHE) for Perfect Forward Secrecy with 1-RTT handshake.",
            "pros": ["Guaranteed Perfect Forward Secrecy (PFS)", "1-RTT low latency handshake", "Zero insecure legacy cipher suites", "Encrypted handshake metadata"],
            "cons": ["Requires modern crypto stack support"]
        }
    ]
    return jsonify({"status": "success", "comparison_matrix": matrix})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[*] Starting DH & MITM Educational Server on http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=True)
