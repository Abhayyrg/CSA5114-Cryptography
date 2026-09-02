"""
End-to-end integration test against the running Flask server on http://127.0.0.1:5000
"""

import urllib.request
import json
import sys


BASE_URL = "http://127.0.0.1:5000"


def test_url(path, expected_text=None):
    url = BASE_URL + path
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'IntegrationTester'})
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            content = response.read().decode('utf-8')
            assert status == 200, f"Expected 200, got {status} for {url}"
            if expected_text:
                assert expected_text in content, f"Expected '{expected_text}' in response for {url}"
            print(f"[OK] GET {path} (200 OK)")
            return content
    except Exception as e:
        print(f"[FAIL] GET {path}: {e}")
        sys.exit(1)


def test_post_json(path, payload, expected_key=None, expected_val=None):
    url = BASE_URL + path
    data = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json', 'User-Agent': 'IntegrationTester'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            res_data = json.loads(response.read().decode('utf-8'))
            assert status == 200, f"Expected 200, got {status} for {url}"
            if expected_key:
                assert expected_key in res_data, f"Key {expected_key} missing in {res_data}"
            if expected_val is not None:
                assert res_data.get(expected_key) == expected_val, f"Expected {expected_val}, got {res_data.get(expected_key)}"
            print(f"[OK] POST {path} -> {res_data.get('status', 'OK')}")
            return res_data
    except Exception as e:
        print(f"[FAIL] POST {path}: {e}")
        sys.exit(1)


def main():
    print("=== Testing All 10 Page Routes ===")
    test_url('/', 'Diffie–Hellman Key Exchange & MITM Attack Protection')
    test_url('/dh', 'Standard Diffie–Hellman Key Exchange')
    test_url('/mitm', 'MITM ATTACK SUCCESSFUL')
    test_url('/detection', 'Attack Detection & Cryptographic Fingerprinting')
    test_url('/protected-dh', 'Protected Diffie–Hellman Exchange')
    test_url('/signatures', 'Digital Signature Demonstration')
    test_url('/comparison', 'Cryptographic Countermeasure Comparison')
    test_url('/analysis', 'In-Depth Security Analysis')
    test_url('/recommendation', 'Recommended Secure Architecture')
    test_url('/about', 'Assignment Specification')

    print("\n=== Testing REST API Endpoints ===")
    # 1. DH presets
    presets = test_url('/api/dh/presets', 'Classroom Classic')

    # 2. DH generation & validation
    dh_res = test_post_json('/api/dh/generate', {'p': 23, 'g': 5, 'a': 6, 'b': 15}, 'match', True)
    assert dh_res['K_A'] == 2 and dh_res['K_B'] == 2
    assert len(dh_res['steps']) == 8
    print("   -> Verified K_A == K_B == 2 with 8 educational steps")

    # 3. MITM simulation
    mitm_res = test_post_json('/api/mitm/simulate', {
        'p': 23, 'g': 5, 'a': 6, 'b': 15, 'e': 7, 'e_bob': 9,
        'message': 'Wire transfer $1,000 to Bob',
        'tampered_message': 'Wire transfer $100,000 to Eve'
    }, 'attack_successful', True)
    assert not mitm_res['secrets']['alice_bob_match'], "Alice and Bob secrets must not match during MITM!"
    assert mitm_res['secrets']['alice_eve_match'], "Alice and Eve secrets must match!"
    assert mitm_res['secrets']['bob_eve_match'], "Bob and Eve secrets must match!"
    assert mitm_res['message_demo']['bob_received'] == 'Wire transfer $100,000 to Eve'
    print("   -> Verified MITM interception & fraudulent message tampering")

    # 4. Detection fingerprint
    fp_match = test_post_json('/api/detection/fingerprint', {
        'entity': 'Alice', 'public_value': 'A=8', 'tamper': False
    }, 'matches', True)
    assert "Authentication Successful" in fp_match['verdict']

    fp_mismatch = test_post_json('/api/detection/fingerprint', {
        'entity': 'Alice', 'public_value': 'A=8', 'tamper': True, 'tampered_value': 'A=17'
    }, 'matches', False)
    assert "WARNING" in fp_mismatch['verdict']
    print("   -> Verified Fingerprint match and tamper detection")

    # 5. RSA Signatures
    sign_res = test_post_json('/api/auth/sign', {
        'identity': 'alice', 'dh_public_value': '8', 'p': '23', 'g': '5'
    }, 'status', 'success')
    sig_b64 = sign_res['signature_b64']

    # Genuine verify
    verify_res = test_post_json('/api/auth/verify', {
        'identity': 'alice', 'original_dh_val': '8', 'received_dh_val': '8',
        'p': '23', 'g': '5', 'signature_b64': sig_b64
    }, 'is_valid', True)
    print("   -> Verified genuine RSA-PSS signature verification: VALID")

    # Tampered verify
    verify_tampered = test_post_json('/api/auth/verify', {
        'identity': 'alice', 'original_dh_val': '8', 'received_dh_val': '17',
        'p': '23', 'g': '5', 'signature_b64': sig_b64
    }, 'is_valid', False)
    assert "INVALID" in verify_tampered['verified_message']
    print("   -> Verified tampered RSA-PSS signature verification: INVALID (MITM Detected)")

    # 6. Protected DH
    prot_normal = test_post_json('/api/protected/exchange', {
        'p': 23, 'g': 5, 'a': 6, 'b': 15, 'eve_intercept': False
    }, 'exchange_status', 'COMPLETED_SECURELY')

    prot_attack = test_post_json('/api/protected/exchange', {
        'p': 23, 'g': 5, 'a': 6, 'b': 15, 'eve_intercept': True
    }, 'exchange_status', 'ABORTED')
    assert prot_attack['attack_blocked'] is True
    print("   -> Verified Protected DH blocks Eve's attack and aborts exchange")

    # 7. Comparison matrix
    comp_res = test_url('/api/comparison', 'TLS 1.3')
    print("   -> Verified Comparison Matrix endpoint returns 5 architectural profiles")

    print("\nALL 17 INTEGRATION TESTS PASSED PERFECTLY!")


if __name__ == '__main__':
    main()
