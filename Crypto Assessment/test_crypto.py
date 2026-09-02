"""
Automated unit tests for Diffie-Hellman math, MITM simulation,
RSA signatures, and Flask API endpoints.
"""

import unittest
import json
from app import (
    app, is_prime, is_primitive_root, find_primitive_root,
    simple_xor_cipher, simple_xor_decipher, compute_fingerprint,
    get_or_create_rsa_keypair
)


class TestDiffieHellmanAndCrypto(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.client.testing = True

    def test_primality_and_primitive_roots(self):
        self.assertTrue(is_prime(23))
        self.assertTrue(is_prime(47))
        self.assertTrue(is_prime(97))
        self.assertFalse(is_prime(24))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(4))

        # Check primitive root
        self.assertTrue(is_primitive_root(5, 23))
        self.assertFalse(is_primitive_root(1, 23))

    def test_dh_exchange_math(self):
        p = 23
        g = 5
        a = 6
        b = 15
        A = pow(g, a, p)
        B = pow(g, b, p)
        K_A = pow(B, a, p)
        K_B = pow(A, b, p)
        self.assertEqual(K_A, K_B)
        self.assertEqual(A, 8)
        self.assertEqual(B, 19)
        self.assertEqual(K_A, 2)

    def test_api_dh_generate(self):
        res = self.client.post('/api/dh/generate', json={'p': 23, 'g': 5, 'a': 6, 'b': 15})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['K_A'], data['K_B'])
        self.assertTrue(data['match'])
        self.assertEqual(len(data['steps']), 8)

    def test_api_mitm_simulate(self):
        res = self.client.post('/api/mitm/simulate', json={
            'p': 23, 'g': 5, 'a': 6, 'b': 15, 'e': 7, 'e_bob': 9,
            'message': 'Hello Bob', 'tampered_message': 'Hello from Eve'
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['status'], 'success')
        # Check Eve's asymmetric keys
        self.assertEqual(data['secrets']['K_Alice'], data['secrets']['K_Eve_Alice'])
        self.assertEqual(data['secrets']['K_Bob'], data['secrets']['K_Eve_Bob'])
        # Alice and Bob do NOT share the same secret
        self.assertFalse(data['secrets']['alice_bob_match'])
        # Eve's tampering succeeds
        self.assertEqual(data['message_demo']['bob_received'], 'Hello from Eve')

    def test_api_detection_fingerprint(self):
        # Genuine check
        res = self.client.post('/api/detection/fingerprint', json={
            'entity': 'Alice', 'public_value': 'A=8', 'tamper': False
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['matches'])

        # Tampered check
        res2 = self.client.post('/api/detection/fingerprint', json={
            'entity': 'Alice', 'public_value': 'A=8', 'tamper': True, 'tampered_value': 'A_Eve=14'
        })
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertFalse(data2['matches'])

    def test_rsa_signature_and_tamper_detection(self):
        # Sign
        res_sign = self.client.post('/api/auth/sign', json={
            'identity': 'alice', 'dh_public_value': '8', 'p': '23', 'g': '5'
        })
        self.assertEqual(res_sign.status_code, 200)
        sig_data = res_sign.get_json()
        sig_b64 = sig_data['signature_b64']
        self.assertTrue(bool(sig_b64))

        # Verify Genuine
        res_verify = self.client.post('/api/auth/verify', json={
            'identity': 'alice', 'original_dh_val': '8', 'received_dh_val': '8',
            'p': '23', 'g': '5', 'signature_b64': sig_b64
        })
        self.assertEqual(res_verify.status_code, 200)
        verify_data = res_verify.get_json()
        self.assertTrue(verify_data['is_valid'])

        # Verify Tampered
        res_verify_tampered = self.client.post('/api/auth/verify', json={
            'identity': 'alice', 'original_dh_val': '8', 'received_dh_val': '14',
            'p': '23', 'g': '5', 'signature_b64': sig_b64
        })
        self.assertEqual(res_verify_tampered.status_code, 200)
        verify_tampered_data = res_verify_tampered.get_json()
        self.assertFalse(verify_tampered_data['is_valid'])

    def test_api_protected_exchange(self):
        # Normal authenticated
        res_auth = self.client.post('/api/protected/exchange', json={
            'p': 23, 'g': 5, 'a': 6, 'b': 15, 'eve_intercept': False
        })
        self.assertEqual(res_auth.status_code, 200)
        auth_data = res_auth.get_json()
        self.assertEqual(auth_data['exchange_status'], 'COMPLETED_SECURELY')

        # Eve tries to intercept
        res_attack = self.client.post('/api/protected/exchange', json={
            'p': 23, 'g': 5, 'a': 6, 'b': 15, 'eve_intercept': True
        })
        self.assertEqual(res_attack.status_code, 200)
        attack_data = res_attack.get_json()
        self.assertEqual(attack_data['exchange_status'], 'ABORTED')
        self.assertTrue(attack_data['attack_blocked'])

    def test_api_comparison(self):
        res = self.client.get('/api/comparison')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(len(data['comparison_matrix']), 5)

    def test_all_pages_render(self):
        pages = ['/', '/dh', '/mitm', '/detection', '/protected-dh',
                 '/signatures', '/comparison', '/analysis', '/recommendation', '/about']
        for p in pages:
            res = self.client.get(p)
            self.assertEqual(res.status_code, 200, f"Page {p} failed to render with 200")
            self.assertIn(b'<!DOCTYPE html>', res.data, f"Page {p} did not return valid HTML")



if __name__ == '__main__':
    unittest.main()
