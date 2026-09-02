# Evaluation of Diffie–Hellman Key Exchange and Protection Against Man-in-the-Middle Attacks

**Network Security Academic Assignment & Interactive Demonstration Tool**

---

## 1. Problem Statement

The **Diffie–Hellman (DH) Key Exchange**, introduced by Whitfield Diffie and Martin Hellman in 1976, was the first practical method enabling two parties (Alice and Bob) to establish a shared secret key across an insecure public channel without transmitting the key itself. The mathematical secrecy relies on the difficulty of the **Discrete Logarithm Problem (DLP)** in finite groups.

However, **basic Diffie–Hellman provides zero endpoint authentication**. When an active adversary (Eve) occupies the communication path, she can intercept public parameters, replace them with her own values, and establish independent cryptographic keys with each victim. Both parties falsely assume they are speaking securely with each other, while the attacker can eavesdrop, decrypt, modify, and re-encrypt all network traffic without detection.

---

## 2. Project Objectives

1. **Demonstrate Normal Diffie–Hellman:** Illustrate the step-by-step modular mathematics ($g^a \bmod p$, $g^b \bmod p$) that allow two endpoints to reach an identical secret key ($K_A = K_B$).
2. **Demonstrate Active MITM Vulnerability:** Simulate how Eve intercepts public values, substitutes them with $A_E$ and $B_E$, and creates two distinct secrets ($K_{AE} \neq K_{BE}$), enabling real-time message tampering.
3. **Explore Attack Detection Mechanisms:** Implement key fingerprinting (SHA-256) and show how parameter alteration triggers immediate mismatch warnings.
4. **Demonstrate Cryptographic Countermeasures:** Integrate genuine digital signatures using RSA-PSS and SHA-256 via Python `cryptography` to prove message authenticity and non-repudiation.
5. **Demonstrate Protected (Authenticated) Diffie–Hellman:** Show how signature verification gates key derivation, instantly aborting the exchange if tampering is detected.
6. **Evaluate Countermeasure Architectures:** Provide a 7-criterion comparative matrix spanning Basic DH, Authenticated DH, DH+Signatures, DH+PKI, and modern TLS 1.3.
7. **Architectural Recommendation:** Formulate an architectural blueprint for modern networks (TLS 1.3 with Ephemeral Diffie–Hellman / ECDHE and X.509 PKI).

---

## 3. Application Modules

The application is structured into 10 dedicated modules:

| # | Module Name | Route | Description |
|---|-------------|-------|-------------|
| 1 | **Dashboard** | `/` | System overview, vulnerability diagrams, and faculty evaluation guide. |
| 2 | **Normal Diffie–Hellman** | `/dh` | 8-step interactive stepper, custom/preset parameters ($p, g, a, b$), and live modular math. |
| 3 | **MITM Attack Simulation** | `/mitm` | Interception topology, key asymmetry ($K_A \neq K_B$), and live message tampering console. |
| 4 | **Attack Detection** | `/detection` | SHA-256 key fingerprints, matching vs mismatch detection, and the 7 defensive pillars. |
| 5 | **Protected Diffie–Hellman** | `/protected-dh` | Authenticated exchange with mutual signature verification and attack deterrence. |
| 6 | **Digital Signatures** | `/signatures` | Real RSA-2048 signing with PSS padding & SHA-256; live byte-tampering test. |
| 7 | **Countermeasure Comparison** | `/comparison` | Comparative evaluation matrix across Security, Authentication, Performance, etc. |
| 8 | **Security Analysis** | `/analysis` | Mathematical analysis of DLP, forward secrecy, and quantum computing vulnerabilities. |
| 9 | **Final Recommendation** | `/recommendation` | End-to-end blueprint diagram isolating Eve outside the TLS 1.3 trust boundary. |
| 10 | **About / Documentation** | `/about` | Assignment specifications, rubric compliance, and formal academic references. |

---

## 4. Technologies Used

- **Frontend:** HTML5, CSS3 (Custom Cyber Dark Glassmorphism Theme), Vanilla JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons
- **Backend:** Python 3.11+, Flask 3.0+
- **Cryptography Engine:**
  - Python Standard Library `pow(base, exp, mod)` for exact Diffie–Hellman arithmetic.
  - Python Standard Library `hashlib` for SHA-256 fingerprinting.
  - `cryptography` library (`cryptography.hazmat.primitives.asymmetric.rsa`) for real RSA-PSS digital signatures.
- **Database:** None required (stateless, reproducible educational simulator).

---

## 5. System Requirements

- Python 3.9, 3.10, 3.11, or 3.12
- `pip` package manager
- Any modern web browser (Chrome, Edge, Firefox, Safari)

---

## 6. Installation & Quick Start

### 1. Clone or Navigate to the Project Directory
```bash
cd "c:\Users\Abhay\Downloads\Crypto Assessment"
```

### 2. Install Required Dependencies
```bash
pip install -r requirements.txt
```
*(Dependencies: `Flask>=3.0.0`, `cryptography>=42.0.0`)*

### 3. Run Automated Tests
```bash
python test_crypto.py
```
*(Verifies primality testing, DH calculations, MITM exploits, RSA signatures, and all 10 page routes)*

### 4. Start the Application
```bash
python app.py
```

### 5. Access the Web Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. How to Demonstrate (Step-by-Step for Evaluation)

### Demonstration 1: Normal Diffie–Hellman
1. Navigate to **Normal DH** (`/dh`).
2. Select the **Classroom Classic (p=23, g=5)** preset.
3. Click **Auto Play Stepper** or step through Steps 1 to 8:
   - Alice computes $A = 5^6 \bmod 23 = 8$.
   - Bob computes $B = 5^{15} \bmod 23 = 19$.
   - Alice computes $K_A = 19^6 \bmod 23 = 2$.
   - Bob computes $K_B = 8^{15} \bmod 23 = 2$.
4. Observe the green confirmation banner: **"Shared Secret Successfully Established (K = 2)"**.

### Demonstration 2: MITM Attack Simulation
1. Navigate to **MITM Attack** (`/mitm`).
2. Click **Start MITM Attack**.
3. Observe how Eve intercepts Alice's $A=8$ and Bob's $B=19$ and substitutes $A_E=17$ and $B_E=13$.
4. Notice that $K_{Alice} = 12$ while $K_{Bob} = 18$ ($K_{Alice} \neq K_{Bob}$).
5. Under **Live Packet Interception & Tampering Demo**:
   - Alice sends: *"Wire transfer $1,000 to Bob"*.
   - Eve decrypts it with $K_{EA}=12$, alters it to *"Wire transfer $100,000 to Eve's Off-Shore Account"*, and re-encrypts with $K_{EB}=18$.
   - Bob decrypts the fraudulent message cleanly with his key $K_{Bob}=18$, unaware of the compromise.

### Demonstration 3: Attack Detection & Fingerprinting
1. Navigate to **Attack Detection** (`/detection`).
2. Click **Load Matching Preset**: shows fingerprint `AB:12:CD:34:EF:56` &rarr; **Authentication Successful**.
3. Click **Load Mismatch Preset**: shows fingerprint `91:AA:34:72:BC:10` &rarr; **WARNING: Possible MITM Attack Detected**.

### Demonstration 4: Real RSA Digital Signatures
1. Navigate to **Digital Signatures** (`/signatures`).
2. Click **Generate RSA Digital Signature**: generates real 2048-bit RSA-PSS signature over $A=8$.
3. Click **Verify Digital Signature**: shows **VALID**.
4. Click **Tamper Value (Eve MITM)**: modifies value to $17$.
5. Click **Verify Digital Signature**: shows **INVALID** with alert: *"MITM modification detected!"*

### Demonstration 5: Protected Diffie–Hellman & Architectural Evaluation
1. Navigate to **Protected DH** (`/protected-dh`).
2. Click **Execute Protected Exchange**: Alice and Bob sign their public shares; mutual verification succeeds.
3. Click **Simulate Eve Attack**: Eve attempts substitution; Bob rejects the invalid signature and aborts key derivation immediately.
4. Review **Countermeasures** (`/comparison`) and **Recommendation** (`/recommendation`) to examine the TLS 1.3 architecture.

---

## 8. Cryptographic Summary & Formulas

### Basic Diffie–Hellman Exchange
1. Public parameters: Prime $p$, Generator $g \in \mathbb{F}_p^*$.
2. Alice private $a \in [2, p-2]$, sends public $A = g^a \bmod p$.
3. Bob private $b \in [2, p-2]$, sends public $B = g^b \bmod p$.
4. Alice computes: $K_A = B^a \bmod p = (g^b)^a \equiv g^{ab} \bmod p$.
5. Bob computes: $K_B = A^b \bmod p = (g^a)^b \equiv g^{ab} \bmod p$.

### MITM Attack Formulation
1. Eve intercepts $A$, forwards $A_E = g^{e_1} \bmod p$ to Bob.
2. Eve intercepts $B$, forwards $B_E = g^{e_2} \bmod p$ to Alice.
3. Alice derives: $K_{AE} = (B_E)^a = g^{a \cdot e_2} \bmod p$.
4. Bob derives: $K_{BE} = (A_E)^b = g^{b \cdot e_1} \bmod p$.
5. Eve derives both: $K_{AE} = A^{e_2} \bmod p$ and $K_{BE} = B^{e_1} \bmod p$.

### Countermeasure: Authenticated DH (STS Protocol)
- Alice sends: $\{A, \text{Sign}_{SK_A}(A, B, p, g)\}$.
- Bob verifies with $PK_A$. Because Eve cannot forge $\text{Sign}_{SK_A}$, substitution is impossible.

---

## 9. Academic Disclaimer

> **IMPORTANT:** This application is strictly an educational tool developed for academic evaluation in Network Security coursework. It utilizes small prime numbers (e.g. $p=23$) so that calculations can be manually verified by students and faculty. It is NOT intended for production cryptographic use. Real-world systems require standardized safe primes ($\ge 2048$ bits) or elliptic curves (e.g. Curve25519) integrated with X.509 Public Key Infrastructure (PKI).

---

## 10. References

1. **Diffie, W., & Hellman, M. (1976).** *New Directions in Cryptography.* IEEE Transactions on Information Theory, 22(6), 644-654.
2. **Rescorla, E. (2018).** *The Transport Layer Security (TLS) Protocol Version 1.3.* RFC 8446, IETF.
3. **Diffie, W., van Oorschot, P. C., & Wiener, M. J. (1992).** *Authentication and Authenticated Key Exchanges.* Designs, Codes and Cryptography, 2(2), 107-125.
4. **Kivinen, T., & Kojo, M. (2003).** *More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE).* RFC 3526.
