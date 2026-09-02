/**
 * Digital Signatures Demonstration Controller
 */

let activeSignature = '';
let originalValue = '8';

document.addEventListener('DOMContentLoaded', () => {
  initSignatures();
});

async function initSignatures() {
  bindSigEvents();
  // Automatically generate initial signature
  await generateSignature();
}

function bindSigEvents() {
  const btnSign = document.getElementById('btnSignPayload');
  if (btnSign) {
    btnSign.addEventListener('click', generateSignature);
  }

  const btnVerify = document.getElementById('btnVerifySig');
  if (btnVerify) {
    btnVerify.addEventListener('click', verifySignature);
  }

  const btnTamper = document.getElementById('btnTamperValue');
  if (btnTamper) {
    btnTamper.addEventListener('click', () => {
      const inputRecv = document.getElementById('verifyReceivedVal');
      inputRecv.value = '17'; // Eve's substituted value
      inputRecv.classList.remove('text-info');
      inputRecv.classList.add('text-danger');
      document.getElementById('tamperStatusLabel').innerHTML = 
        '<span class="text-danger fw-bold"><i class="bi bi-radioactive"></i> TAMPERED: Substituted by Eve (A_Eve = 17)</span>';
      verifySignature();
      showToast('Value tampered with in transit by Eve!', 'warning');
    });
  }

  const btnRestore = document.getElementById('btnRestoreValue');
  if (btnRestore) {
    btnRestore.addEventListener('click', () => {
      const inputRecv = document.getElementById('verifyReceivedVal');
      inputRecv.value = originalValue;
      inputRecv.classList.remove('text-danger');
      inputRecv.classList.add('text-info');
      document.getElementById('tamperStatusLabel').innerHTML = 
        'Status: Value is authentic and matches original transmission.';
      verifySignature();
      showToast('Restored authentic original value.', 'info');
    });
  }
}

async function generateSignature() {
  const p = document.getElementById('sigInputP').value;
  const g = document.getElementById('sigInputG').value;
  const A = document.getElementById('sigInputA').value;
  originalValue = A;

  document.getElementById('dispPayloadSigned').textContent = `DH_PUB:${A}|p:${p}|g:${g}`;

  try {
    const res = await fetch('/api/auth/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identity: 'alice',
        dh_public_value: A,
        p: p,
        g: g
      })
    });

    const data = await res.json();
    if (data.status === 'success') {
      activeSignature = data.signature_b64;
      document.getElementById('dispSignatureB64').value = activeSignature;
      document.getElementById('resSigPreview').textContent = activeSignature.substring(0, 48) + '...';
      document.getElementById('verifyReceivedVal').value = A;
      document.getElementById('resOriginalMsg').textContent = `Alice DH Public Value: A = ${A}`;
      await verifySignature();
      showToast('Successfully generated RSA-2048 / SHA-256 digital signature.', 'success');
    }
  } catch (err) {
    showToast('Signature error: ' + err.message, 'danger');
  }
}

async function verifySignature() {
  const p = document.getElementById('sigInputP').value;
  const g = document.getElementById('sigInputG').value;
  const receivedVal = document.getElementById('verifyReceivedVal').value;

  document.getElementById('resReceivedMsg').textContent = `Received Value: ${receivedVal}`;

  if (!activeSignature) {
    showToast('Please generate a signature first.', 'warning');
    return;
  }

  try {
    const res = await fetch('/api/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identity: 'alice',
        original_dh_val: originalValue,
        received_dh_val: receivedVal,
        p: p,
        g: g,
        signature_b64: activeSignature
      })
    });

    const data = await res.json();
    renderVerificationOutcome(data);
  } catch (err) {
    showToast('Verification failed: ' + err.message, 'danger');
  }
}

function renderVerificationOutcome(data) {
  const badge = document.getElementById('badgeVerification');
  const banner = document.getElementById('sigAlertResult');
  const icon = document.getElementById('sigResultIcon');
  const title = document.getElementById('sigResultTitle');
  const desc = document.getElementById('sigResultDesc');

  if (data.is_valid) {
    badge.className = 'badge badge-cyber badge-emerald fs-6';
    badge.textContent = 'VALID';

    banner.className = 'success-banner py-2 px-3';
    icon.className = 'bi bi-shield-fill-check text-success fs-4';
    title.textContent = 'Signature VALID: Integrity & Authenticity Verified';
    title.className = 'text-white fw-bold mb-0';
    desc.textContent = data.verified_message;
  } else {
    badge.className = 'badge badge-cyber badge-crimson fs-6';
    badge.textContent = 'INVALID';

    banner.className = 'danger-banner py-2 px-3';
    icon.className = 'bi bi-shield-fill-x text-danger fs-4';
    title.textContent = 'Signature INVALID: MITM modification detected!';
    title.className = 'text-danger fw-bold mb-0';
    desc.textContent = data.verified_message;
  }
}
