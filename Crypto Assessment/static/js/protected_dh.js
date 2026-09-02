/**
 * Protected / Authenticated Diffie-Hellman Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  initProtectedDH();
});

function initProtectedDH() {
  const btnRun = document.getElementById('btnRunAuthDH');
  const btnToggleEve = document.getElementById('btnToggleEveAuth');

  if (btnRun) {
    btnRun.addEventListener('click', () => {
      executeProtectedDH(false);
    });
  }

  if (btnToggleEve) {
    btnToggleEve.addEventListener('click', () => {
      executeProtectedDH(true);
    });
  }

  // Run initial clean authenticated exchange
  executeProtectedDH(false);
}

async function executeProtectedDH(eveAttempt) {
  try {
    const res = await fetch('/api/protected/exchange', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        p: 23,
        g: 5,
        a: 6,
        b: 15,
        eve_intercept: eveAttempt
      })
    });

    const data = await res.json();
    renderProtectedOutcome(data, eveAttempt);
  } catch (err) {
    showToast('Protected DH error: ' + err.message, 'danger');
  }
}

function renderProtectedOutcome(data, isEveAttempt) {
  const channelBox = document.getElementById('protChannelBox');
  const channelModeText = document.getElementById('channelModeText');
  const eveStatusBadge = document.getElementById('eveStatusBadge');
  const eveStatusDesc = document.getElementById('eveStatusDesc');
  const pillPacketA = document.getElementById('pillProtPacketA');
  const badgeBobVerifyAlice = document.getElementById('badgeBobVerifyAlice');
  const badgeAliceVerifyBob = document.getElementById('badgeAliceVerifyBob');

  const banner = document.getElementById('protOutcomeBanner');
  const icon = document.getElementById('protOutcomeIcon');
  const title = document.getElementById('protOutcomeTitle');
  const desc = document.getElementById('protOutcomeDesc');

  if (isEveAttempt) {
    // Attack detected & blocked
    channelBox.style.borderColor = 'rgba(244, 63, 94, 0.6)';
    channelModeText.textContent = 'Active Interception Blocked by Signature Mismatch';
    channelModeText.className = 'text-danger small mb-3';

    eveStatusBadge.className = 'badge badge-cyber badge-crimson';
    eveStatusBadge.textContent = 'ATTACK BLOCKED';
    eveStatusDesc.textContent = 'Eve attempted to substitute A with A_Eve=17. Bob attempted signature verification using Alice’s public RSA key and the test failed!';

    pillPacketA.className = 'packet-pill packet-tampered w-100 justify-content-center mb-2';
    pillPacketA.innerHTML = '<i class="bi bi-slash-circle"></i> Tampered {A_Eve=17, Invalid Sig} <i class="bi bi-x-circle"></i>';

    badgeBobVerifyAlice.className = 'badge badge-cyber badge-crimson float-end';
    badgeBobVerifyAlice.textContent = 'FAILED (REJECTED)';

    badgeAliceVerifyBob.className = 'badge badge-cyber badge-amber float-end';
    badgeAliceVerifyBob.textContent = 'ABORTED';

    banner.className = 'danger-banner p-3';
    icon.className = 'bi bi-shield-slash-fill text-danger fs-3';
    title.textContent = 'MITM ATTACK BLOCKED & PREVENTED!';
    title.className = 'text-danger fw-bold mb-1';
    desc.textContent = data.message;

    showToast('Attack thwarted! Digital signature verification protected the key exchange.', 'success');
  } else {
    // Clean authenticated exchange
    channelBox.style.borderColor = 'rgba(16, 185, 129, 0.4)';
    channelModeText.textContent = 'Mutual Signatures Enforced & Verified';
    channelModeText.className = 'text-emerald small mb-3';

    eveStatusBadge.className = 'badge badge-cyber badge-cyan';
    eveStatusBadge.textContent = 'Passive (Bypassed)';
    eveStatusDesc.textContent = 'Eve cannot alter packets without invalidating signatures. Active tampering is completely deterred.';

    pillPacketA.className = 'packet-pill w-100 justify-content-center mb-2';
    pillPacketA.innerHTML = '<i class="bi bi-arrow-right"></i> Alice: {A=8, Valid Sig_A} <i class="bi bi-arrow-right"></i>';

    badgeBobVerifyAlice.className = 'badge badge-cyber badge-emerald float-end';
    badgeBobVerifyAlice.textContent = 'PASSED (VERIFIED)';

    badgeAliceVerifyBob.className = 'badge badge-cyber badge-emerald float-end';
    badgeAliceVerifyBob.textContent = 'PASSED (VERIFIED)';

    banner.className = 'success-banner p-3';
    icon.className = 'bi bi-shield-fill-check text-success fs-3';
    title.textContent = 'Authenticated Diffie–Hellman Completed Securely';
    title.className = 'text-white fw-bold mb-1';
    desc.textContent = `${data.message} Shared Secret established: K = ${data.shared_secret}. Both endpoints have mutually verified identities.`;

    showToast('Authenticated DH successfully completed.', 'success');
  }
}
