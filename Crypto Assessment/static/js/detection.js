/**
 * Attack Detection & Fingerprinting Controller
 */

document.addEventListener('DOMContentLoaded', () => {
  initDetection();
});

function initDetection() {
  const switchTamper = document.getElementById('switchTamperFP');
  const inputExpected = document.getElementById('fpInputExpected');
  const inputReceived = document.getElementById('fpInputReceived');
  const btnPresetNormal = document.getElementById('btnPresetNormal');
  const btnPresetMismatch = document.getElementById('btnPresetMismatch');

  if (switchTamper) {
    switchTamper.addEventListener('change', (e) => {
      if (e.target.checked) {
        inputReceived.value = "Eve_Substituted_Public_Value:A_Eve=17|p=23|g=5";
      } else {
        inputReceived.value = inputExpected.value;
      }
      evaluateFingerprints();
    });
  }

  if (inputExpected) {
    inputExpected.addEventListener('input', () => {
      if (!switchTamper.checked) {
        inputReceived.value = inputExpected.value;
      }
      evaluateFingerprints();
    });
  }

  if (inputReceived) {
    inputReceived.addEventListener('input', evaluateFingerprints);
  }

  if (btnPresetNormal) {
    btnPresetNormal.addEventListener('click', () => {
      if (switchTamper) switchTamper.checked = false;
      inputExpected.value = "Alice_DH_Public_Value:A=8|p=23|g=5";
      inputReceived.value = "Alice_DH_Public_Value:A=8|p=23|g=5";
      setHardcodedPreset("AB:12:CD:34:EF:56", "AB:12:CD:34:EF:56", true);
      showToast('Loaded standard matching fingerprint preset.', 'success');
    });
  }

  if (btnPresetMismatch) {
    btnPresetMismatch.addEventListener('click', () => {
      if (switchTamper) switchTamper.checked = true;
      inputExpected.value = "Alice_DH_Public_Value:A=8|p=23|g=5";
      inputReceived.value = "Eve_Substituted_Public_Value:A_Eve=17|p=23|g=5";
      setHardcodedPreset("AB:12:CD:34:EF:56", "91:AA:34:72:BC:10", false);
      showToast('WARNING: Possible MITM Attack Detected! (Fingerprint mismatch)', 'warning');
    });
  }

  evaluateFingerprints();
}

function setHardcodedPreset(exp, recv, isMatch) {
  document.getElementById('dispExpectedFP').textContent = exp;
  document.getElementById('dispReceivedFP').textContent = recv;
  renderVerdict(isMatch);
}

async function evaluateFingerprints() {
  const expVal = document.getElementById('fpInputExpected').value;
  const recvVal = document.getElementById('fpInputReceived').value;

  try {
    const res = await fetch('/api/detection/fingerprint', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entity: 'Alice',
        public_value: expVal,
        tamper: (expVal !== recvVal),
        tampered_value: recvVal
      })
    });

    const data = await res.json();
    if (data.status === 'success') {
      document.getElementById('dispExpectedFP').textContent = data.expected_fingerprint;
      document.getElementById('dispReceivedFP').textContent = data.received_fingerprint;
      renderVerdict(data.matches);
    }
  } catch (err) {
    console.error('Error evaluating fingerprints:', err);
  }
}

function renderVerdict(isMatch) {
  const banner = document.getElementById('detectionVerdictBanner');
  const icon = document.getElementById('verdictIcon');
  const title = document.getElementById('verdictTitle');
  const detail = document.getElementById('verdictDetail');
  const boxRecv = document.getElementById('boxReceivedFP');

  if (isMatch) {
    banner.className = 'success-banner py-2 px-3';
    icon.className = 'bi bi-check-circle-fill text-success fs-4';
    title.textContent = 'Authentication Successful';
    title.className = 'text-white fw-bold mb-0';
    detail.textContent = 'Fingerprints match exactly. Public parameters originate genuinely from Alice and were not altered in transit.';
    boxRecv.style.borderColor = 'rgba(16, 185, 129, 0.4)';
  } else {
    banner.className = 'danger-banner py-2 px-3';
    icon.className = 'bi bi-exclamation-triangle-fill text-danger fs-4';
    title.textContent = 'WARNING: Possible MITM Attack Detected';
    title.className = 'text-danger fw-bold mb-0';
    detail.textContent = 'Fingerprint mismatch detected! The received public parameter has been intercepted and substituted by an unauthorized third party.';
    boxRecv.style.borderColor = 'rgba(244, 63, 94, 0.7)';
  }
}
