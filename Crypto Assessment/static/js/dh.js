/**
 * Normal Diffie-Hellman Simulation Controller
 */

let currentDHData = null;
let currentStep = 1;
const totalSteps = 8;
let autoPlayInterval = null;

const stepDetails = [
  {
    step: 1,
    title: "Step 1: Agreement on Public Parameters",
    desc: "Alice and Bob publicly agree on a large prime modulus p and a generator / primitive root g.",
    math: (d) => `Public Parameters agreed: p = ${d.p}, g = ${d.g} (Insecurely broadcast to the entire network)`
  },
  {
    step: 2,
    title: "Step 2: Alice Chooses Private Key",
    desc: "Alice selects a secret private random integer a. Alice NEVER transmits this value to anyone.",
    math: (d) => `Alice Private Key: a = ${d.a} (Kept strictly confidential in Alice's local memory)`
  },
  {
    step: 3,
    title: "Step 3: Bob Chooses Private Key",
    desc: "Bob selects his secret private random integer b. Bob NEVER transmits this value to anyone.",
    math: (d) => `Bob Private Key: b = ${d.b} (Kept strictly confidential in Bob's local memory)`
  },
  {
    step: 4,
    title: "Step 4: Alice Computes & Transmits Public Value A",
    desc: "Alice computes A = g^a mod p and sends A over the insecure network to Bob.",
    math: (d) => `A = g^a mod p = ${d.g}^${d.a} mod ${d.p} = ${d.A} (Transmitted across network)`
  },
  {
    step: 5,
    title: "Step 5: Bob Computes & Transmits Public Value B",
    desc: "Bob computes B = g^b mod p and sends B over the insecure network to Alice.",
    math: (d) => `B = g^b mod p = ${d.g}^${d.b} mod ${d.p} = ${d.B} (Transmitted across network)`
  },
  {
    step: 6,
    title: "Step 6: Alice Computes Shared Secret",
    desc: "Alice receives Bob's public value B and raises it to her private key a mod p.",
    math: (d) => `K_A = B^a mod p = ${d.B}^${d.a} mod ${d.p} = ${d.K_A}`
  },
  {
    step: 7,
    title: "Step 7: Bob Computes Shared Secret",
    desc: "Bob receives Alice's public value A and raises it to his private key b mod p.",
    math: (d) => `K_B = A^b mod p = ${d.A}^${d.b} mod ${d.p} = ${d.K_B}`
  },
  {
    step: 8,
    title: "Step 8: Cryptographic Equivalence & Verification",
    desc: "Because (g^b)^a = g^(ab) = (g^a)^b mod p, both parties arrive at the identical shared secret!",
    math: (d) => `K_A (${d.K_A}) == K_B (${d.K_B}) -> Shared Secret Established Successfully!`
  }
];

document.addEventListener('DOMContentLoaded', () => {
  initDH();
});

async function initDH() {
  bindEvents();
  await executeDHCalculation();
}

function bindEvents() {
  const presetSelect = document.getElementById('presetSelect');
  if (presetSelect) {
    presetSelect.addEventListener('change', handlePresetChange);
  }

  const btnGenerateParams = document.getElementById('btnGenerateParams');
  if (btnGenerateParams) {
    btnGenerateParams.addEventListener('click', randomizeKeys);
  }

  const btnComputeAll = document.getElementById('btnComputeAll');
  if (btnComputeAll) {
    btnComputeAll.addEventListener('click', () => {
      executeDHCalculation(true);
    });
  }

  const btnNext = document.getElementById('btnNextStep');
  if (btnNext) {
    btnNext.addEventListener('click', () => setStep(currentStep + 1));
  }

  const btnPrev = document.getElementById('btnPrevStep');
  if (btnPrev) {
    btnPrev.addEventListener('click', () => setStep(currentStep - 1));
  }

  const btnAutoPlay = document.getElementById('btnAutoPlay');
  if (btnAutoPlay) {
    btnAutoPlay.addEventListener('click', toggleAutoPlay);
  }

  const btnReset = document.getElementById('btnResetDH');
  if (btnReset) {
    btnReset.addEventListener('click', resetSimulation);
  }

  // Click on stepper circles
  document.querySelectorAll('.step-node').forEach(node => {
    node.addEventListener('click', () => {
      const s = parseInt(node.getAttribute('data-step'));
      setStep(s);
    });
  });
}

function handlePresetChange(e) {
  const val = e.target.value;
  const descEl = document.getElementById('presetDesc');
  const inputP = document.getElementById('inputP');
  const inputG = document.getElementById('inputG');

  if (val === 'custom') {
    descEl.textContent = 'Custom parameters: Ensure p is prime and g is in range [2, p-1].';
    inputP.removeAttribute('readonly');
    inputG.removeAttribute('readonly');
    return;
  }

  const presets = [
    { p: 23, g: 5, desc: 'Smallest textbook example, easy to trace by hand.' },
    { p: 47, g: 5, desc: 'Quick modular calculations with distinct generator cycles.' },
    { p: 97, g: 5, desc: 'Two-digit prime demonstrating intermediate exponentiation.' },
    { p: 283, g: 3, desc: 'Moderate sized prime with g=3 as a valid primitive root.' },
    { p: 7919, g: 7, desc: 'The 1,000th prime number, highlighting non-trivial discrete logs.' }
  ];

  const sel = presets[parseInt(val)];
  if (sel) {
    inputP.value = sel.p;
    inputG.value = sel.g;
    descEl.textContent = sel.desc;
    executeDHCalculation();
  }
}

async function randomizeKeys() {
  const p = parseInt(document.getElementById('inputP').value) || 23;
  const max = Math.min(p - 2, 40);
  const min = 2;
  const a = Math.floor(Math.random() * (max - min + 1)) + min;
  const b = Math.floor(Math.random() * (max - min + 1)) + min;

  document.getElementById('inputA').value = a;
  document.getElementById('inputB').value = b;
  showToast('Generated fresh random private keys for Alice and Bob.', 'info');
  await executeDHCalculation();
}

async function executeDHCalculation(jumpToEnd = false) {
  const validationAlert = document.getElementById('validationAlert');
  validationAlert.classList.add('d-none');

  const p = parseInt(document.getElementById('inputP').value);
  const g = parseInt(document.getElementById('inputG').value);
  const a = parseInt(document.getElementById('inputA').value);
  const b = parseInt(document.getElementById('inputB').value);

  try {
    const res = await fetch('/api/dh/generate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ p, g, a, b })
    });

    const data = await res.json();
    if (!res.ok || data.status !== 'success') {
      validationAlert.textContent = data.message || 'Error computing Diffie-Hellman exchange.';
      validationAlert.classList.remove('d-none');
      showToast(data.message, 'danger');
      return;
    }

    currentDHData = data;
    updateDisplayData(data);
    if (jumpToEnd) {
      setStep(totalSteps);
      showToast('Calculated full Diffie-Hellman key exchange.', 'success');
    } else {
      setStep(currentStep);
    }
  } catch (err) {
    validationAlert.textContent = 'Server communication error: ' + err.message;
    validationAlert.classList.remove('d-none');
  }
}

function updateDisplayData(d) {
  // Alice column
  document.getElementById('dispAliceA').textContent = `a = ${d.a}`;
  document.getElementById('dispAliceCalc').innerHTML = `A = g^a mod p<br>A = ${d.g}^${d.a} mod ${d.p} = <span class="text-white fw-bold">${d.A}</span>`;
  document.getElementById('dispAliceRecvB').textContent = `B = ${d.B} (from Bob)`;
  document.getElementById('dispAliceSecret').innerHTML = `K_A = B^a mod p<br>K_A = ${d.B}^${d.a} mod ${d.p} = <span class="math-secret fs-6">${d.K_A}</span>`;

  // Network packets
  document.getElementById('packetAVal').textContent = d.A;
  document.getElementById('packetBVal').textContent = d.B;
  document.getElementById('obsP').textContent = d.p;
  document.getElementById('obsG').textContent = d.g;
  document.getElementById('obsA').textContent = d.A;
  document.getElementById('obsB').textContent = d.B;

  // Bob column
  document.getElementById('dispBobB').textContent = `b = ${d.b}`;
  document.getElementById('dispBobCalc').innerHTML = `B = g^b mod p<br>B = ${d.g}^${d.b} mod ${d.p} = <span class="text-white fw-bold">${d.B}</span>`;
  document.getElementById('dispBobRecvA').textContent = `A = ${d.A} (from Alice)`;
  document.getElementById('dispBobSecret').innerHTML = `K_B = A^b mod p<br>K_B = ${d.A}^${d.b} mod ${d.p} = <span class="math-secret fs-6">${d.K_B}</span>`;

  document.getElementById('verifiedSecretVal').textContent = d.K_A;
}

function setStep(stepNum) {
  if (!currentDHData) return;
  if (stepNum < 1) stepNum = 1;
  if (stepNum > totalSteps) stepNum = totalSteps;

  currentStep = stepNum;

  // Update Stepper Nodes
  document.querySelectorAll('.step-node').forEach(node => {
    const s = parseInt(node.getAttribute('data-step'));
    node.classList.remove('active', 'completed');
    if (s === currentStep) {
      node.classList.add('active');
    } else if (s < currentStep) {
      node.classList.add('completed');
    }
  });

  // Update Stepper Header
  document.getElementById('stepCounter').textContent = `Step ${currentStep} of ${totalSteps}`;

  // Update Description & Math
  const info = stepDetails[currentStep - 1];
  document.getElementById('activeStepTitle').textContent = info.title;
  document.getElementById('activeStepDesc').textContent = info.desc;
  document.getElementById('activeStepMath').textContent = info.math(currentDHData);

  // Buttons enable/disable
  document.getElementById('btnPrevStep').disabled = (currentStep === 1);
  const btnNext = document.getElementById('btnNextStep');
  if (currentStep === totalSteps) {
    btnNext.innerHTML = 'Complete <i class="bi bi-check2"></i>';
    btnNext.classList.remove('btn-cyber-cyan');
    btnNext.classList.add('btn-cyber-emerald');
  } else {
    btnNext.innerHTML = 'Next Step <i class="bi bi-chevron-right"></i>';
    btnNext.classList.remove('btn-cyber-emerald');
    btnNext.classList.add('btn-cyber-cyan');
  }

  // Show/Hide Success Banner
  const successBanner = document.getElementById('successBanner');
  if (currentStep === totalSteps) {
    successBanner.classList.remove('d-none');
  } else {
    successBanner.classList.add('d-none');
  }
}

function toggleAutoPlay() {
  const btn = document.getElementById('btnAutoPlay');
  if (autoPlayInterval) {
    clearInterval(autoPlayInterval);
    autoPlayInterval = null;
    btn.innerHTML = '<i class="bi bi-play-fill"></i> Auto Play Stepper';
    btn.classList.remove('btn-cyber-crimson');
    btn.classList.add('btn-cyber-outline');
    showToast('Auto-play paused.', 'info');
  } else {
    if (currentStep === totalSteps) {
      setStep(1);
    }
    btn.innerHTML = '<i class="bi bi-pause-fill"></i> Pause Stepper';
    btn.classList.remove('btn-cyber-outline');
    btn.classList.add('btn-cyber-crimson');
    showToast('Auto-playing steps...', 'info');

    autoPlayInterval = setInterval(() => {
      if (currentStep < totalSteps) {
        setStep(currentStep + 1);
      } else {
        clearInterval(autoPlayInterval);
        autoPlayInterval = null;
        btn.innerHTML = '<i class="bi bi-play-fill"></i> Auto Play Stepper';
        btn.classList.remove('btn-cyber-crimson');
        btn.classList.add('btn-cyber-outline');
      }
    }, 2200);
  }
}

function resetSimulation() {
  if (autoPlayInterval) {
    clearInterval(autoPlayInterval);
    autoPlayInterval = null;
    document.getElementById('btnAutoPlay').innerHTML = '<i class="bi bi-play-fill"></i> Auto Play Stepper';
  }
  document.getElementById('inputP').value = 23;
  document.getElementById('inputG').value = 5;
  document.getElementById('inputA').value = 6;
  document.getElementById('inputB').value = 15;
  document.getElementById('presetSelect').value = '0';
  document.getElementById('presetDesc').textContent = 'Smallest textbook example, easy to trace by hand.';
  setStep(1);
  executeDHCalculation();
  showToast('Simulation reset to default parameters (p=23, g=5).', 'info');
}
