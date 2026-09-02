/**
 * Man-in-the-Middle (MITM) Simulation Controller
 */

let mitmState = {
  p: 23,
  g: 5,
  a: 6,
  b: 15,
  e: 7,
  e_bob: 9,
  data: null
};

document.addEventListener('DOMContentLoaded', () => {
  initMITM();
});

async function initMITM() {
  bindMITMEvents();
  await runMITMSimulation();
}

function bindMITMEvents() {
  const btnExecute = document.getElementById('btnExecuteMITM');
  if (btnExecute) {
    btnExecute.addEventListener('click', async () => {
      // Pick randomized Eve keys for active dynamic exploit
      mitmState.e = Math.floor(Math.random() * 12) + 3;
      mitmState.e_bob = Math.floor(Math.random() * 12) + 3;
      await runMITMSimulation();
      showToast('Executed new MITM interception with randomized attacker keys!', 'danger');
    });
  }

  const btnReset = document.getElementById('btnResetMITM');
  if (btnReset) {
    btnReset.addEventListener('click', resetMITM);
  }

  const btnTransmit = document.getElementById('btnTransmitMsg');
  if (btnTransmit) {
    btnTransmit.addEventListener('click', async () => {
      await runMITMSimulation();
      showToast('Message transmitted by Alice and intercepted by Eve.', 'info');
    });
  }

  const btnForward = document.getElementById('btnEveForward');
  if (btnForward) {
    btnForward.addEventListener('click', async () => {
      await runMITMSimulation();
      showToast("Eve re-encrypted tampered message and delivered to Bob.", 'warning');
    });
  }
}

async function runMITMSimulation() {
  const msgInput = document.getElementById('msgAliceInput');
  const tamperedInput = document.getElementById('msgEveTampered');

  const message = msgInput ? msgInput.value : "Wire transfer $1,000 to Bob";
  const tampered_message = tamperedInput ? tamperedInput.value : "Wire transfer $100,000 to Eve's Off-Shore Account";

  try {
    const res = await fetch('/api/mitm/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        p: mitmState.p,
        g: mitmState.g,
        a: mitmState.a,
        b: mitmState.b,
        e: mitmState.e,
        e_bob: mitmState.e_bob,
        message: message,
        tampered_message: tampered_message
      })
    });

    const data = await res.json();
    if (!res.ok || data.status !== 'success') {
      showToast(data.message || 'Error executing MITM simulation', 'danger');
      return;
    }

    mitmState.data = data;
    renderMITM(data);
  } catch (err) {
    showToast('Failed to connect to MITM simulation server: ' + err.message, 'danger');
  }
}

function renderMITM(d) {
  const h = d.honest_keys;
  const e = d.eve_keys;
  const s = d.secrets;
  const p = d.parameters;
  const m = d.message_demo;

  // Alice
  document.getElementById('mitmAlice_a').textContent = `a = ${h.a}`;
  document.getElementById('mitmAlice_A').textContent = `A = ${h.A}`;
  document.getElementById('mitmAlice_Recv').textContent = `B_Eve = ${e.B_Eve}`;
  document.getElementById('mitmAlice_Key').innerHTML = 
    `K_Alice = (B_Eve)^a mod p = ${e.B_Eve}^${h.a} mod ${p.p} = <span class="fs-6">${s.K_Alice}</span>`;

  // Eve
  document.getElementById('mitmEve_e').textContent = `e_1 = ${e.e}`;
  document.getElementById('mitmEve_eBob').textContent = `e_2 = ${e.e_bob}`;

  // Bob
  document.getElementById('mitmBob_b').textContent = `b = ${h.b}`;
  document.getElementById('mitmBob_B').textContent = `B = ${h.B}`;
  document.getElementById('mitmBob_Recv').textContent = `A_Eve = ${e.A_Eve}`;
  document.getElementById('mitmBob_Key').innerHTML = 
    `K_Bob = (A_Eve)^b mod p = ${e.A_Eve}^${h.b} mod ${p.p} = <span class="fs-6">${s.K_Bob}</span>`;

  // Key discrepancy comparison
  document.getElementById('compAliceKey').textContent = s.K_Alice;
  document.getElementById('compBobKey').textContent = s.K_Bob;
  document.getElementById('compMatchBadge').innerHTML = 
    `<i class="bi bi-x-circle"></i> FALSE (${s.K_Alice} &ne; ${s.K_Bob})`;
  document.getElementById('compEveAliceKey').textContent = `${s.K_Eve_Alice} (Matches Alice)`;
  document.getElementById('compEveBobKey').textContent = `${s.K_Eve_Bob} (Matches Bob)`;

  // Message tampering demo
  document.getElementById('dispAliceCipher').textContent = m.alice_ciphertext;
  document.getElementById('dispEveDecrypted').textContent = m.eve_decrypted;
  document.getElementById('dispBobReceived').textContent = m.bob_received;
}

function resetMITM() {
  mitmState.p = 23;
  mitmState.g = 5;
  mitmState.a = 6;
  mitmState.b = 15;
  mitmState.e = 7;
  mitmState.e_bob = 9;

  const msgInput = document.getElementById('msgAliceInput');
  const tamperedInput = document.getElementById('msgEveTampered');
  if (msgInput) msgInput.value = "Wire transfer $1,000 to Bob";
  if (tamperedInput) tamperedInput.value = "Wire transfer $100,000 to Eve's Off-Shore Account";

  runMITMSimulation();
  showToast('Reset MITM simulation to textbook default parameters.', 'info');
}
