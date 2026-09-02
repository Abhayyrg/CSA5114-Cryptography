/**
 * Common Helper Utilities for DH & MITM Educational Application
 */

function showToast(message, type = 'info') {
  const toastEl = document.getElementById('cyberToast');
  const toastMsg = document.getElementById('toastMessage');
  if (!toastEl || !toastMsg) return;

  let icon = 'bi-info-circle-fill text-info';
  if (type === 'success') icon = 'bi-check-circle-fill text-success';
  if (type === 'error' || type === 'danger') icon = 'bi-exclamation-octagon-fill text-danger';
  if (type === 'warning') icon = 'bi-exclamation-triangle-fill text-warning';

  toastMsg.innerHTML = `<i class="bi ${icon} fs-5"></i> <span>${message}</span>`;
  const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
  toast.show();
}

/**
 * Format large numbers or binary with commas/spaces
 */
function formatNumber(num) {
  return Number(num).toLocaleString();
}
