const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
const form = document.getElementById('check-form');
const statusEl = document.getElementById('status');
const resultsEl = document.getElementById('results');
const notifyButton = document.getElementById('notify-button');
const notifyStatus = document.getElementById('notify-status');

const renderBreaches = (breaches) => {
  if (!breaches.length) {
    resultsEl.hidden = true;
    resultsEl.innerHTML = '';
    return;
  }

  resultsEl.hidden = false;
  resultsEl.innerHTML = breaches
    .map((breach) => {
      const classes = breach.dataClasses?.join(', ') ?? '';
      return `
        <article class="breach">
          <h3>${breach.name}</h3>
          <p><strong>Domain:</strong> ${breach.domain}</p>
          <p><strong>Breach date:</strong> ${breach.breachDate}</p>
          <p><strong>Data classes:</strong> ${classes}</p>
        </article>
      `;
    })
    .join('');
};

const postJson = async (url, payload) => {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken ?? '',
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  return { ok: response.ok, status: response.status, data };
};

form?.addEventListener('submit', async (event) => {
  event.preventDefault();
  statusEl.textContent = 'Checking…';
  resultsEl.hidden = true;

  const email = document.getElementById('email')?.value ?? '';
  const { ok, data } = await postJson('/api/check', { email });

  if (!ok) {
    statusEl.textContent = data.message ?? 'Something went wrong.';
    renderBreaches([]);
    return;
  }

  statusEl.textContent = data.message ?? '';
  renderBreaches(data.breaches ?? []);
});

notifyButton?.addEventListener('click', async () => {
  notifyStatus.textContent = 'Sending verification link…';
  const email = document.getElementById('email')?.value ?? '';
  const { ok, data } = await postJson('/api/notify/request', { email });

  notifyStatus.textContent = ok
    ? data.message ?? 'Verification link sent.'
    : data.message ?? 'Unable to send verification link.';
});
