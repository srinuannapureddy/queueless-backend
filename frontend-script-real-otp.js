/* QueueLess REAL backend connection
   Replace the old demo login block in script.js with this.
   Keep your existing HTML/CSS.
*/
const API_BASE = 'https://YOUR-BACKEND-DOMAIN/api';

let qlAuth = localStorage.getItem('qlAuth') || '';

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (qlAuth) headers.Authorization = `Bearer ${qlAuth}`;

  const res = await fetch(API_BASE + path, { ...options, headers });
  const data = await res.json().catch(() => ({}));

  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

/* ---------- REAL SMS OTP ---------- */
$('#send').onclick = async () => {
  const mobile = $('#mob').value.trim();

  if (!/^[6-9]\d{9}$/.test(mobile)) {
    $('#lerr').textContent = 'Enter a valid 10-digit mobile number.';
    return;
  }

  $('#lerr').textContent = 'Sending OTP...';
  $('#send').disabled = true;

  try {
    await api('/auth/send-code', {
      method: 'POST',
      body: JSON.stringify({ mobile })
    });

    $('#lerr').textContent = 'OTP sent to your mobile number.';
    $('#codeBox').hidden = false;
    $('#send').hidden = true;
  } catch (err) {
    $('#lerr').textContent = err.message;
    $('#send').disabled = false;
  }
};

$('#ver').onclick = async () => {
  const mobile = $('#mob').value.trim();
  const code = $('#code').value.trim();

  if (!/^[6-9]\d{9}$/.test(mobile)) {
    $('#lerr').textContent = 'Enter a valid 10-digit mobile number.';
    return;
  }

  if (!/^\d{4,10}$/.test(code)) {
    $('#lerr').textContent = 'Enter the OTP received by SMS.';
    return;
  }

  $('#lerr').textContent = 'Verifying...';
  $('#ver').disabled = true;

  try {
    const data = await api('/auth/verify', {
      method: 'POST',
      body: JSON.stringify({ mobile, code })
    });

    qlAuth = data.token;
    localStorage.setItem('qlAuth', qlAuth);

    $('#lerr').textContent = '';
    $('nav').hidden = false;
    show('home');
  } catch (err) {
    $('#lerr').textContent = err.message;
    $('#ver').disabled = false;
  }
};
