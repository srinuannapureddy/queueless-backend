/* Use this pattern when replacing the old browser-only token creation. */

$('#get').onclick = async () => {
  if (!qlAuth) {
    show('login');
    return;
  }

  const name = prompt('Enter your name:');
  if (!name) return;

  try {
    const token = await api('/tokens', {
      method: 'POST',
      body: JSON.stringify({
        state: sel.st,
        district: sel.di,
        dept: sel.d,
        service: sel.s,
        name
      })
    });

    tok = token;
    save();
    renderTok();
    show('tok');
  } catch (err) {
    alert(err.message);
  }
};

/* Real queue status instead of pred() */
async function showQ() {
  try {
    const q = await api(
      `/queue-status?state=${encodeURIComponent(sel.st)}` +
      `&district=${encodeURIComponent(sel.di)}` +
      `&dept=${encodeURIComponent(sel.d)}` +
      `&service=${encodeURIComponent(sel.s)}`
    );

    $('#qn').textContent = sel.s;
    $('#qsub').textContent = `${D[sel.d].n}, ${sel.di}, ${sel.st}`;
    $('#pp').textContent = q.waiting;
    $('#ww').textContent = q.estMin + ' ' + t('min');
    $('#cf').textContent = '—';
    $('#sts').textContent = q.label;
    $('#docs').textContent = D[sel.d].docs;
    $('#map').href =
      'https://www.google.com/maps/search/?api=1&query=' +
      encodeURIComponent(D[sel.d].n + ' ' + sel.di + ' ' + sel.st);

    $('#queue').hidden = false;
  } catch (err) {
    $('#lerr').textContent = err.message;
  }
}

/* Poll a real token instead of moving position every 6 seconds locally. */
async function refreshRealToken() {
  if (!tok?.id) return;

  try {
    tok = await api('/tokens/' + encodeURIComponent(tok.id));
    save();
    renderTok();

    if (tok.alert && !tok.notified) {
      tok.notified = 1;
      alertMe();
      save();
    }
  } catch (_) {}
}

setInterval(refreshRealToken, 5000);
