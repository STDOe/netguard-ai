const form = document.querySelector('#login');
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const field = document.querySelector('#token');
  const status = document.querySelector('#error');
  const submit = form.querySelector('button');
  submit.disabled = true;
  try {
    const body = JSON.stringify({token: field.value});
    field.value = '';
    const response = await fetch('/session', {
      method: 'POST', headers: {'Content-Type': 'application/json', 'X-NetGuard-Login': '1'}, body
    });
    if (!response.ok) throw new Error(response.status === 401 ? 'Access token rejected.' : 'Unable to sign in.');
    location.reload();
  } catch (error) {
    status.textContent = error.message;
    field.focus();
  } finally {
    submit.disabled = false;
  }
});
