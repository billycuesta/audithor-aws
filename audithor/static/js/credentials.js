const el = (id) => document.getElementById(id);
let mode = 'keys';
const safeGet = (key) => { try { return localStorage.getItem(key); } catch { return null; } };
const safeSet = (key, value) => { try { localStorage.setItem(key, value); } catch { /* storage may be unavailable */ } };
export function getCredentialMode() { return mode; }
function paintMode() {
  for (const prefix of ['', 'landing-']) {
    const keys = el(`${prefix}credential-mode-keys`), profile = el(`${prefix}credential-mode-profile`);
    for (const [button, active] of [[keys, mode === 'keys'], [profile, mode === 'profile']]) {
      if (!button) continue;
      button.setAttribute('aria-checked', String(active));
      button.classList.toggle('bg-[#eb3496]', active); button.classList.toggle('text-white', active);
      button.classList.toggle(prefix ? 'text-slate-100' : 'text-gray-600', !active);
      button.classList.toggle(prefix ? 'hover:bg-white/10' : 'hover:bg-gray-200', !active);
    }
    if (prefix) {
      const keyArea = el('landing-key-controls');
      keyArea?.classList.toggle('hidden', mode === 'profile'); keyArea?.setAttribute('aria-hidden', String(mode === 'profile'));
    } else {
      for (const id of ['key-cell-access', 'key-cell-secret', 'key-cell-token']) {
        const cell = el(id); cell?.classList.toggle('hidden', mode === 'profile'); cell?.setAttribute('aria-hidden', String(mode === 'profile'));
      }
    }
    const profileArea = el(prefix ? 'landing-profile-controls' : 'profile-controls');
    profileArea?.classList.toggle('hidden', mode !== 'profile'); profileArea?.setAttribute('aria-hidden', String(mode !== 'profile'));
    const hintArea = el(`${prefix}aws-profile-hint-area`);
    const profileDisabled = Boolean(el(`${prefix}credential-mode-profile`)?.disabled);
    hintArea?.classList.toggle('hidden', mode !== 'profile' && !profileDisabled);
    hintArea?.setAttribute('aria-hidden', String(mode !== 'profile' && !profileDisabled));
    const select = el(`${prefix}aws-profile-select`); select?.setAttribute('aria-hidden', String(mode !== 'profile'));
  }
  safeSet('audithor.credentialMode', mode);
}
export function syncCredentialMode() { paintMode(); }
function syncProfile(value) {
  for (const id of ['aws-profile-select', 'landing-aws-profile-select']) { const select = el(id); if (select) select.value = value; }
  safeSet('audithor.awsProfile', value);
}
export function buildCredentialPayload() {
  if (mode === 'profile') return { profile: el('aws-profile-select')?.value || '' };
  const payload = { access_key: el('access-key-input')?.value.trim() || '', secret_key: el('secret-key-input')?.value.trim() || '' };
  const token = el('session-token-input')?.value.trim(); if (token) payload.session_token = token;
  return payload;
}
export function validateCredentials() {
  const payload = buildCredentialPayload();
  if (mode === 'profile') return payload.profile ? null : 'Please select an AWS profile.';
  return payload.access_key && payload.secret_key ? null : 'Please enter the Access Key ID and Secret Access Key.';
}
export async function loadProfiles() {
  const selects = [el('aws-profile-select'), el('landing-aws-profile-select')].filter(Boolean);
  try {
    const response = await fetch(window.CONSTANTS.API.AWS_PROFILES, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const data = await response.json();
    if (!response.ok || data.error) throw new Error(data.error || `Unable to load AWS profiles (${response.status})`);
    const profiles = Array.isArray(data.profiles) ? data.profiles : [];
    const unavailableReason = 'Profile scans are only available when Audithor is bound to this machine (loopback).';
    for (const prefix of ['', 'landing-']) {
      const radio = el(`${prefix}credential-mode-profile`);
      if (radio) {
        radio.disabled = data.enabled === false;
        radio.setAttribute('aria-disabled', String(data.enabled === false));
        if (data.enabled === false) radio.title = unavailableReason;
        else radio.removeAttribute('title');
      }
      const hint = el(`${prefix}aws-profile-hint`);
      if (hint) hint.textContent = data.enabled === false ? unavailableReason : 'From ~/.aws/credentials and ~/.aws/config';
    }
    if (data.enabled === false && mode === 'profile') mode = 'keys';
    if (data.enabled === false) paintMode();
    for (const select of selects) {
      select.replaceChildren();
      if (data.enabled === false) { const option = document.createElement('option'); option.textContent = unavailableReason; select.append(option); select.disabled = true; continue; }
      if (!profiles.length) { const option = document.createElement('option'); option.textContent = 'No profiles found in ~/.aws'; select.append(option); select.disabled = true; continue; }
      select.disabled = false;
      for (const name of profiles) { const option = document.createElement('option'); option.value = name; option.textContent = name; select.append(option); }
      const remembered = safeGet('audithor.awsProfile'); const chosen = remembered && profiles.includes(remembered) ? remembered : data.default;
      if (chosen && profiles.includes(chosen)) select.value = chosen;
    }
    const selected = selects[0]?.value; if (selected) { for (const select of selects) select.value = selected; }
  } catch (error) {
    for (const select of selects) { select.replaceChildren(); const option = document.createElement('option'); option.textContent = error.message || 'Unable to load AWS profiles'; select.append(option); select.disabled = true; }
  }
}
export function initCredentialControls() {
  const rememberedMode = safeGet('audithor.credentialMode'); if (rememberedMode === 'profile' || rememberedMode === 'keys') mode = rememberedMode;
  for (const prefix of ['', 'landing-']) {
    const buttons = [el(`${prefix}credential-mode-keys`), el(`${prefix}credential-mode-profile`)];
    buttons[0]?.addEventListener('click', () => { mode = 'keys'; paintMode(); });
    buttons[1]?.addEventListener('click', () => { mode = 'profile'; paintMode(); });
    buttons[0]?.parentElement?.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      event.preventDefault(); mode = mode === 'keys' ? 'profile' : 'keys'; paintMode(); (mode === 'keys' ? buttons[0] : buttons[1])?.focus();
    });
    el(`${prefix}aws-profile-refresh`)?.addEventListener('click', loadProfiles);
    el(`${prefix}aws-profile-select`)?.addEventListener('change', (event) => syncProfile(event.target.value));
  }
  paintMode();
}
