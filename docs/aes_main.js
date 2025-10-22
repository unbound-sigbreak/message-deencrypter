document.addEventListener('DOMContentLoaded', () => {
  const keyInput = document.getElementById('keyB64');
  const keyStatus = document.getElementById('keyStatus');
  const keyWarning = document.getElementById('keyWarning');
  const genKeyBtn = document.getElementById('genKeyBtn');
  const showHelpBtn = document.getElementById('showHelpBtn');
  const helpContainer = document.getElementById('helpContainer');

  const plaintextArea = document.getElementById('plaintext');
  const ciphertextArea = document.getElementById('ciphertext');
  const decryptedArea = document.getElementById('decrypted');
  const encryptBtn = document.getElementById('encryptBtn');
  const decryptBtn = document.getElementById('decryptBtn');

  const LOCAL_KEY = 'aes-gcm-key-b64';
  const IV_BYTES = 12;   // recommended for GCM
  const KEY_BYTES = 32;  // 256-bit

  // utils
  const u8 = (n) => new Uint8Array(n);
  const enc = (s) => new TextEncoder().encode(s);
  const dec = (b) => new TextDecoder().decode(b);

  const b64enc = (bytes) => {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  };
  const b64dec = (b64) => {
    const clean = (b64 || '').replace(/\s+/g, '');
    try {
      const bin = atob(clean);
      const out = u8(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch {
      return null;
    }
  };

  const concat = (a, b) => {
    const out = u8(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  };

  const setKeyStatus = (ok, okMsg = 'Key OK.', errMsg = 'Invalid key. Must be base64 for exactly 32 bytes.') => {
    keyWarning.style.display = ok ? 'none' : 'block';
    keyStatus.textContent = ok ? okMsg : errMsg;
    keyStatus.className = ok ? 'info' : 'warning';
  };

  // key handling
  const generateKey = () => {
    const bytes = u8(KEY_BYTES);
    crypto.getRandomValues(bytes);
    return b64enc(bytes);
  };

  const validateAndPersistKey = () => {
    const bytes = b64dec(keyInput.value);
    const ok = !!bytes && bytes.length === KEY_BYTES;
    setKeyStatus(ok);
    if (ok) {
      const clean = keyInput.value.replace(/\s+/g, '');
      localStorage.setItem(LOCAL_KEY, clean);
      if (keyInput.value !== clean) keyInput.value = clean;
    }
    return ok;
  };

  const loadOrInitKey = () => {
    let b64 = localStorage.getItem(LOCAL_KEY);
    if (!b64) {
      b64 = generateKey();
      localStorage.setItem(LOCAL_KEY, b64);
    }
    keyInput.value = b64;
    validateAndPersistKey();
  };

  const importAesKey = async () => {
    const raw = b64dec(localStorage.getItem(LOCAL_KEY) || '');
    if (!raw || raw.length !== KEY_BYTES) throw new Error('Key not set or invalid.');
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  };

  // crypto ops
  const doEncrypt = async () => {
    if (!validateAndPersistKey()) return alert('Fix key first.');
    const key = await importAesKey();
    const iv = u8(IV_BYTES); crypto.getRandomValues(iv);
    const pt = enc(plaintextArea.value);
    const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, pt);
    const out = concat(iv, new Uint8Array(ctBuf));
    ciphertextArea.value = b64enc(out);
  };

  const doDecrypt = async () => {
    if (!validateAndPersistKey()) return alert('Fix key first.');
    const all = b64dec(ciphertextArea.value);
    if (!all || all.length <= IV_BYTES) { decryptedArea.value = '[Invalid ciphertext]'; return; }
    const iv = all.slice(0, IV_BYTES);
    const ct = all.slice(IV_BYTES);
    try {
      const key = await importAesKey();
      const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      decryptedArea.value = dec(ptBuf);
    } catch {
      decryptedArea.value = '[Decryption failed]';
    }
  };

  // UI events
  genKeyBtn.onclick = () => {
    const b64 = generateKey();
    localStorage.setItem(LOCAL_KEY, b64);
    keyInput.value = b64;
    setKeyStatus(true, 'New key generated.');
  };
  showHelpBtn.onclick = () => {
    helpContainer.style.display = helpContainer.style.display === 'block' ? 'none' : 'block';
  };
  keyInput.oninput = validateAndPersistKey;
  encryptBtn.onclick = doEncrypt;
  decryptBtn.onclick = doDecrypt;

  // init
  loadOrInitKey();
  keyInput.autofocus = true;
});
